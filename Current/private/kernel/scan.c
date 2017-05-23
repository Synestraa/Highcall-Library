#include <highcall.h>
#include <stdio.h>
#include <intrin.h>

DECL_EXTERN_API(NTSTATUS, ScanPageMinesCheck, PSCAN_PAGE_MINES ScanInformation)
{
	ULONG x = 0;

	if (ScanInformation == NULL || ScanInformation->MineAmount == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	for (; x < ScanInformation->MineAmount; x++)
	{
		WORKING_SET_EX_DATA info;
		ZERO(&info);

		info.VirtualAddress = ScanInformation->Pages[x];

		if (!HcProcessQueryWorkingSetEx(NtCurrentProcess(), &info))
		{
			return STATUS_INTERNAL_ERROR;
		}

		if (info.VirtualAttributes.Valid)
		{
			return STATUS_FAIL_CHECK;
		}
	}

	return STATUS_SUCCESS;
}

DECL_EXTERN_API(NTSTATUS, ScanPageMinesCreate, PSCAN_PAGE_MINES ScanInformation)
{
	ULONG n;
	ULONG x;

	if (!ScanInformation)
	{
		return STATUS_INVALID_PARAMETER;
	}

	ScanInformation->Pages = (LPVOID*) HcVirtualAlloc(NULL, ScanInformation->MineAmount * sizeof(LPVOID), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ScanInformation->Pages)
	{
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	if (!ScanInformation->Flags)
	{
		ScanInformation->Flags = PAGE_READWRITE;
	}

	for (n = 0; n < ScanInformation->MineAmount; n++)
	{
		ScanInformation->Pages[n] = HcVirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, ScanInformation->Flags);
		if (!ScanInformation->Pages[n])
		{
			/* free whatever we've allocated so far then... */
			for (x = 0; x < n; x++)
			{
				HcVirtualFree(ScanInformation->Pages[x], 0, MEM_RELEASE);
			}

			return STATUS_MEMORY_NOT_ALLOCATED;
		}
	}

	return STATUS_SUCCESS;
}

static int g_LevelHandler = 0;
static BOOLEAN g_vehContained = TRUE;

LONG NTAPI ExceptionDebuggerDetectionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	PCONTEXT ctx = ExceptionInfo->ContextRecord;
	PEXCEPTION_RECORD exception = ExceptionInfo->ExceptionRecord;

	if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0)
	{
		g_LevelHandler++;
	}

	if (exception->ExceptionCode == EXCEPTION_INVALID_HANDLE)
	{
		g_vehContained = TRUE;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (exception->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)
	{
		g_vehContained = TRUE;

#ifdef _WIN64
		ExceptionInfo->ContextRecord->Rip++;
#else
		ExceptionInfo->ContextRecord->Eip++;
#endif
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

DECL_EXTERN_API(NTSTATUS, ScanHideCurrentThread)
{
	return HcSetInformationThread(NtCurrentThread(), ThreadHideFromDebugger, NULL, 0);
}

DECL_EXTERN_API(NTSTATUS, ScanApplyDebuggerMines)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG Protect = 0;
	LPBYTE fnDbgBreakPoint, fnDbgUserBreakPoint;

	Status = HcScanHideCurrentThread();
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	fnDbgBreakPoint = HcModuleProcedureA(HcGlobal.HandleNtdll, "DbgBreakPoint");
	if (!fnDbgBreakPoint)
	{
		return STATUS_INVALID_ADDRESS;
	}

	fnDbgUserBreakPoint = HcModuleProcedureA(HcGlobal.HandleNtdll, "DbgUserBreakPoint");
	if (!fnDbgUserBreakPoint)
	{
		return STATUS_INVALID_ADDRESS;
	}

	if (HcVirtualProtect(fnDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &Protect))
	{
		*fnDbgBreakPoint = 0xc3; /* just return */

		HcVirtualProtect(fnDbgBreakPoint, 1, Protect, &Protect);
	}
	else
	{
		return HcErrorGetLastStatus();
	}

	if (HcVirtualProtect(fnDbgUserBreakPoint, 1, PAGE_EXECUTE_READWRITE, &Protect))
	{
		*fnDbgUserBreakPoint = 0xc3; /* just return */

		HcVirtualProtect(fnDbgUserBreakPoint, 1, Protect, &Protect);
	}
	else
	{
		return HcErrorGetLastStatus();
	}

	return STATUS_SUCCESS;
}

DECL_EXTERN_API(NTSTATUS, ScanCheckProcessDebuggerFlags)
{
	NTSTATUS Status;
	ULONG Flags = 0;
	ULONG ReturnSize = 0;

	Status = HcQueryInformationProcess(NtCurrentProcess(), ProcessDebugFlags, &Flags, sizeof(Flags), &ReturnSize);
	if (NT_SUCCESS(Status))
	{
		if (ReturnSize != sizeof(Flags) || Flags == 0)
		{
			g_LevelHandler++;
			return STATUS_DEBUGGER_ATTACHED;
		}
	}
	else
	{
		g_LevelHandler++;
		return STATUS_FAIL_CHECK;
	}

	return STATUS_SUCCESS;
}

DECL_EXTERN_API(NTSTATUS, ScanCheckPebFlags)
{
	PPEB Peb = NtCurrentPeb();
	if (Peb == NULL)
	{
		/* this is pretty fucking weird if im being honest. unless we're a mini process. */
		g_LevelHandler++;
		return STATUS_INVALID_ADDRESS;
	}

	/* not sure if I should even bother, tbh. */
	if (Peb->BeingDebugged)
	{
		/* does it get more basic? */
		g_LevelHandler++;
		return STATUS_DEBUGGER_ATTACHED;
	}

	if (Peb->NtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
	{
		g_LevelHandler++;
		return STATUS_DEBUGGER_ATTACHED;
	}

	return STATUS_SUCCESS;
}

DECL_EXTERN_API(NTSTATUS, ScanCheckDebuggerPort)
{
	NTSTATUS Status;
	LPVOID DebugPort = NULL;

	Status = HcQueryInformationProcess(NtCurrentProcess(), ProcessDebugPort, &DebugPort, sizeof(LPVOID), NULL);
	if (NT_SUCCESS(Status))
	{
		if (DebugPort != NULL)
		{
			g_LevelHandler++;
			return STATUS_DEBUGGER_ATTACHED;
		}
	}
	else
	{
		g_LevelHandler++;
		return STATUS_FAIL_CHECK;
	}

	return STATUS_SUCCESS;
}

DECL_EXTERN_API(NTSTATUS, ScanCheckKernelFlag)
{
	LPBYTE KUSER_SHARED_DATA = (LPBYTE) 0x7ffe0000;
	if (*(KUSER_SHARED_DATA + 0x2d4) == 0x3)
	{
		g_LevelHandler++;
		return STATUS_DEBUGGER_ATTACHED;
	}

	return STATUS_SUCCESS;
}

DECL_EXTERN_API(NTSTATUS, ScanCheckKernelDebugger)
{
	NTSTATUS Status;
	USHORT KernelDebuggerQuery = 0;

	Status = HcQuerySystemInformation(SystemKernelDebuggerInformation, &KernelDebuggerQuery, sizeof(KernelDebuggerQuery), NULL);
	if (NT_SUCCESS(Status))
	{
		if ((BYTE) KernelDebuggerQuery && !HIBYTE(KernelDebuggerQuery))
		{
			g_LevelHandler++;
			return STATUS_DEBUGGER_ATTACHED;
		}
	}
	else
	{
		g_LevelHandler++;
		return STATUS_FAIL_CHECK;
	}

	return STATUS_SUCCESS;
}

DECL_EXTERN_API(NTSTATUS, ScanCheckThreadHook)
{
	ULONG_PTR ThreadStartAddressInformation = 0;
	ULONG Size;
	ULONG_PTR Base;
	NTSTATUS Status;

	Base = (ULONG_PTR) HcModuleHandleA(NULL);
	Size = HcModuleSize((HMODULE) Base);

	Status = HcQueryInformationThread(NtCurrentThread(), ThreadQuerySetWin32StartAddress, &ThreadStartAddressInformation, sizeof(ThreadStartAddressInformation), NULL);
	if (NT_SUCCESS(Status))
	{
		if (ThreadStartAddressInformation < Base || ThreadStartAddressInformation > Base + Size)
		{
			g_LevelHandler++;
			return STATUS_DEBUGGER_ATTACHED;
		}
	}
	else
	{
		g_LevelHandler++;
		return STATUS_FAIL_CHECK;
	}

	return STATUS_SUCCESS;
}

DECL_EXTERN_API(NTSTATUS, ScanCheckHeaderFlags)
{
	HMODULE BaseOfModule = HcModuleHandleA(NULL);
	PIMAGE_NT_HEADERS Headers = HcImageGetNtHeader(BaseOfModule);
	PIMAGE_LOAD_CONFIG_DIRECTORY pImageLoadConfigDirectory = NULL;

	if (Headers == NULL)
	{
		return STATUS_FAIL_CHECK;
	}

	pImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY) 
		((ULONG_PTR) BaseOfModule + Headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);

	if (pImageLoadConfigDirectory->GlobalFlagsClear != 0)
	{
		g_LevelHandler++;
		return STATUS_DEBUGGER_ATTACHED;
	}

	return STATUS_SUCCESS;
}

DECL_EXTERN_API(NTSTATUS, ScanCheckDebugHandle)
{
	NTSTATUS Status;
	HANDLE DebugHandle = NULL;
	ULONG ReturnedLength = 0;

	Status = HcQueryInformationProcess(NtCurrentProcess(), ProcessDebugObjectHandle, &DebugHandle, sizeof(DebugHandle), &ReturnedLength);
	if (NT_SUCCESS(Status))
	{
		if (DebugHandle != NULL)
		{
			g_LevelHandler++;
			return STATUS_DEBUGGER_ATTACHED;
		}
	}
	else if (Status != STATUS_PORT_NOT_SET)
	{
		/* STATUS_PORT_NOT_SET is a totally legit value... others are not */

		g_LevelHandler++;
		return STATUS_FAIL_CHECK;
	}

	return STATUS_SUCCESS;
}

DECL_EXTERN_API(NTSTATUS, ScanCheckModification)
{
	LPBYTE fnDbgBreakPoint, fnDbgUserBreakPoint;

	fnDbgBreakPoint = HcModuleProcedureA(HcGlobal.HandleNtdll, "DbgBreakPoint");
	fnDbgUserBreakPoint = HcModuleProcedureA(HcGlobal.HandleNtdll, "DbgUserBreakPoint");

	if (*fnDbgBreakPoint != 0xc3 || *fnDbgUserBreakPoint != 0xc3)
	{
		g_LevelHandler++;
		return STATUS_FAIL_CHECK;
	}

	return STATUS_SUCCESS;
}

DECL_EXTERN_API(NTSTATUS, ScanCheckIsThreadHidden)
{
	BOOLEAN IsHidden = FALSE;
	NTSTATUS Status;
	
	Status = HcQueryInformationThread(NtCurrentThread(), ThreadHideFromDebugger, &IsHidden, sizeof(IsHidden), NULL);
	if (!NT_SUCCESS(Status))
	{
		g_LevelHandler++; /* this should never fail. */
		return STATUS_FAIL_CHECK;
	}
	else
	{
		if (!IsHidden)
		{
			g_LevelHandler++;
			return STATUS_FAIL_CHECK;
		}
	}

	return STATUS_SUCCESS;
}

DECL_EXTERN_API(NTSTATUS, ScanCheckHardwareBreakpoints)
{
	CONTEXT Context;
	ZERO(&Context);

	Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	/* we arent ever really supposed to get a hardware breakpoint.
	* should check other threads. */
	if (!HcThreadGetContext(NtCurrentThread(), &Context))
	{
		g_LevelHandler++;
		return STATUS_FAIL_CHECK;
	}

	/* Is there a bp set in any of the 4 (max) bp slots? */
	if (Context.Dr0 != 0 || Context.Dr1 != 0 || Context.Dr2 != 0 || Context.Dr3 != 0)
	{
		g_LevelHandler++;
		return STATUS_DEBUGGER_ATTACHED;
	}

	return STATUS_SUCCESS;
}

DECL_EXTERN_API(NTSTATUS, ScanCheckInvalidDebugObject)
{
	NTSTATUS Status;
	HANDLE debugObject;
	OBJECT_ATTRIBUTES oa;

	InitializeObjectAttributes(&oa, 0, 0, 0, 0);

	Status = HcCreateDebugObject(&debugObject, DEBUG_ALL_ACCESS, &oa, 0);
	if (NT_SUCCESS(Status))
	{
		POBJECT_TYPE_INFORMATION Object = (POBJECT_TYPE_INFORMATION) HcAllocPage(0x1000);

		Status = HcQueryObject(debugObject, ObjectTypeInformation, Object, 0x1000, NULL);
		if (NT_SUCCESS(Status))
		{
			if (Object->TotalNumberOfObjects == 0) //there must be 1 object...
			{
				g_LevelHandler++;
				Status = STATUS_DEBUGGER_ATTACHED;
			}
		}
		else
		{
			g_LevelHandler++;
			HcClose(debugObject);
			Status = STATUS_FAIL_CHECK;
		}

		HcFreePage(Object);
		HcClose(debugObject);
	}
	else
	{
		g_LevelHandler++;
		STATUS_FAIL_CHECK;
	}

	return Status;
}

DECL_EXTERN_API(NTSTATUS, ScanCheckVEH)
{
	NTSTATUS Status;
	HANDLE hVectoredHandler;
	LPVOID Page;
	ULONG Protect = 0;

	g_vehContained = FALSE;
	hVectoredHandler = AddVectoredExceptionHandler(1, ExceptionDebuggerDetectionHandler);

	/* If we get an exception... then we're running under a debugger. */
	Status = HcClose((HANDLE) (ULONG_PTR) 0xDE4DBEEF);
	if (Status != STATUS_INVALID_HANDLE)
	{
		g_LevelHandler++;
		Status = STATUS_FAIL_CHECK;
		goto done;
	}

	if (g_vehContained)
	{
		/* swallowed.. */
		g_LevelHandler++;
		Status = STATUS_DEBUGGER_ATTACHED;
		goto done;
	}

	/* If there was no exception... */
	g_vehContained = FALSE;
	_enable();

	if (!g_vehContained)
	{
		g_LevelHandler++;
		Status = STATUS_DEBUGGER_ATTACHED;
		goto done;
	}

	/* If there was no exception... something is wrong. */
	g_vehContained = FALSE;

	Page = HcVirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (Page == NULL)
	{
		Status = STATUS_FAIL_CHECK;
		goto done;
	}

	*(BYTE*) Page = 0xc3; /* ret */

	if (!HcVirtualProtect(Page, 0x1000, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &Protect))
	{
		g_LevelHandler++; /* unusual */
		Status = STATUS_FAIL_CHECK;
	}
	else
	{
		__try
		{
			((void(*)())Page)();
		}
		__except (GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
		{
			/* let the VEH do the work. */
			g_vehContained = TRUE;
		}

		if (!g_vehContained)
		{
			g_LevelHandler++;
			Status = STATUS_DEBUGGER_ATTACHED;
		}
	}

	HcVirtualFree(Page, 0, MEM_RELEASE);

done:
	RemoveVectoredExceptionHandler(hVectoredHandler);
	return Status;
}

DECL_EXTERN_API(NTSTATUS, ScanCheckMemoryModificationSelf)
{

}

DECL_EXTERN_API(ULONG, ScanCheckDebuggerBasic, BOOLEAN CheckDebuggerMines)
{
	g_LevelHandler = 0;

	HcScanCheckProcessDebuggerFlags();
	HcScanCheckPebFlags();
	HcScanCheckDebuggerPort();
	HcScanCheckKernelFlag();
	HcScanCheckKernelDebugger();
	HcScanCheckThreadHook();
	HcScanCheckHeaderFlags();
	HcScanCheckDebugHandle();
	HcScanCheckHardwareBreakpoints();
	HcScanCheckInvalidDebugObject();
	HcScanCheckVEH();

	if (CheckDebuggerMines)
	{
		HcScanCheckModification();
		HcScanCheckIsThreadHidden();
	}

	return g_LevelHandler;
}