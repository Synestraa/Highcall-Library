#include <highcall.h>

#include "../../public/imports.h"
#include "../sys/syscall.h"

DECL_EXTERN_API(DWORD, ProcessGetCurrentId, VOID)
{
	return HandleToUlong(NtCurrentTeb()->ClientId.UniqueProcess);
}

DECL_EXTERN_API(DWORD, ProcessGetId, IN HANDLE Process)
{
	PROCESS_BASIC_INFORMATION ProcessBasic;
	NTSTATUS Status;

	ZERO(&ProcessBasic);

	/* Query the kernel */
	Status = HcQueryInformationProcess(Process,
		ProcessBasicInformation,
		&ProcessBasic,
		sizeof(ProcessBasic),
		NULL);

	if (!NT_SUCCESS(Status))
	{
		/* Handle failure */
		HcErrorSetNtStatus(Status);
		return 0;
	}

	/* Return the PID */
	return HandleToUlong(ProcessBasic.UniqueProcessId);
}

DECL_EXTERN_API(BOOLEAN, ProcessIsWow64Ex, CONST IN HANDLE hProcess)
{
	ULONG_PTR pbi = 0;
	NTSTATUS Status;

	/* Query the kernel */
	Status = HcQueryInformationProcess(hProcess,
		ProcessWow64Information,
		&pbi,
		sizeof(pbi),
		NULL);

	if (!NT_SUCCESS(Status))
	{
		/* Handle error path */
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	/* Enforce this is a BOOLEAN, and return success */
	return pbi != 0;
}

DECL_EXTERN_API(BOOLEAN, ProcessIsWow64, CONST IN DWORD dwProcessId)
{
	HANDLE hProcess;
	BOOLEAN Result;

	hProcess = HcProcessOpen(dwProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
	if (!hProcess)
	{
		return FALSE;
	}

	Result = HcProcessIsWow64Ex(hProcess);

	HcObjectClose(hProcess);
	return Result;
}

DECL_EXTERN_API(BOOLEAN, ProcessExitCode, CONST IN SIZE_T dwProcessId, IN LPDWORD lpExitCode)
{
	HANDLE hProcess;
	PROCESS_BASIC_INFORMATION ProcessBasic;
	NTSTATUS Status;

	ZERO(&ProcessBasic);

	hProcess = HcProcessOpen(dwProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
	if (!hProcess)
	{
		return FALSE;
	}

	/* Ask the kernel */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		&ProcessBasic,
		sizeof(ProcessBasic),
		NULL);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		HcClose(hProcess);
		return FALSE;
	}

	*lpExitCode = (DWORD)ProcessBasic.ExitStatus;

	HcClose(hProcess);
	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ProcessExitCodeEx, CONST IN HANDLE hProcess, IN LPDWORD lpExitCode)
{
	PROCESS_BASIC_INFORMATION ProcessBasic;
	NTSTATUS Status;

	ZERO(&ProcessBasic);

	/* Ask the kernel */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation, 
		&ProcessBasic,
		sizeof(ProcessBasic),
		NULL);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	*lpExitCode = (DWORD) ProcessBasic.ExitStatus;

	return TRUE;
}

DECL_EXTERN_API(HANDLE, ProcessOpen, CONST SIZE_T dwProcessId, CONST ACCESS_MASK DesiredAccess)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid;
	HANDLE hProcess = NULL;

	ZERO(&oa);
	ZERO(&cid);

	cid.UniqueProcess = (HANDLE)dwProcessId;
	cid.UniqueThread = 0;

	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

	Status = HcOpenProcess(&hProcess, DesiredAccess, &oa, &cid);

	HcErrorSetNtStatus(Status);
	if (NT_SUCCESS(Status))
	{
		return hProcess;
	}

	return 0;
}

DECL_EXTERN_API(BOOLEAN, ProcessReadyEx, CONST HANDLE hProcess)
{
	NTSTATUS Status;
	PPEB_LDR_DATA LoaderData;
	PROCESS_BASIC_INFORMATION ProcInfo;
	DWORD ExitCode = 0;
	DWORD dwPbiLen = 0;

	ZERO(&ProcInfo);

	/* Will fail if there is a mismatch in compiler architecture. */
	if (!HcProcessExitCodeEx(hProcess, &ExitCode) || ExitCode != STATUS_PENDING)
	{
		return FALSE;
	}

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		&ProcInfo,
		sizeof(ProcInfo),
		&dwPbiLen);

	HcErrorSetNtStatus(Status);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}
	
	/* Read loader data address from PEB */
	if (!HcProcessReadMemory(hProcess,
		&(ProcInfo.PebBaseAddress->LoaderData),
		&LoaderData, 
		sizeof(LoaderData),
		NULL) || !LoaderData)
	{
		return FALSE;
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ProcessReady, CONST SIZE_T dwProcessId)
{
	BOOLEAN Success;
	HANDLE hProcess;

	hProcess = HcProcessOpen(dwProcessId,
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);

	if (!hProcess)
	{
		return FALSE;
	}

	/* Ensure we didn't find it before ntdll was loaded */
	Success = HcProcessReadyEx(hProcess);

	HcClose(hProcess);
	return Success;
}

DECL_EXTERN_API(BOOLEAN, ProcessSuspend, CONST SIZE_T dwProcessId)
{
	NTSTATUS Status;
	HANDLE hProcess;

	hProcess = HcProcessOpen(dwProcessId, PROCESS_ALL_ACCESS);
	if (!hProcess)
	{
		return FALSE;
	}

	Status = HcSuspendProcess(hProcess);

	HcClose(hProcess);
	return NT_SUCCESS(Status);
}

DECL_EXTERN_API(BOOLEAN, ProcessSuspendEx, CONST HANDLE hProcess)
{
	/* Suspend and return */
	return NT_SUCCESS(HcSuspendProcess(hProcess));
}

DECL_EXTERN_API(BOOLEAN, ProcessResume, CONST SIZE_T dwProcessId)
{
	NTSTATUS Status;
	HANDLE hProcess;

	hProcess = HcProcessOpen(dwProcessId, PROCESS_ALL_ACCESS);
	if (!hProcess)
	{
		return FALSE;
	}

	Status = HcResumeProcess(hProcess);

	HcClose(hProcess);
	return NT_SUCCESS(Status);
}

DECL_EXTERN_API(BOOLEAN, ProcessResumeEx, CONST HANDLE hProcess)
{
	return NT_SUCCESS(HcResumeProcess(hProcess));
}

DECL_EXTERN_API(BOOLEAN, ProcessWriteMemory, CONST HANDLE hProcess,
	CONST LPVOID lpBaseAddress,
	CONST VOID* lpBuffer,
	SIZE_T nSize,
	PSIZE_T lpNumberOfBytesWritten)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG OldValue = 0;
	SIZE_T RegionSize = 0;
	PVOID Base = NULL;
	BOOLEAN UnProtect = FALSE;

	/* Set parameters for protect call */
	RegionSize = nSize;
	Base = lpBaseAddress;

	/* Check the current status */
	Status = HcProtectVirtualMemory(hProcess,
		&Base,
		&RegionSize,
		PAGE_EXECUTE_READWRITE,
		&OldValue);

	HcErrorSetNtStatus(Status);
	if (NT_SUCCESS(Status))
	{
		/* Check if we are unprotecting */
		UnProtect = OldValue & (PAGE_READWRITE |
			PAGE_WRITECOPY |
			PAGE_EXECUTE_READWRITE |
			PAGE_EXECUTE_WRITECOPY) ? FALSE : TRUE;

		if (!UnProtect)
		{
			/* Set the new protection */
			HcProtectVirtualMemory(hProcess,
				&Base,
				&RegionSize,
				OldValue,
				&OldValue);

			/* Write the memory */
			Status = HcWriteVirtualMemory(hProcess,
				lpBaseAddress,
				(LPVOID)lpBuffer,
				nSize,
				&nSize);

			/* In Win32, the parameter is optional, so handle this case */
			if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;

			if (!NT_SUCCESS(Status))
			{
				HcErrorSetNtStatus(Status);
				return FALSE;
			}

			/* Flush the ITLB */
			HcFlushInstructionCache(hProcess, lpBaseAddress, nSize);
			return TRUE;
		}

		/* Check if we were read only */
		if (OldValue & (PAGE_NOACCESS | PAGE_READONLY))
		{
			/* Restore protection and fail */
			HcProtectVirtualMemory(hProcess,
				&Base,
				&RegionSize,
				OldValue,
				&OldValue);

			/* Note: This is what Windows returns and code depends on it */
			return FALSE;
		}

		/* Otherwise, do the write */
		Status = HcWriteVirtualMemory(hProcess,
			lpBaseAddress,
			(LPVOID)lpBuffer,
			nSize,
			&nSize);

		/* In Win32, the parameter is optional, so handle this case */
		if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;

		/* And restore the protection */
		HcProtectVirtualMemory(hProcess,
			&Base,
			&RegionSize,
			OldValue,
			&OldValue);

		if (!NT_SUCCESS(Status))
		{
			/* Note: This is what Windows returns and code depends on it */
			return FALSE;
		}

		/* Flush the ITLB */
		HcFlushInstructionCache(hProcess, lpBaseAddress, nSize);
		return TRUE;
	}

	return FALSE;
}

DECL_EXTERN_API(BOOLEAN, ProcessReadMemory, CONST IN HANDLE hProcess,
	IN LPCVOID lpBaseAddress,
	IN LPVOID lpBuffer,
	IN SIZE_T nSize,
	OUT PSIZE_T lpNumberOfBytesRead)
{
	NTSTATUS Status;

	/* Do the read */
	Status = HcReadVirtualMemory(hProcess,
		(PVOID)lpBaseAddress,
		lpBuffer,
		nSize,
		&nSize);

	/* In user-mode, this parameter is optional */
	if (lpNumberOfBytesRead)
	{
		*lpNumberOfBytesRead = nSize;
	}

	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	return TRUE;
}

DECL_EXTERN_API(HANDLE, ProcessCreateThread, CONST IN HANDLE hProcess,
	CONST IN LPTHREAD_START_ROUTINE lpStartAddress,
	CONST IN LPVOID lpParamater,
	CONST IN DWORD dwCreationFlags)
{
	NTSTATUS Status;
	HANDLE hThread = 0;

	Status = HcCreateThreadEx(&hThread,
		THREAD_ALL_ACCESS, 
		NULL, 
		hProcess,
		lpStartAddress,
		lpParamater, 
		dwCreationFlags,
		0,
		0,
		0,
		NULL);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return 0;
	}

	return hThread;
}

DECL_EXTERN_API(BOOLEAN, ProcessReadNullifiedString, CONST HANDLE hProcess,
	CONST PUNICODE_STRING usStringIn,
	LPWSTR lpStringOut,
	CONST SIZE_T lpSize)
{
	SIZE_T tStringSize;

	/* Get the maximum len we have/can write in given size */
	tStringSize = usStringIn->Length + sizeof(UNICODE_NULL);
	if (lpSize * sizeof(WCHAR) < tStringSize)
	{
		tStringSize = lpSize * sizeof(WCHAR);
	}

	/* Read the string */
	if (!HcProcessReadMemory(hProcess,
		usStringIn->Buffer,
		lpStringOut,
		tStringSize,
		NULL))
	{
		return FALSE;
	}

	/* If we are at the end of the string, prepare to override to nullify string */
	if (tStringSize == usStringIn->Length + sizeof(UNICODE_NULL))
	{
		tStringSize -= sizeof(UNICODE_NULL);
	}

	/* Nullify at the end if needed */
	if (tStringSize >= lpSize * sizeof(WCHAR))
	{
		if (lpSize)
		{
			ASSERT(lpSize >= sizeof(UNICODE_NULL));
			lpStringOut[lpSize - 1] = UNICODE_NULL;
		}
	}
	/* Otherwise, nullify at last written char */
	else
	{
		ASSERT(tStringSize + sizeof(UNICODE_NULL) <= lpSize * sizeof(WCHAR));
		lpStringOut[tStringSize / sizeof(WCHAR)] = UNICODE_NULL;
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ProcessLdrModuleToHighCallModule, CONST IN HANDLE hProcess,
	CONST IN PLDR_DATA_TABLE_ENTRY Module,
	OUT PHC_MODULE_INFORMATIONW phcModuleOut)
{
	HcProcessReadNullifiedString(hProcess,
		&Module->BaseModuleName,
		phcModuleOut->Name,
		Module->BaseModuleName.Length);

	HcProcessReadNullifiedString(hProcess,
		&Module->FullModuleName,
		phcModuleOut->Path,
		Module->FullModuleName.Length);

	phcModuleOut->Size = Module->SizeOfImage;
	phcModuleOut->Base = Module->ModuleBase;

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ProcessGetModuleHandleByNameAdvW, 
	CONST IN HANDLE ProcessHandle,
	IN LPCWSTR lpModuleName OPTIONAL)
{
	BOOLEAN Continue;
	MEMORY_BASIC_INFORMATION basicInfo;
	PHC_MODULE_INFORMATIONW hcmInformation;
	SIZE_T allocationSize = 0;
	PVOID baseAddress = NULL;

	ZERO(&basicInfo);

	if (!NT_SUCCESS(HcQueryVirtualMemory(
		ProcessHandle,
		baseAddress,
		MemoryBasicInformation,
		&basicInfo,
		sizeof(MEMORY_BASIC_INFORMATION),
		NULL)))
	{
		return FALSE;
	}

	Continue = TRUE;

	while (Continue)
	{
		if (basicInfo.Type == MEM_IMAGE)
		{
			hcmInformation = HcInitializeModuleInformationW(MAX_PATH, MAX_PATH);

			hcmInformation->Base = basicInfo.AllocationBase;
			allocationSize = 0;

			/* Calculate destination of next module. */
			do
			{
				baseAddress = (PVOID)((ULONG_PTR)baseAddress + basicInfo.RegionSize);
				allocationSize += basicInfo.RegionSize;

				if (!NT_SUCCESS(HcQueryVirtualMemory(ProcessHandle,
					baseAddress,
					MemoryBasicInformation,
					&basicInfo,
					sizeof(MEMORY_BASIC_INFORMATION),
					NULL)))
				{
					Continue = FALSE;
					break;
				}

			} while (basicInfo.AllocationBase == (PVOID)hcmInformation->Base);

			hcmInformation->Size = allocationSize;

			if (HcProcessModuleFileName(ProcessHandle,
				(PVOID)hcmInformation->Base,
				hcmInformation->Path,
				MAX_PATH))
			{
				//
				// Temporary.
				// The name should be stripped from the path.
				// The path should be resolved from native to dos.
				//
				HcStringCopyW(hcmInformation->Name, hcmInformation->Path, MAX_PATH);
			}

			HcDestroyModuleInformationW(hcmInformation);
		}
		else
		{
			baseAddress = (PVOID)((ULONG_PTR)baseAddress + basicInfo.RegionSize);

			if (!NT_SUCCESS(HcQueryVirtualMemory(ProcessHandle,
				baseAddress,
				MemoryBasicInformation,
				&basicInfo,
				sizeof(MEMORY_BASIC_INFORMATION),
				NULL)))
			{
				Continue = FALSE;
			}
		}
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ProcessEnumModulesW, CONST HANDLE hProcess,
	CONST HC_MODULE_CALLBACK_EVENTW hcmCallback,
	LPARAM lParam)
{
	NTSTATUS Status;
	PPEB_LDR_DATA LoaderData;
	PLIST_ENTRY ListHead, ListEntry;
	PROCESS_BASIC_INFORMATION ProcInfo;
	LDR_DATA_TABLE_ENTRY ldrModule;
	PHC_MODULE_INFORMATIONW Module;
	SIZE_T Count = 0;
	ULONG Len = 0;

	ZERO(&ProcInfo);
	ZERO(&ldrModule);

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		&ProcInfo,
		sizeof(ProcInfo),
		&Len);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	if (ProcInfo.PebBaseAddress == NULL)
	{
		HcErrorSetNtStatus(STATUS_PARTIAL_COPY);
		return FALSE;
	}

	/* Read loader data address from PEB */
	if (!HcProcessReadMemory(hProcess,
		&(ProcInfo.PebBaseAddress->LoaderData),
		&LoaderData, sizeof(LoaderData),
		NULL))
	{
		return FALSE;
	}

	/* Store list head address */
	ListHead = &LoaderData->InLoadOrderModuleList;

	/* Read first element in the modules list */
	if (!HcProcessReadMemory(hProcess,
		&(LoaderData->InLoadOrderModuleList.Flink),
		&ListEntry,
		sizeof(ListEntry),
		NULL))
	{
		return FALSE;
	}

	/* Loop on the modules */
	while (ListEntry != ListHead)
	{
		/* Load module data */
		if (!HcProcessReadMemory(hProcess,
			CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks),
			&ldrModule,
			sizeof(ldrModule),
			NULL))
		{
			return FALSE;
		}

		Module = HcInitializeModuleInformationW(MAX_PATH, MAX_PATH);

		/* Attempt to convert to a HC module */
		if (HcProcessLdrModuleToHighCallModule(hProcess,
			&ldrModule,
			Module))
		{
			/* Give it to the caller */
			if (hcmCallback(*Module, lParam))
			{
				HcDestroyModuleInformationW(Module);
				return TRUE;
			}

			Count += 1;
		}

		HcDestroyModuleInformationW(Module);

		if (Count > MAX_MODULES)
		{
			HcErrorSetNtStatus(STATUS_INVALID_HANDLE);
			return FALSE;
		}

		/* Get to next listed module */
		ListEntry = ldrModule.InLoadOrderLinks.Flink;
	}

	return FALSE;
}

DECL_EXTERN_API(BOOLEAN, ProcessEnumMappedImagesW, CONST HANDLE ProcessHandle,
	CONST HC_MODULE_CALLBACK_EVENTW hcmCallback,
	LPARAM lParam)
{
	BOOLEAN Continue;
	MEMORY_BASIC_INFORMATION basicInfo;
	PHC_MODULE_INFORMATIONW hcmInformation;
	SIZE_T allocationSize = 0;
	PVOID baseAddress = NULL;

	ZERO(&basicInfo);

	if (!NT_SUCCESS(HcQueryVirtualMemory(
		ProcessHandle,
		baseAddress,
		MemoryBasicInformation,
		&basicInfo,
		sizeof(MEMORY_BASIC_INFORMATION),
		NULL)))
	{
		return FALSE;
	}

	Continue = TRUE;

	while (Continue)
	{
		if (basicInfo.Type == MEM_IMAGE)
		{
			hcmInformation = HcInitializeModuleInformationW(MAX_PATH, MAX_PATH);

			hcmInformation->Base = basicInfo.AllocationBase;
			allocationSize = 0;

			/* Calculate destination of next module. */
			do
			{
				baseAddress = (PVOID)((ULONG_PTR)baseAddress + basicInfo.RegionSize);
				allocationSize += basicInfo.RegionSize;

				if (!NT_SUCCESS(HcQueryVirtualMemory(ProcessHandle,
					baseAddress,
					MemoryBasicInformation,
					&basicInfo,
					sizeof(MEMORY_BASIC_INFORMATION),
					NULL)))
				{
					Continue = FALSE;
					break;
				}

			} while (basicInfo.AllocationBase == (PVOID) hcmInformation->Base);

			hcmInformation->Size = allocationSize;

			if (HcProcessModuleFileName(ProcessHandle,
				(PVOID)hcmInformation->Base,
				hcmInformation->Path,
				MAX_PATH))
			{
				/* Temporary.
					The name should be stripped from the path.
					The path should be resolved from native to dos.
				*/
				HcStringCopyW(hcmInformation->Name, hcmInformation->Path, MAX_PATH);
			}

			if (hcmCallback(*hcmInformation, lParam))
			{
				HcDestroyModuleInformationW(hcmInformation);
				return TRUE;
			}

			HcDestroyModuleInformationW(hcmInformation);
		}
		else
		{
			baseAddress = (PVOID)((ULONG_PTR)baseAddress + basicInfo.RegionSize);

			if (!NT_SUCCESS(HcQueryVirtualMemory(ProcessHandle,
				baseAddress,
				MemoryBasicInformation,
				&basicInfo,
				sizeof(MEMORY_BASIC_INFORMATION),
				NULL)))
			{
				Continue = FALSE;
			}
		}
	}

	return TRUE;
}

static
NTSTATUS
HCAPI
GetProcessList(LPVOID* ppBuffer, PSYSTEM_PROCESS_INFORMATION* pSystemInformation)
{
	DWORD ReturnLength = 0;
	LPVOID Buffer;
	PSYSTEM_PROCESS_INFORMATION pSysList;
	NTSTATUS Status;
	
	Status = HcQuerySystemInformation(SystemProcessInformation,
			NULL,
			0,
			&ReturnLength);

	if (Status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return Status;
	}

	Buffer = HcAlloc(ReturnLength);
	pSysList = (PSYSTEM_PROCESS_INFORMATION)Buffer;

	for (;;)
	{
		/* Query the process list. */
		Status = HcQuerySystemInformation(SystemProcessInformation,
			pSysList,
			ReturnLength,
			&ReturnLength);

		if (Status != STATUS_INFO_LENGTH_MISMATCH)
		{
			break;
		}
		else
		{
			ReturnLength += 0xffff;

			HcFree(Buffer);

			Buffer = HcAlloc(ReturnLength);
			pSysList = (PSYSTEM_PROCESS_INFORMATION)Buffer;
		}
	}

	if (NT_SUCCESS(Status))
	{
		*ppBuffer = Buffer;
		*pSystemInformation = pSysList;
	}
	else
	{
		HcFree(Buffer);
	}

	return Status;
}

DECL_EXTERN_API(BOOLEAN, ProcessEnumByNameExW, CONST LPCWSTR lpProcessName,
	HC_PROCESS_CALLBACK_EXW Callback,
	LPARAM lParam)
{
	NTSTATUS Status;
	HANDLE CurrentHandle;
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
	PHC_PROCESS_INFORMATION_EXW hcpInformation;
	PVOID Buffer = NULL;

	/* Query the process list. */
	Status = GetProcessList(&Buffer, &processInfo);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	RtlInitUnicodeString(&processInfo->ImageName, L"IdleSystem");

	/* Loop through the process list */
	while (TRUE)
	{
		hcpInformation = HcInitializeProcessInformationExW(MAX_PATH);

		/* Check for a match */
		if (HcStringIsNullOrEmpty(lpProcessName) || HcStringEqualW(processInfo->ImageName.Buffer, lpProcessName, TRUE))
		{
			hcpInformation->Id = HandleToUlong(processInfo->UniqueProcessId);
			hcpInformation->ParentProcessId = HandleToUlong(processInfo->InheritedFromUniqueProcessId);

			/* Copy the name */
			HcStringCopyW(hcpInformation->Name,
				processInfo->ImageName.Buffer,
				processInfo->ImageName.Length);

			/* Try opening the process */
			CurrentHandle = HcProcessOpen((SIZE_T)processInfo->UniqueProcessId,
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);

			if (CurrentHandle != NULL)
			{
				hcpInformation->CanAccess = TRUE;

				/* Query main module */
				HcProcessQueryInformationModule(CurrentHandle,
					NULL,
					hcpInformation->MainModule);

				/* Close this handle. */
				HcClose(CurrentHandle);
			}

			/* Call the callback as long as the user doesn't return FALSE. */
			if (Callback(*hcpInformation, lParam))
			{
				HcDestroyProcessInformationExW(hcpInformation);
				HcFree(Buffer);
				return TRUE;
			}
		}

		HcDestroyProcessInformationExW(hcpInformation);

		if (!processInfo->NextEntryOffset)
		{
			break;
		}

		/* Calculate the next entry address */
		processInfo = (PSYSTEM_PROCESS_INFORMATION)((SIZE_T)processInfo + processInfo->NextEntryOffset);
	}

	HcFree(Buffer);
	return FALSE;
}

DECL_EXTERN_API(BOOLEAN, ProcessGetById, CONST IN DWORD dwProcessId, OUT PHC_PROCESS_INFORMATIONW pProcessInfo)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
	PVOID Buffer = NULL;
	BOOLEAN ReturnValue = FALSE;

	/* Query the process list. */
	Status = GetProcessList(&Buffer, &processInfo);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return ReturnValue;
	}

	RtlInitUnicodeString(&processInfo->ImageName, L"IdleSystem");

	/* Loop through the process list */
	while (TRUE)
	{
		DWORD processId = HandleToUlong(processInfo->UniqueProcessId);

		/* Check for a match */
		if (processId == dwProcessId)
		{
			pProcessInfo->Id = processId;
			pProcessInfo->ParentProcessId = HandleToUlong(processInfo->InheritedFromUniqueProcessId);

			/* Copy the name */
			HcStringCopyW(pProcessInfo->Name,
				processInfo->ImageName.Buffer,
				processInfo->ImageName.Length);

			ReturnValue = TRUE;
			goto end;
		}

		if (!processInfo->NextEntryOffset)
		{
			break;
		}

		/* Calculate the next entry address */
		processInfo = (PSYSTEM_PROCESS_INFORMATION)((SIZE_T)processInfo + processInfo->NextEntryOffset);
	}

end:
	HcFree(Buffer);
	return ReturnValue;
}

DECL_EXTERN_API(BOOLEAN, ProcessGetByNameW, CONST IN LPCWSTR lpName, OUT PHC_PROCESS_INFORMATIONW pProcessInfo)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
	PVOID Buffer = NULL;
	BOOLEAN ReturnValue = FALSE;

	/* Query the process list. */
	Status = GetProcessList(&Buffer, &processInfo);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return ReturnValue;
	}

	RtlInitUnicodeString(&processInfo->ImageName, L"IdleSystem");

	/* Loop through the process list */
	while (TRUE)
	{
		DWORD processId = HandleToUlong(processInfo->UniqueProcessId);

		/* Check for a match */
		if (!HcStringIsNullOrEmpty(processInfo->ImageName.Buffer) 
			&& HcStringEqualW(processInfo->ImageName.Buffer, lpName, TRUE))
		{
			pProcessInfo->Id = processId;
			pProcessInfo->ParentProcessId = HandleToUlong(processInfo->InheritedFromUniqueProcessId);

			/* Copy the name */
			HcStringCopyW(pProcessInfo->Name,
				processInfo->ImageName.Buffer,
				processInfo->ImageName.Length);

			ReturnValue = TRUE;
			goto end;
		}

		if (!processInfo->NextEntryOffset)
		{
			break;
		}

		/* Calculate the next entry address */
		processInfo = (PSYSTEM_PROCESS_INFORMATION)((SIZE_T)processInfo + processInfo->NextEntryOffset);
	}

end:
	HcFree(Buffer);
	return ReturnValue;
}

DECL_EXTERN_API(BOOLEAN, ProcessEnumByNameW, CONST LPCWSTR lpProcessName,
	HC_PROCESS_CALLBACKW Callback,
	LPARAM lParam)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
	PHC_PROCESS_INFORMATIONW hcpInformation = NULL;
	PVOID Buffer = NULL;

	/* Query the process list. */
	Status = GetProcessList(&Buffer, &processInfo);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	RtlInitUnicodeString(&processInfo->ImageName, L"IdleSystem");

	/* Loop through the process list */
	while (TRUE)
	{
		hcpInformation = HcInitializeProcessInformationW(MAX_PATH);

		/* Check for a match */
		if (HcStringIsNullOrEmpty(lpProcessName) || HcStringEqualW(processInfo->ImageName.Buffer, lpProcessName, TRUE))
		{
			hcpInformation->Id = HandleToUlong(processInfo->UniqueProcessId);
			hcpInformation->ParentProcessId = HandleToUlong(processInfo->InheritedFromUniqueProcessId);

			/* Copy the name */
			HcStringCopyW(hcpInformation->Name,
				processInfo->ImageName.Buffer,
				processInfo->ImageName.Length);

			/* Call the callback as long as the user doesn't return FALSE. */
			if (Callback(*hcpInformation, lParam))
			{
				HcFree(Buffer);
				HcDestroyProcessInformationW(hcpInformation);
				return TRUE;
			}
		}

		HcDestroyProcessInformationW(hcpInformation);

		if (!processInfo->NextEntryOffset)
		{
			break;
		}

		/* Calculate the next entry address */
		processInfo = (PSYSTEM_PROCESS_INFORMATION)((SIZE_T)processInfo + processInfo->NextEntryOffset);
	}

	HcFree(Buffer);
	return FALSE;
}

DECL_EXTERN_API(SIZE_T, ProcessModuleFileName, CONST HANDLE hProcess,
	CONST LPVOID lpv,
	LPWSTR lpFilename,
	CONST DWORD nSize)
{
	SIZE_T tFileNameLength;
	SIZE_T tFileNameSize = 0;
	NTSTATUS Status;

	struct
	{
		MEMORY_SECTION_NAME memSection;
		WCHAR CharBuffer[MAX_PATH];
	} SectionName;

	/* If no buffer, no need to keep going on */
	if (nSize == 0)
	{
		HcErrorSetNtStatus(STATUS_INSUFFICIENT_RESOURCES);
		return 0;
	}

	/* Query section name */
	Status = HcQueryVirtualMemory(hProcess, lpv, MemoryMappedFilenameInformation,
		&SectionName, sizeof(SectionName), &tFileNameSize);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return 0;
	}

	/* Prepare to copy file name */
	tFileNameLength = tFileNameSize = SectionName.memSection.SectionFileName.Length / sizeof(WCHAR);
	if (tFileNameSize + 1 > nSize)
	{
		tFileNameLength = nSize - 1;
		tFileNameSize = nSize;
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
	}
	else
	{
		HcErrorSetNtStatus(STATUS_SUCCESS);
	}

	/* Copy, zero and return */
	HcInternalCopy(lpFilename, SectionName.memSection.SectionFileName.Buffer, tFileNameLength * sizeof(WCHAR));
	lpFilename[tFileNameLength] = 0;

	return tFileNameSize;
}

static HC_EXTERN_API NTSTATUS HCAPI GetHandleEntries(PSYSTEM_HANDLE_INFORMATION* handleList)
{
	// @defineme 0xffff USHRT_MAX

	NTSTATUS Status;
	ULONG dataLength = 0xffff;

	for (;;)
	{
		*handleList = (PSYSTEM_HANDLE_INFORMATION)HcVirtualAlloc(NULL, dataLength, MEM_COMMIT, PAGE_READWRITE);

		Status = HcQuerySystemInformation(SystemHandleInformation, *handleList, dataLength, &dataLength);
		if (!NT_SUCCESS(Status))
		{
			if (Status != STATUS_INFO_LENGTH_MISMATCH)
			{
				return Status;
			}

			HcVirtualFree(*handleList, 0, MEM_RELEASE);
			dataLength += 0xffff;
		}
		else
		{
			break;
		}
	}

	return Status;
}

DECL_EXTERN_API(BOOLEAN, ProcessEnumHandleEntries, HC_HANDLE_ENTRY_CALLBACKW callback, LPARAM lParam)
{
	PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
	NTSTATUS Status;
	BOOLEAN ReturnValue = FALSE;

	Status = GetHandleEntries(&handleInfo);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	for (DWORD i = handleInfo->NumberOfHandles; i > 0; i--)
	{
		SYSTEM_HANDLE_TABLE_ENTRY_INFO curHandle = handleInfo->Handles[i];

		if (callback(&curHandle, lParam))
		{
			ReturnValue = TRUE;
			break;
		}
	}

	HcVirtualFree(handleInfo, 0, MEM_RELEASE);
	return ReturnValue;
}

DECL_EXTERN_API(BOOLEAN, ProcessEnumHandles, HC_HANDLE_CALLBACKW callback, DWORD dwTypeIndex, LPARAM lParam)
{
	PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
	NTSTATUS Status;
	BOOLEAN ReturnValue = FALSE;
	HANDLE hProcess = NULL;
	DWORD dwLastProcess = 0;
	HANDLE hDuplicate;
	DWORD currentProcessId = HcProcessGetCurrentId();

	Status = GetHandleEntries(&handleInfo);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	for (DWORD i = handleInfo->NumberOfHandles; i > 0; i--)
	{
		const SYSTEM_HANDLE_TABLE_ENTRY_INFO curHandle = handleInfo->Handles[i];
		if (curHandle.ObjectTypeIndex != dwTypeIndex && dwTypeIndex != OBJECT_TYPE_ANY)
		{
			continue;
		}

		if (dwLastProcess != curHandle.UniqueProcessId && curHandle.UniqueProcessId != currentProcessId)
		{
			if (hProcess != NULL)
			{
				HcObjectClose(hProcess);
			}

			hProcess = HcProcessOpen(curHandle.UniqueProcessId, PROCESS_ALL_ACCESS);
			if (!hProcess)
			{
				// report
				continue;
			}

			dwLastProcess = curHandle.UniqueProcessId;
		}

		Status = HcDuplicateObject(hProcess, 
			(HANDLE)curHandle.HandleValue, 
			NtCurrentProcess,
			&hDuplicate,
			0, 
			FALSE,
			DUPLICATE_SAME_ACCESS);

		if (!NT_SUCCESS(Status))
		{
			// report error
			continue;
		}

		if (callback(hDuplicate, hProcess, lParam))
		{
			ReturnValue = TRUE;
			HcObjectClose(hDuplicate);
			goto done;
		}

		HcObjectClose(hDuplicate);
	}

done:
	if (hProcess != NULL)
	{
		HcObjectClose(hProcess);
	}

	HcVirtualFree(handleInfo, 0, MEM_RELEASE);
	return ReturnValue;
}

DECL_EXTERN_API(BOOLEAN, ProcessSetPrivilegeA, CONST HANDLE hProcess,
	CONST LPCSTR Privilege,
	CONST BOOLEAN bEnablePrivilege)
{
	LPWSTR lpConvertedPrivilege = HcStringConvertAtoW(Privilege);
	BOOLEAN bReturn;

	bReturn = HcProcessSetPrivilegeW(hProcess, lpConvertedPrivilege, bEnablePrivilege);
	if (lpConvertedPrivilege != NULL)
	{
		HcFree(lpConvertedPrivilege);
	}

	return bReturn;
}

DECL_EXTERN_API(BOOLEAN, ProcessSetPrivilegeW, CONST HANDLE hProcess,
	CONST LPCWSTR Privilege,
	CONST BOOLEAN bEnablePrivilege)
{
	NTSTATUS Status;
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp;
	TOKEN_PRIVILEGES tpPrevious;
	PLUID pLuid = NULL;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	ZERO(&tp);
	ZERO(&tpPrevious);

	/* Acquire handle to token */
	Status = HcOpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	/* Find the privilege */
	pLuid = HcLookupPrivilegeValueW(Privilege);
	if (!pLuid)
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
		HcObjectClose(hToken);
		return FALSE;
	}

	/* Set one privilege */
	tp.PrivilegeCount = 1;

	/* The id of our privilege */
	tp.Privileges[0].Luid = *pLuid;

	/* No special attributes */
	tp.Privileges[0].Attributes = 0;

	Status = HcAdjustPrivilegesToken(hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious
	);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		HcObjectClose(hToken);
		return FALSE;
	}

	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = *pLuid;

	if (bEnablePrivilege)
	{
		/* Enable this privilege */
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
	else
	{
		/* Disable this privilege */
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
			tpPrevious.Privileges[0].Attributes);
	}

	Status = HcAdjustPrivilegesToken(
		hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL
	);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		HcObjectClose(hToken);
		return FALSE;
	}

	HcObjectClose(hToken);
	return TRUE;
};

DECL_EXTERN_API(BOOLEAN, ProcessGetPebWow64, CONST HANDLE hProcess, PPEB32 pPeb)
{
	NTSTATUS Status;
	ULONG_PTR wow64 = 0;
	ULONG Len = 0;

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcess(
		hProcess,
		ProcessWow64Information,
		&wow64,
		sizeof(wow64),
		&Len);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	if (wow64 == 0)
	{
		HcErrorSetNtStatus(STATUS_PARTIAL_COPY);
		return FALSE;
	}

	if (!HcProcessReadMemory(hProcess,
		(LPVOID)wow64,
		pPeb,
		sizeof(*pPeb),
		NULL))
	{
		return FALSE;
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ProcessGetPeb, CONST HANDLE hProcess, PPEB pPeb)
{
	NTSTATUS Status;
	PROCESS_BASIC_INFORMATION ProcInfo;
	ULONG Len = 0;

	ZERO(&ProcInfo);

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		&ProcInfo,
		sizeof(ProcInfo),
		&Len);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	if (ProcInfo.PebBaseAddress == NULL)
	{
		HcErrorSetNtStatus(STATUS_PARTIAL_COPY);
		return FALSE;
	}

	if (!HcProcessReadMemory(hProcess,
		ProcInfo.PebBaseAddress,
		pPeb,
		sizeof(*pPeb),
		NULL))
	{
		return FALSE;
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ProcessGetPeb32, CONST HANDLE hProcess, PPEB32 pPeb)
{
	NTSTATUS Status;
	PROCESS_BASIC_INFORMATION32 ProcInfo;
	ULONG Len = 0;

	ZERO(&ProcInfo);

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		&ProcInfo,
		sizeof(ProcInfo),
		&Len);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	if (!ProcInfo.PebBaseAddress)
	{
		HcErrorSetNtStatus(STATUS_PARTIAL_COPY);
		return FALSE;
	}

	if (!HcProcessReadMemory(hProcess,
		UlongToHandle(ProcInfo.PebBaseAddress) /* HANDLE == VOID* */,
		pPeb,
		sizeof(*pPeb),
		NULL))
	{
		return FALSE;
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ProcessGetPeb64, CONST HANDLE hProcess, PPEB64 pPeb)
{
	NTSTATUS Status;
#ifdef _WIN64
	PROCESS_BASIC_INFORMATION ProcInfo;
#else
	PROCESS_BASIC_INFORMATION64 ProcInfo;
#endif
	ULONG Len = 0;

	ZERO(&ProcInfo);

#ifdef _WIN64
	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		&ProcInfo,
		sizeof(ProcInfo),
		&Len);
#else
	Status = HcWow64QueryInformationProcess64(hProcess,
		ProcessBasicInformation,
		&ProcInfo,
		sizeof(ProcInfo),
		&Len);
#endif

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	if (!ProcInfo.PebBaseAddress)
	{
		HcErrorSetNtStatus(STATUS_PARTIAL_COPY);
		return FALSE;
	}

#ifdef _WIN64
	if (!HcProcessReadMemory(hProcess,
		(PVOID)ProcInfo.PebBaseAddress,
		pPeb,
		sizeof(*pPeb),
		NULL))
	{
		return FALSE;
	}
#else
	if (!HcWow64ReadVirtualMemory64(hProcess,
		(PVOID64)ProcInfo.PebBaseAddress,
		pPeb,
		sizeof(*pPeb),
		NULL))
	{
		return FALSE;
	}
#endif

	return TRUE;
}

DECL_EXTERN_API(DWORD, ProcessGetCommandLineA, CONST HANDLE hProcess, LPSTR* lpszCommandline, CONST BOOLEAN bAlloc)
{
	LPWSTR lpCmd = NULL;
	DWORD dwReturnLEngth;
	
	if (lpszCommandline == NULL)
	{
		/* query jut the length. */
		return HcProcessGetCommandLineW(hProcess, NULL, FALSE);
	}

	dwReturnLEngth = HcProcessGetCommandLineW(hProcess, &lpCmd, TRUE);

	if (bAlloc)
	{
		*lpszCommandline = HcStringAllocA(dwReturnLEngth);
		HcStringCopyConvertWtoA(lpCmd, *lpszCommandline, dwReturnLEngth);
	}

	HcFree(lpCmd);
	return dwReturnLEngth;
}

DECL_EXTERN_API(DWORD, ProcessGetCommandLineW, CONST HANDLE hProcess,
	LPWSTR* lpszCommandline,
	CONST BOOLEAN bAlloc)
{
	DWORD dwCmdLength;
	PROCESS_BASIC_INFORMATION ProcInfo;
	RTL_USER_PROCESS_PARAMETERS processParameters;
	PEB peb;

	ZERO(&peb);
	ZERO(&ProcInfo);
	ZERO(&processParameters);

	if (!HcProcessGetPeb(hProcess, &peb))
	{
		return 0;
	}

	if (!HcProcessReadMemory(hProcess,
		peb.ProcessParameters,
		&processParameters,
		sizeof(processParameters),
		NULL))
	{
		return 0;
	}

	dwCmdLength = processParameters.CommandLine.Length / sizeof(WCHAR);
	if (lpszCommandline == NULL)
	{
		return dwCmdLength;
	}

	if (bAlloc)
	{
		*lpszCommandline = HcStringAllocW(dwCmdLength);
		if (!*lpszCommandline)
		{
			HcErrorSetNtStatus(STATUS_NO_MEMORY);
			return 0;
		}
	}

	if (!HcProcessReadNullifiedString(hProcess,
		&(processParameters.CommandLine),
		*lpszCommandline,
		processParameters.CommandLine.Length / 2))
	{
		return 0;
	}

	return dwCmdLength;
}

DECL_EXTERN_API(DWORD, ProcessGetCurrentDirectoryW,CONST HANDLE hProcess, LPWSTR* lpszDirectory)
{
	PROCESS_BASIC_INFORMATION pbi;
	RTL_USER_PROCESS_PARAMETERS upp;
	PEB peb;
	DWORD dwReturnLength;
	SIZE_T len = 0;

	ZERO(&pbi);
	ZERO(&upp);
	ZERO(&peb);

	if (!HcProcessGetPeb(hProcess, &peb))
	{
		return 0;
	}

	if (!HcProcessReadMemory(hProcess, 
		peb.ProcessParameters,
		&upp, 
		sizeof(RTL_USER_PROCESS_PARAMETERS), 
		&len))
	{
		return 0;
	}

	dwReturnLength = upp.CurrentDirectory.DosPath.Length / sizeof(WCHAR);
	if (lpszDirectory == NULL)
	{
		return dwReturnLength;
	}

	if (!HcProcessReadNullifiedString(hProcess,
		&upp.CurrentDirectory.DosPath,
		*lpszDirectory, 
		upp.CurrentDirectory.DosPath.Length))
	{
		return 0;
	}

	return dwReturnLength;
}

DECL_EXTERN_API(DWORD, ProcessGetCurrentDirectoryA, CONST HANDLE hProcess, LPSTR* szDirectory)
{
	LPWSTR lpCopy = HcStringAllocW(MAX_PATH);
	DWORD dwCount;

	if (szDirectory == NULL)
	{
		/* just give the count */
		return HcProcessGetCurrentDirectoryW(hProcess, NULL);
	}

	dwCount = HcProcessGetCurrentDirectoryW(hProcess, &lpCopy);
	if (!dwCount)
	{
		HcFree(lpCopy);
		return 0;
	}

	if (!HcStringCopyConvertWtoA(lpCopy, *szDirectory, dwCount))
	{
		HcFree(lpCopy);
		return 0;
	}

	HcFree(lpCopy);
	return dwCount;
}
