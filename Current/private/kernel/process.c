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
	Status = HcQueryInformationProcessEx(Process,
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
	Status = HcQueryInformationProcessEx(hProcess,
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

	return pbi != 0;
}

DECL_EXTERN_API(BOOLEAN, ProcessIsWow64, CONST IN DWORD dwProcessId)
{
	HANDLE hProcess;
	BOOLEAN Result = FALSE;

	hProcess = HcProcessOpen(dwProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
	if (hProcess)
	{
		Result = HcProcessIsWow64Ex(hProcess);
		HcObjectClose(&hProcess);
	}

	return Result;
}

DECL_EXTERN_API(BOOLEAN, ProcessExitCode, CONST IN SIZE_T dwProcessId, OUT LPDWORD lpExitCode)
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
	Status = HcQueryInformationProcessEx(hProcess,
		ProcessBasicInformation,
		&ProcessBasic,
		sizeof(ProcessBasic),
		NULL);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		HcObjectClose(&hProcess);
		return FALSE;
	}

	*lpExitCode = (DWORD)ProcessBasic.ExitStatus;

	HcObjectClose(&hProcess);
	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ProcessExitCodeEx, CONST IN HANDLE hProcess, OUT LPDWORD lpExitCode)
{
	PROCESS_BASIC_INFORMATION ProcessBasic;
	NTSTATUS Status;

	ZERO(&ProcessBasic);

	/* Ask the kernel */
	Status = HcQueryInformationProcessEx(hProcess,
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

DECL_EXTERN_API(HANDLE, ProcessOpen, CONST IN SIZE_T dwProcessId, CONST IN ACCESS_MASK DesiredAccess)
{
	NTSTATUS Status;
	HANDLE hProcess = NULL;

	if (HcGlobal.IsWow64)
	{
		OBJECT_ATTRIBUTES_WOW64 oa;
		CLIENT_ID_WOW64 cid;
		PTR_64(HANDLE) hProcess64 = 0;

		ZERO(&oa);
		ZERO(&cid);

		cid.UniqueProcess = WOW64_CONVERT(HANDLE) dwProcessId;
		cid.UniqueThread = 0;

		InitializeObjectAttributesWow64(&oa, NULL, 0, NULL, NULL);

		Status = HcOpenProcessWow64((ULONG64) &hProcess64, DesiredAccess, (ULONG64) &oa, (ULONG64) &cid);
		if (NT_SUCCESS(Status))
		{
			hProcess = POINTER32_HARDCODED (HANDLE) hProcess64;
		}
	}
	else
	{
		OBJECT_ATTRIBUTES oa;
		CLIENT_ID cid;

		ZERO(&oa);
		ZERO(&cid);

		cid.UniqueProcess = (HANDLE) dwProcessId;
		cid.UniqueThread = 0;

		InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

		Status = HcOpenProcess(&hProcess, DesiredAccess, &oa, &cid);
	}

	HcErrorSetNtStatus(Status);
	if (NT_SUCCESS(Status))
	{
		return hProcess;
	}

	return 0;
}

DECL_EXTERN_API(BOOLEAN, ProcessReadyEx, CONST IN HANDLE hProcess)
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
	Status = HcQueryInformationProcessEx(hProcess,
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

DECL_EXTERN_API(BOOLEAN, ProcessReady, CONST IN SIZE_T dwProcessId)
{
	BOOLEAN Success;
	HANDLE hProcess;

	hProcess = HcProcessOpen(dwProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
	if (!hProcess)
	{
		return FALSE;
	}

	Success = HcProcessReadyEx(hProcess);

	HcObjectClose(&hProcess);
	return Success;
}

DECL_EXTERN_API(BOOLEAN, ProcessSuspend, CONST IN SIZE_T dwProcessId)
{
	BOOLEAN Success;
	HANDLE hProcess;

	hProcess = HcProcessOpen(dwProcessId, PROCESS_SUSPEND_RESUME);
	if (!hProcess)
	{
		return FALSE;
	}

	Success = HcProcessSuspendEx(hProcess);
	HcObjectClose(&hProcess);

	return Success;
}

DECL_EXTERN_API(BOOLEAN, ProcessTerminate, CONST IN HANDLE hProcess, CONST IN NTSTATUS Status)
{
	NTSTATUS rStatus;

	if (HcGlobal.IsWow64)
	{
		rStatus = HcTerminateProcessWow64((ULONG64) hProcess, Status);
	}
	else
	{
		rStatus = HcTerminateProcess(hProcess, Status);
	}

	return NT_SUCCESS(Status);
}

DECL_EXTERN_API(BOOLEAN, ProcessSuspendEx, CONST IN HANDLE hProcess)
{
	NTSTATUS Status;

	if (HcGlobal.IsWow64)
	{
		Status = HcSuspendProcessWow64((ULONG64) hProcess);
	}
	else
	{
		Status = HcSuspendProcess(hProcess);
	}

	return NT_SUCCESS(Status);
}

DECL_EXTERN_API(BOOLEAN, ProcessResume, CONST IN SIZE_T dwProcessId)
{
	NTSTATUS Status;
	HANDLE hProcess;

	hProcess = HcProcessOpen(dwProcessId, PROCESS_SUSPEND_RESUME);
	if (!hProcess)
	{
		return FALSE;
	}

	Status = HcProcessResumeEx(hProcess);
	HcObjectClose(&hProcess);

	return NT_SUCCESS(Status);
}

DECL_EXTERN_API(BOOLEAN, ProcessResumeEx, CONST IN HANDLE hProcess)
{
	NTSTATUS Status;

	if (HcGlobal.IsWow64)
	{
		Status = HcResumeProcessWow64((ULONG64) hProcess);
	}
	else
	{
		Status = HcResumeProcess(hProcess);
	}

	return NT_SUCCESS(Status);
}

static BOOLEAN NTAPI HcProcessWriteMemoryInternal(CONST IN HANDLE hProcess,
	CONST IN LPVOID lpBaseAddress,
	CONST IN LPVOID lpBuffer,
	IN SIZE_T nSize,
	OUT PSIZE_T lpNumberOfBytesWritten)
{
	NTSTATUS Status;
	SIZE_T WrittenBytes = 0;

	if (HcGlobal.IsWow64)
	{
		PTR_64(SIZE_T) nSize64 = WOW64_CONVERT(SIZE_T) nSize;

		Status = HcWriteVirtualMemoryWow64((ULONG64) hProcess,
			(ULONG64) lpBaseAddress,
			(ULONG64) lpBuffer,
			nSize,
			(ULONG64) &nSize64);

		WrittenBytes = (SIZE_T) nSize64;
	}
	else
	{
		Status = HcWriteVirtualMemory(hProcess,
			lpBaseAddress,
			(LPVOID) lpBuffer,
			nSize,
			&nSize);
	}

	if (NT_SUCCESS(Status))
	{
		if (lpNumberOfBytesWritten)
		{
			*lpNumberOfBytesWritten = WrittenBytes;
		}
	}

	HcErrorSetNtStatus(Status);
	return NT_SUCCESS(Status);
}

DECL_EXTERN_API(BOOLEAN, ProcessWriteMemory, CONST IN HANDLE hProcess,
	CONST IN LPVOID lpBaseAddress,
	CONST IN LPVOID lpBuffer,
	IN SIZE_T nSize,
	OUT PSIZE_T lpNumberOfBytesWritten)
{
	ULONG OldValue = 0;
	BOOLEAN UnProtect;
	BOOLEAN Success;

	Success = HcVirtualProtectEx(hProcess, 
		lpBaseAddress,
		nSize,
		PAGE_EXECUTE_READWRITE,
		&OldValue);

	if (Success)
	{
		/* Check if we are unprotecting */
		UnProtect = OldValue & (PAGE_READWRITE |
			PAGE_WRITECOPY |
			PAGE_EXECUTE_READWRITE |
			PAGE_EXECUTE_WRITECOPY) ? FALSE : TRUE;

		if (!UnProtect)
		{
			/* Set the new protection */
			HcVirtualProtectEx(hProcess,
				lpBaseAddress,
				nSize,
				OldValue,
				&OldValue);

			/* Write the memory */
			Success = HcProcessWriteMemoryInternal(hProcess,
				lpBaseAddress,
				(LPVOID)lpBuffer,
				nSize,
				&nSize);

			/* In Win32, the parameter is optional, so handle this case */
			if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;

			if (!Success)
			{
				return FALSE;
			}

			/* Flush the ITLB */
			HcProcessFlushInstructionCache(hProcess, lpBaseAddress, nSize);
			return TRUE;
		}

		/* Check if we were read only */
		if (OldValue & (PAGE_NOACCESS | PAGE_READONLY))
		{
			/* Restore protection and fail */
			HcVirtualProtectEx(hProcess,
				lpBaseAddress,
				nSize,
				OldValue,
				&OldValue);

			/* Note: This is what Windows returns and code depends on it */
			return FALSE;
		}

		/* Otherwise, do the write */
		Success = HcProcessWriteMemoryInternal(hProcess,
			lpBaseAddress,
			(LPVOID)lpBuffer,
			nSize,
			&nSize);

		/* In Win32, the parameter is optional, so handle this case */
		if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;

		/* And restore the protection */
		HcVirtualProtectEx(hProcess,
			lpBaseAddress,
			nSize,
			OldValue,
			&OldValue);

		if (!Success)
		{
			/* Note: This is what Windows returns and code depends on it */
			return FALSE;
		}

		/* Flush the ITLB */
		HcProcessFlushInstructionCache(hProcess, lpBaseAddress, nSize);
		return TRUE;
	}

	return FALSE;
}

DECL_EXTERN_API(BOOLEAN, ProcessWriteMemoryWow64, CONST IN HANDLE hProcess,
	CONST IN PVOID64 lpBaseAddress,
	CONST IN PVOID64 lpBuffer,
	IN ULONG64 nSize,
	OUT PULONG64 lpNumberOfBytesWritten)
{
	NTSTATUS Status;

	/* Write the memory */
	Status = HcWriteVirtualMemoryWow64((DWORD64) hProcess,
		(DWORD64) lpBaseAddress,
		(DWORD64) lpBuffer,
		(DWORD64) nSize,
		(DWORD64) &nSize);

	/* In Win32, the parameter is optional, so handle this case */
	if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ProcessWriteMemory64, CONST IN HANDLE hProcess,
	CONST IN PVOID64 lpBaseAddress,
	CONST IN PVOID64 lpBuffer,
	IN ULONG64 nSize,
	OUT PULONG64 lpNumberOfBytesWritten)
{
#ifndef _WIN64
	return HcProcessWriteMemoryWow64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
#else
	return HcProcessWriteMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
#endif
}

DECL_EXTERN_API(BOOLEAN, ProcessReadMemory, CONST IN HANDLE hProcess,
	IN LPVOID lpBaseAddress,
	IN LPVOID lpBuffer,
	IN SIZE_T nSize,
	OUT PSIZE_T lpNumberOfBytesRead)
{
	NTSTATUS Status;
	SIZE_T ReadBytes = 0;

	if (HcGlobal.IsWow64)
	{
		PTR_64(SIZE_T) nSize64 = 0;

		Status = HcReadVirtualMemoryWow64((ULONG64) hProcess,
			(ULONG64) lpBaseAddress,
			(ULONG64) lpBuffer,
			nSize,
			(ULONG64) &nSize64);

		ReadBytes = (SIZE_T) nSize64;
	}
	else
	{
		Status = HcReadVirtualMemory(hProcess,
			lpBaseAddress,
			lpBuffer,
			nSize,
			&ReadBytes);
	}

	/* In user-mode, this parameter is optional */
	if (lpNumberOfBytesRead)
	{
		*lpNumberOfBytesRead = ReadBytes;
	}

	HcErrorSetNtStatus(Status);
	return NT_SUCCESS(Status);
}

DECL_EXTERN_API(BOOLEAN, ProcessReadMemoryWow64, CONST IN HANDLE hProcess,
	IN PVOID64 lpBaseAddress,
	IN PVOID64 lpBuffer,
	IN ULONG64 nSize,
	OUT PULONG64 lpNumberOfBytesRead)
{
	NTSTATUS Status;
	ULONGLONG ReadBytes = 0;

	/* Do the read */
	Status = HcReadVirtualMemoryWow64((DWORD64) hProcess,
		(DWORD64) lpBaseAddress,
		(DWORD64) lpBuffer,
		(DWORD64) nSize,
		(DWORD64) &ReadBytes);

	/* In user-mode, this parameter is optional */
	if (lpNumberOfBytesRead)
	{
		*lpNumberOfBytesRead = ReadBytes;
	}

	HcErrorSetNtStatus(Status);
	return NT_SUCCESS(Status);
}

DECL_EXTERN_API(BOOLEAN, ProcessReadMemory64, CONST IN HANDLE hProcess,
	IN PVOID64 lpBaseAddress,
	IN PVOID64 lpBuffer,
	IN ULONG64 nSize,
	OUT PULONG64 lpNumberOfBytesRead)
{
#ifndef _WIN64
	return HcProcessReadMemoryWow64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
#else
	return HcProcessReadMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
#endif
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
		return INVALID_HANDLE;
	}

	return hThread;
}

DECL_EXTERN_API(HANDLE, ProcessCreateThread64, CONST IN HANDLE hProcess,
	CONST IN DWORD64 lpStartAddress,
	CONST IN DWORD64 lpParameter,
	CONST IN DWORD dwCreationFlags)
{
	NTSTATUS Status;
	HANDLE hThread = 0;

#ifndef _WIN64
	DWORD64 hThread64 = 0;
	Status = HcCreateThreadExWow64((DWORD64) &hThread64, THREAD_ALL_ACCESS, 0, (DWORD64) hProcess, lpStartAddress, lpParameter, 0, 0, 0, 0, 0);
#else
	Status = HcCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPVOID) lpStartAddress, (LPVOID) lpParameter, dwCreationFlags, 0, 0, 0, NULL);
#endif
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return INVALID_HANDLE;
	}

#ifndef _WIN64
	hThread = (HANDLE) (ULONG_PTR) hThread64;
#endif

	return hThread;
}

DECL_EXTERN_API(BOOLEAN, ProcessReadNullifiedString, CONST IN HANDLE hProcess,
	CONST IN PUNICODE_STRING usStringIn,
	OUT LPWSTR lpStringOut,
	CONST IN SIZE_T lpSize)
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

static void internal_spi_to_highcall_struct(PSYSTEM_PROCESS_INFORMATION sysInfo, PPROCESS_INFORMATION_W pInformation)
{
	if (sysInfo == NULL || pInformation == NULL)
		return;

	pInformation->Id = HandleToUlong(sysInfo->UniqueProcessId);
	pInformation->ParentProcessId = HandleToUlong(sysInfo->InheritedFromUniqueProcessId);

	if (sysInfo->ImageName.Buffer != NULL)
	{
		/* Copy the name */
		HcStringCopyW(pInformation->Name,
			sysInfo->ImageName.Buffer,
			sysInfo->ImageName.Length / sizeof(WCHAR));
	}
}

static void internal_spi_to_highcall_struct_detailed(PSYSTEM_PROCESS_INFORMATION sysInfo, PPROCESS_INFORMATION_EX_W pInformation)
{
	pInformation->Id = HandleToUlong(sysInfo->UniqueProcessId);
	pInformation->ParentProcessId = HandleToUlong(sysInfo->InheritedFromUniqueProcessId);

	/* Copy the name */
	HcStringCopyW(pInformation->Name,
		sysInfo->ImageName.Buffer,
		sysInfo->ImageName.Length / sizeof(WCHAR));

	/* Try opening the process */
	HANDLE hProcess = HcProcessOpen(pInformation->Id, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);

	if (hProcess != NULL)
	{
		pInformation->CanAccess = TRUE;

		/* Query main module */
		HcModuleQueryInformationExW(hProcess, NULL, &pInformation->MainModule);

		/* Close this handle. */
		HcObjectClose(&hProcess);
	}
}

static NTSTATUS internal_process_list(LPVOID* ppBuffer, PSYSTEM_PROCESS_INFORMATION* pSystemInformation, LPVOID* processInfo64)
{
	DWORD ReturnLength = 0;
	LPVOID Buffer;
	PSYSTEM_PROCESS_INFORMATION pSysList;
	NTSTATUS Status;
	LPVOID SystemInformation64 = NULL;
	
	Status = HcQuerySystemInformationInternal(SystemProcessInformation, NULL, 0, &ReturnLength, &SystemInformation64);
	if (Status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return Status;
	}

	Buffer = HcAlloc(ReturnLength);
	pSysList = (PSYSTEM_PROCESS_INFORMATION)Buffer;

	for (;;)
	{
		/* Query the process list. */
		Status = HcQuerySystemInformationInternal(SystemProcessInformation, pSysList, ReturnLength, &ReturnLength, &SystemInformation64);

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
		*processInfo64 = SystemInformation64;
	}
	else
	{
		HcFree(Buffer);
	}

	return Status;
}

DECL_EXTERN_API(BOOLEAN, ProcessEnumByNameExW, IN LPCWSTR lpProcessName,
	IN ProcessCallbackExW Callback,
	IN LPARAM lParam)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
	PROCESS_INFORMATION_EX_W hcpInformation;
	PVOID Buffer = NULL;
	LPVOID processInfo64 = NULL;

	/* Query the process list. */
	Status = internal_process_list(&Buffer, &processInfo, &processInfo64);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	/* Loop through the process list */
	while (TRUE)
	{
		/* Check for a match */
		if (HcStringIsNullOrEmpty(lpProcessName) || HcStringEqualW(processInfo->ImageName.Buffer, lpProcessName, TRUE))
		{
			internal_spi_to_highcall_struct_detailed(processInfo, &hcpInformation);

			/* Call the callback as long as the user doesn't return FALSE. */
			if (Callback(hcpInformation, lParam))
			{
				HcFree(Buffer);
				return TRUE;
			}
		}

		if (!processInfo->NextEntryOffset)
		{
			break;
		}

		/* Calculate the next entry address */
		processInfo = (PSYSTEM_PROCESS_INFORMATION)((SIZE_T)processInfo + processInfo->NextEntryOffset);
	}

	HcFree(processInfo64);
	HcFree(Buffer);
	return FALSE;
}

DECL_EXTERN_API(BOOLEAN, ProcessGetById, CONST IN DWORD dwProcessId, OUT PPROCESS_INFORMATION_W pProcessInfo)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
	PVOID Buffer = NULL;
	BOOLEAN ReturnValue = FALSE;
	LPVOID processInfo64 = NULL;

	/* Query the process list. */
	Status = internal_process_list(&Buffer, &processInfo, &processInfo64);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return ReturnValue;
	}

	/* Loop through the process list */
	while (TRUE)
	{
		DWORD processId = HandleToUlong(processInfo->UniqueProcessId);

		/* Check for a match */
		if (processId == dwProcessId)
		{
			internal_spi_to_highcall_struct(processInfo, pProcessInfo);

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
	HcFree(processInfo64);
	HcFree(Buffer);
	return ReturnValue;
}


DECL_EXTERN_API(NTSTATUS, QuerySystemInformationInternal, IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT LPVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength,
	OUT LPVOID* outSystemInfo64)
{
	NTSTATUS Status;
	LPVOID SystemInformation64;

	if (HcGlobal.IsWow64)
	{
		SystemInformation64 = HcAlloc(SystemInformationLength);

		Status = HcQuerySystemInformationWow64(SystemInformationClass, (ULONG64) SystemInformation64, SystemInformationLength, ReturnLength);
		if (NT_SUCCESS(Status))
		{
			/* Praise thy conversions. */
			if (SystemInformationClass == SystemProcessInformation)
			{
				PSYSTEM_PROCESS_INFORMATION_WOW64 SystemInfo64 = (PSYSTEM_PROCESS_INFORMATION_WOW64) SystemInformation64;
				PSYSTEM_PROCESS_INFORMATION SystemOriginal = (PSYSTEM_PROCESS_INFORMATION) SystemInformation;

				/* Loop through the process list */
				LPVOID previousAddress = NULL;

				while (TRUE)
				{
					HcInternalCopy(SystemOriginal, SystemInfo64, FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION_WOW64, ImageName));
					HcInternalCopy(
						((LPBYTE) SystemOriginal) + FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION, ReadOperationCount),
						((LPBYTE) SystemInfo64) + FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION_WOW64, ReadOperationCount),
						sizeof(SYSTEM_PROCESS_INFORMATION_WOW64) - FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION_WOW64, ReadOperationCount));

					SystemOriginal->BasePriority = SystemInfo64->BasePriority;
					SystemOriginal->ImageName.Buffer = (PWSTR) (ULONG_PTR) SystemInfo64->ImageName.Buffer;
					SystemOriginal->ImageName.Length = SystemInfo64->ImageName.Length;
					SystemOriginal->ImageName.MaximumLength = SystemInfo64->ImageName.MaximumLength;
					SystemOriginal->InheritedFromUniqueProcessId = (HANDLE) (ULONG_PTR) SystemInfo64->InheritedFromUniqueProcessId;
					SystemOriginal->UniqueProcessId = (HANDLE) (ULONG_PTR) SystemInfo64->UniqueProcessId;
					SystemOriginal->HandleCount = SystemInfo64->HandleCount;
					SystemOriginal->SessionId = SystemInfo64->SessionId;
					SystemOriginal->PeakVirtualSize = (ULONG_PTR) SystemInfo64->PeakVirtualSize;
					SystemOriginal->VirtualSize = (ULONG_PTR) SystemInfo64->VirtualSize;
					SystemOriginal->PageFaultCount = SystemInfo64->PageFaultCount;
					SystemOriginal->PeakWorkingSetSize = (ULONG_PTR) SystemInfo64->PeakWorkingSetSize;
					SystemOriginal->WorkingSetSize = (ULONG_PTR) SystemInfo64->WorkingSetSize;
					SystemOriginal->QuotaPeakPagedPoolUsage = (ULONG_PTR) SystemInfo64->QuotaPeakPagedPoolUsage;
					SystemOriginal->QuotaPeakNonPagedPoolUsage = (ULONG_PTR) SystemInfo64->QuotaPeakNonPagedPoolUsage;
					SystemOriginal->QuotaNonPagedPoolUsage = (ULONG_PTR) SystemInfo64->QuotaNonPagedPoolUsage;
					SystemOriginal->PagefileUsage = (ULONG_PTR) SystemInfo64->PagefileUsage;
					SystemOriginal->PeakPagefileUsage = (ULONG_PTR) SystemInfo64->PeakPagefileUsage;
					SystemOriginal->PrivatePageCount = (ULONG_PTR) SystemInfo64->PrivatePageCount;

					/* Add full support for thread lists.. :( */

					for (DWORD i = 0; i < SystemOriginal->NumberOfThreads; i++)
					{
						HcInternalCopy(&SystemOriginal->Threads[i], &SystemInfo64->Threads[i], FIELD_OFFSET(SYSTEM_THREAD_INFORMATION_WOW64, WaitTime));

						SystemOriginal->Threads[i].ClientId.UniqueProcess = (HANDLE) (ULONG_PTR) SystemInfo64->Threads[i].ClientId.UniqueProcess;
						SystemOriginal->Threads[i].ClientId.UniqueThread = (HANDLE) (ULONG_PTR) SystemInfo64->Threads[i].ClientId.UniqueThread;
						SystemOriginal->Threads[i].WaitTime = SystemInfo64->Threads[i].WaitTime;
						SystemOriginal->Threads[i].StartAddress = (PBYTE) (ULONG_PTR) SystemInfo64->Threads[i].StartAddress;
						SystemOriginal->Threads[i].Priority = SystemInfo64->Threads[i].Priority;
						SystemOriginal->Threads[i].BasePriority = SystemInfo64->Threads[i].BasePriority;
						SystemOriginal->Threads[i].ContextSwitches = SystemInfo64->Threads[i].ContextSwitches;
						SystemOriginal->Threads[i].ThreadState = SystemInfo64->Threads[i].ThreadState;
						SystemOriginal->Threads[i].WaitReason = SystemInfo64->Threads[i].WaitReason;
					}

					if (!SystemInfo64->NextEntryOffset)
					{
						break;
					}

					previousAddress = SystemOriginal;

					SystemOriginal = (PSYSTEM_PROCESS_INFORMATION) ((ULONG64) SystemOriginal + SystemInfo64->NextEntryOffset);
					SystemInfo64 = (PSYSTEM_PROCESS_INFORMATION_WOW64) ((ULONG64) SystemInfo64 + SystemInfo64->NextEntryOffset);

					SystemOriginal->NextEntryOffset = (ULONG) ((ULONG_PTR) SystemOriginal - (ULONG_PTR) previousAddress);
				}
			}
			else if (SystemInformationClass == SystemHandleInformation)
			{
				PSYSTEM_HANDLE_INFORMATION_WOW64 SystemInfo = (PSYSTEM_HANDLE_INFORMATION_WOW64) SystemInformation64;
				PSYSTEM_HANDLE_INFORMATION SystemOriginal = (PSYSTEM_HANDLE_INFORMATION) SystemInformation;
				
				SystemOriginal->NumberOfHandles = SystemInfo->NumberOfHandles;

				for (DWORD i = 0; i < SystemOriginal->NumberOfHandles; i++)
				{
					HcInternalCopy(&SystemOriginal->Handles[i], &SystemInfo->Handles[i], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
					SystemOriginal->Handles[i].Object = (PVOID) (ULONG_PTR) SystemInfo->Handles[i].Object;
					SystemOriginal->Handles[i].GrantedAccess = SystemInfo->Handles[i].GrantedAccess;
				}
			}
			else
			{
				HcInternalCopy(SystemInformation, (LPVOID) (ULONG_PTR) SystemInformation64, SystemInformationLength);
			}

			if (outSystemInfo64)
			{
				*outSystemInfo64 = SystemInformation64;
			}
		}
	}
	else
	{
		Status = HcQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	}

	return Status;
}


DECL_EXTERN_API(NTSTATUS, ProcessFlushInstructionCache, CONST IN HANDLE ProcessHandle,
	CONST IN LPVOID BaseAddress,
	CONST IN SIZE_T NumberOfBytesToFlush)
{
	if (HcGlobal.IsWow64)
	{
		return HcFlushInstructionCacheWow64((ULONG64) ProcessHandle, (ULONG64) BaseAddress, NumberOfBytesToFlush);
	}

	return HcFlushInstructionCache(ProcessHandle, BaseAddress, NumberOfBytesToFlush);
}

DECL_EXTERN_API(NTSTATUS, QueryInformationProcess64,
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT LPVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	NTSTATUS Status;

#ifdef _WIN64

	Status = HcQueryInformationProcess(ProcessHandle,
		ProcessInformationClass,
		ProcessInformation,
		ProcessInformationLength,
		ReturnLength);

#else

	Status = HcQueryInformationProcessWow64((ULONG64) ProcessHandle,
		ProcessInformationClass,
		(ULONG64) ProcessInformation,
		ProcessInformationLength,
		(ULONG64) ReturnLength);

#endif // _WIN64

	return Status;
}

DECL_EXTERN_API(NTSTATUS, QueryInformationProcessEx,
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT LPVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	if (HcGlobal.IsWow64)
	{
		NTSTATUS Status;
		ULONG OriginalLength = ProcessInformationLength;

		if (ProcessInformationClass == ProcessBasicInformation)
		{
			ProcessInformationLength = sizeof(PROCESS_BASIC_INFORMATION_WOW64);
		}
		else if (ProcessInformationClass == ProcessWow64Information)
		{
			ProcessInformationLength = sizeof(ULONG64);
		}

		PTR_64(LPVOID) ProcessInformation64 = WOW64_CONVERT(LPVOID) HcAlloc(ProcessInformationLength);
		
		Status = HcQueryInformationProcessWow64((ULONG64) ProcessHandle,
			ProcessInformationClass,
			ProcessInformation64,
			ProcessInformationLength,
			(ULONG64) ReturnLength);

		if (NT_SUCCESS(Status))
		{
			if (ProcessInformationClass == ProcessBasicInformation)
			{
				ConvertProcessBasicInformationFromWow64((PPROCESS_BASIC_INFORMATION_WOW64) ProcessInformation64, (PPROCESS_BASIC_INFORMATION) ProcessInformation);
			}
			else if (ProcessInformationClass == ProcessWow64Information)
			{
				*((ULONG_PTR*) ProcessInformation) = (ULONG_PTR) (*(ULONG64*) ProcessInformation64);
			}
			else
			{
				HcInternalCopy(ProcessInformation, POINTER32_HARDCODED(LPVOID) ProcessInformation64, OriginalLength);
			}
		}
		
		HcFree(POINTER32_HARDCODED(LPVOID) ProcessInformation64);
		return Status;
	}

	return HcQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

DECL_EXTERN_API(BOOLEAN, ProcessGetByNameW, IN LPCWSTR lpName, OUT PPROCESS_INFORMATION_W pProcessInfo)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
	PVOID Buffer = NULL;
	BOOLEAN ReturnValue = FALSE;
	LPVOID processInfo64 = NULL;

	/* Query the process list. */
	Status = internal_process_list(&Buffer, &processInfo, &processInfo64);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return ReturnValue;
	}

	/* Loop through the process list */
	while (TRUE)
	{
		/* Check for a match */
		if (!HcStringIsNullOrEmpty(processInfo->ImageName.Buffer) && HcStringEqualW(processInfo->ImageName.Buffer, lpName, TRUE))
		{
			internal_spi_to_highcall_struct(processInfo, pProcessInfo);

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
	HcFree(processInfo64);
	HcFree(Buffer);
	return ReturnValue;
}

DECL_EXTERN_API(BOOLEAN, ProcessGetAllByNameW, IN LPCWSTR lpName, OUT PROCESS_INFORMATION_W* ProcessList, OUT PULONG Count)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
	PVOID Buffer = NULL;
	PVOID processInfo64 = NULL;
	BOOLEAN ReturnValue = FALSE;

	if (Count == NULL)
	{
		HcErrorSetDosError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	*Count = 0;

	/* Query the process list. */
	Status = internal_process_list(&Buffer, &processInfo, &processInfo64);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return ReturnValue;
	}

	if (processInfo == NULL)
		return STATUS_ABANDONED;

	/* Loop through the process list */
	while (TRUE)
	{
		/* Check for a match */
		if (lpName == NULL || (!HcStringIsNullOrEmpty(processInfo->ImageName.Buffer) && HcStringEqualW(processInfo->ImageName.Buffer, lpName, TRUE)))
		{
			/* Insert process into PROCESS_INFORMATION_W[n] structure. */
			if (ProcessList)
			{
				internal_spi_to_highcall_struct(processInfo, &(ProcessList)[*Count]);
			}

			if (!ReturnValue)
			{
				ReturnValue = TRUE;
			}

			(*Count)++;
		}

		if (!processInfo->NextEntryOffset)
		{
			break;
		}

		/* Calculate the next entry address */
		processInfo = (PSYSTEM_PROCESS_INFORMATION) ((SIZE_T) processInfo + processInfo->NextEntryOffset);
	}

	HcFree(processInfo64);
	HcFree(Buffer);
	return ReturnValue;
}

DECL_EXTERN_API(BOOLEAN, ProcessEnumByNameW, IN LPCWSTR lpProcessName,
	IN ProcessCallbackW Callback,
	IN LPARAM lParam)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
	PROCESS_INFORMATION_W hcpInformation;
	PVOID Buffer = NULL;
	LPVOID processInfo64 = NULL;

	/* Query the process list. */
	Status = internal_process_list(&Buffer, &processInfo, &processInfo64);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	/* Loop through the process list */
	while (TRUE)
	{
		ZERO(&hcpInformation);

		/* Check for a match */
		if (HcStringIsNullOrEmpty(lpProcessName) || HcStringEqualW(processInfo->ImageName.Buffer, lpProcessName, TRUE))
		{
			internal_spi_to_highcall_struct(processInfo, &hcpInformation);

			/* Call the callback as long as the user doesn't return FALSE. */
			if (Callback(hcpInformation, lParam))
			{
				HcFree(Buffer);
				return TRUE;
			}
		}

		if (!processInfo->NextEntryOffset)
		{
			break;
		}

		/* Calculate the next entry address */
		processInfo = (PSYSTEM_PROCESS_INFORMATION)((SIZE_T)processInfo + processInfo->NextEntryOffset);
	}

	HcFree(processInfo64);
	HcFree(Buffer);
	return FALSE;
}

DECL_EXTERN_API(BOOLEAN, ProcessSetPrivilegeA, CONST IN HANDLE hProcess,
	IN LPCSTR Privilege,
	CONST IN BOOLEAN bEnablePrivilege)
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

DECL_EXTERN_API(BOOLEAN, ProcessSetPrivilegeW, CONST IN HANDLE hProcess,
	IN LPCWSTR Privilege,
	CONST IN BOOLEAN bEnablePrivilege)
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
		HcObjectClose(&hToken);
		return FALSE;
	}

	/* Set one privilege */
	tp.PrivilegeCount = 1;

	/* The id of our privilege */
	tp.Privileges[0].Luid = *pLuid;

	/* No special attributes */
	tp.Privileges[0].Attributes = 0;

	if (HcGlobal.IsWow64)
	{
		Status = HcAdjustPrivilegesTokenWow64((ULONG64) hToken,
			FALSE,
			(ULONG64) &tp,
			sizeof(TOKEN_PRIVILEGES),
			(ULONG64) &tpPrevious,
			(ULONG64) &cbPrevious);
	}
	else
	{
		Status = HcAdjustPrivilegesToken(hToken,
			FALSE,
			&tp,
			sizeof(TOKEN_PRIVILEGES),
			&tpPrevious,
			&cbPrevious);
	}

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		HcObjectClose(&hToken);
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
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);
	}

	Status = HcAdjustPrivilegesToken(
		hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		HcObjectClose(&hToken);
		return FALSE;
	}

	HcObjectClose(&hToken);
	return TRUE;
};

DECL_EXTERN_API(BOOLEAN, ProcessGetPebWow64, CONST IN HANDLE hProcess, OUT PPEB32 pPeb)
{
	NTSTATUS Status;
	ULONG_PTR wow64 = 0;
	ULONG Len = 0;

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcessEx(
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

DECL_EXTERN_API(BOOLEAN, ProcessGetPeb, CONST IN HANDLE hProcess, OUT PPEB pPeb)
{
	NTSTATUS Status;
	PROCESS_BASIC_INFORMATION ProcInfo;
	ULONG Len = 0;

	ZERO(&ProcInfo);

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcessEx(hProcess,
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

DECL_EXTERN_API(BOOLEAN, ProcessGetPeb32, CONST IN HANDLE hProcess, OUT PPEB32 pPeb)
{
	NTSTATUS Status;
	PROCESS_BASIC_INFORMATION32 ProcInfo;
	ULONG Len = 0;

	ZERO(&ProcInfo);

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcessEx(hProcess,
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

DECL_EXTERN_API(BOOLEAN, ProcessGetPeb64, CONST IN HANDLE hProcess, OUT PPEB64 pPeb)
{
	NTSTATUS Status;
#ifdef _WIN64
	PROCESS_BASIC_INFORMATION ProcInfo;
#else
	PROCESS_BASIC_INFORMATION64 ProcInfo;
#endif
	ULONG Len = 0;

	ZERO(&ProcInfo);

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcess64(hProcess,
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

	if (!HcProcessReadMemory64(hProcess,
		(PVOID64) ProcInfo.PebBaseAddress,
		pPeb,
		sizeof(*pPeb),
		NULL))
	{
		return FALSE;
	}

	return TRUE;
}

DECL_EXTERN_API(ULONG_PTR, ProcessGetExportAddressW, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, IN LPCWSTR lpExportSymbolName)
{
	ULONG_PTR Return = 0;
	LPSTR lpConverted;

	lpConverted = HcStringConvertWtoA(lpExportSymbolName);
	if (lpConverted)
	{
		Return = HcProcessGetExportAddress32A(hProcess, hModule, lpConverted);
		HcFree(lpConverted);
	}

	return Return;
}

DECL_EXTERN_API(ULONG_PTR, ProcessGetExportAddressA, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, IN LPCSTR lpExportSymbolName)
{
	ULONG_PTR Return = 0;
	PDWORD pExportNames = NULL;
	PDWORD pExportFunctions = NULL;
	PWORD pExportOrdinals = NULL;
	LPSTR lpName;
	IMAGE_EXPORT_DIRECTORY ExportDirectory;

	if (!hModule)
	{
		return Return;
	}

	if (!HcImageRemoteExportDirectoryFromModule(hProcess, hModule, &ExportDirectory))
	{
		return Return;
	}

	ULONG NumberOfFunctions = ExportDirectory.NumberOfFunctions;
	ULONG NumberOfNames = ExportDirectory.NumberOfNames;

	pExportNames = (PDWORD) HcAllocPage(NumberOfNames * sizeof(*pExportNames));
	if (!pExportNames)
	{
		goto done;
	}

	if (!HcProcessReadMemory(hProcess, (LPVOID) ((ULONG_PTR) hModule + ExportDirectory.AddressOfNames), pExportNames, NumberOfNames * sizeof(*pExportNames), NULL))
	{
		goto done;
	}

	pExportFunctions = (PDWORD) HcAllocPage(NumberOfFunctions * sizeof(*pExportFunctions));
	if (!pExportFunctions)
	{
		goto done;
	}

	if (!HcProcessReadMemory(hProcess, (LPVOID) ((ULONG_PTR) hModule + ExportDirectory.AddressOfFunctions), pExportFunctions, NumberOfFunctions * sizeof(*pExportFunctions), NULL))
	{
		goto done;
	}

	pExportOrdinals = (PWORD) HcAllocPage(NumberOfFunctions * sizeof(NumberOfNames));
	if (!pExportOrdinals)
	{
		goto done;
	}

	if (!HcProcessReadMemory(hProcess, (LPVOID) ((ULONG_PTR) hModule + ExportDirectory.AddressOfNameOrdinals), pExportOrdinals, NumberOfNames * sizeof(NumberOfNames), NULL))
	{
		goto done;
	}

	for (ULONG_PTR i = 0; i < ExportDirectory.NumberOfFunctions; i++)
	{
		lpName = (LPSTR) HcAlloc(1024); /* seems reasonable */
		if (lpName)
		{
			if (HcProcessReadMemory(hProcess, (LPVOID) ((ULONG_PTR)hModule + pExportNames[i]), lpName, 1024, NULL))
			{
				if (HcStringEqualA(lpName, lpExportSymbolName, TRUE))
				{
					Return = (ULONG_PTR) hModule + pExportFunctions[pExportOrdinals[i]];
				}
			}

			HcFree(lpName);

			if (Return)
			{
				goto done;
			}
		}
		else
		{
			goto done;
		}
	}

done:
	if (pExportNames)
	{
		HcFreePage(pExportNames);
	}

	if (pExportFunctions)
	{
		HcFreePage(pExportFunctions);
	}

	if (pExportOrdinals)
	{
		HcFreePage(pExportOrdinals);
	}

	return Return;
}


DECL_EXTERN_API(ULONG_PTR, ProcessGetExportAddress32W, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, IN LPCWSTR lpExportSymbolName)
{
	ULONG_PTR Return = 0;
	LPSTR lpConverted;

	lpConverted = HcStringConvertWtoA(lpExportSymbolName);
	if (lpConverted)
	{
		Return = HcProcessGetExportAddress32A(hProcess, hModule, lpConverted);
		HcFree(lpConverted);
	}

	return Return;
}

/* This is rather problematic to port to a 32 -> 64 version due to the limitations of ReadVirtualMemory.
*  In a scenario where one must use a 32bit environment to read a 64bit address using Wow64ReadVirtualMemory64 is the way to go.
*/
DECL_EXTERN_API(ULONG_PTR, ProcessGetExportAddress32A, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, IN LPCSTR lpExportSymbolName)
{
	ULONG_PTR Return = 0;
	PDWORD pExportNames = NULL;
	PDWORD pExportFunctions = NULL;
	PWORD pExportOrdinals = NULL;
	LPSTR lpName;
	IMAGE_EXPORT_DIRECTORY ExportDirectory;

	if (!hModule)
	{
		return Return;
	}

	if (!HcImageRemoteExportDirectoryFromModule32(hProcess, hModule, &ExportDirectory))
	{
		return Return;
	}

	ULONG NumberOfFunctions = ExportDirectory.NumberOfFunctions;
	ULONG NumberOfNames = ExportDirectory.NumberOfNames;

	pExportNames = (PDWORD) HcAllocPage(NumberOfNames * sizeof(*pExportNames));
	if (!pExportNames)
	{
		goto done;
	}

	if (!HcProcessReadMemory(hProcess, (LPVOID) ((ULONG_PTR) hModule + ExportDirectory.AddressOfNames), pExportNames, NumberOfNames * sizeof(*pExportNames), NULL))
	{
		goto done;
	}

	pExportFunctions = (PDWORD) HcAllocPage(NumberOfFunctions * sizeof(*pExportFunctions));
	if (!pExportFunctions)
	{
		goto done;
	}

	if (!HcProcessReadMemory(hProcess, (LPVOID) ((ULONG_PTR) hModule + ExportDirectory.AddressOfFunctions), pExportFunctions, NumberOfFunctions * sizeof(*pExportFunctions), NULL))
	{
		goto done;
	}

	pExportOrdinals = (PWORD) HcAllocPage(NumberOfFunctions * sizeof(NumberOfNames));
	if (!pExportOrdinals)
	{
		goto done;
	}

	if (!HcProcessReadMemory(hProcess, (LPVOID) ((ULONG_PTR) hModule + ExportDirectory.AddressOfNameOrdinals), pExportOrdinals, NumberOfNames * sizeof(NumberOfNames), NULL))
	{
		goto done;
	}

	for (ULONG_PTR i = 0; i < ExportDirectory.NumberOfFunctions; i++)
	{
		lpName = (LPSTR) HcAlloc(1024); /* seems reasonable */
		if (lpName)
		{
			if (HcProcessReadMemory(hProcess, (LPVOID) ((ULONG_PTR) hModule + pExportNames[i]), lpName, 1024, NULL))
			{
				if (HcStringEqualA(lpName, lpExportSymbolName, TRUE))
				{
					Return = (ULONG_PTR) hModule + pExportFunctions[pExportOrdinals[i]];
				}
			}

			HcFree(lpName);

			if (Return)
			{
				goto done;
			}
		}
		else
		{
			goto done;
		}
	}

done:
	if (pExportNames)
	{
		HcFreePage(pExportNames);
	}

	if (pExportFunctions)
	{
		HcFreePage(pExportFunctions);
	}

	if (pExportOrdinals)
	{
		HcFreePage(pExportOrdinals);
	}

	return Return;
}

DECL_EXTERN_API(ULONG64, ProcessGetExportAddress64W, CONST IN HANDLE hProcess, CONST IN ULONG64 hModule, IN LPCWSTR lpExportSymbolName)
{
	ULONG64 Return = 0;
	LPSTR lpConverted;

	lpConverted = HcStringConvertWtoA(lpExportSymbolName);
	if (lpConverted)
	{
		Return = HcProcessGetExportAddress64A(hProcess, hModule, lpConverted);
		HcFree(lpConverted);
	}

	return Return;
}

DECL_EXTERN_API(ULONG64, ProcessGetExportAddress64A, CONST IN HANDLE hProcess, CONST IN ULONG64 hModule, IN LPCSTR lpExportSymbolName)
{
	ULONG64 Return = 0;
	PDWORD pExportNames = NULL;
	PDWORD pExportFunctions = NULL;
	PWORD pExportOrdinals = NULL;
	IMAGE_EXPORT_DIRECTORY ExportDirectory;
	LPSTR lpName;

	if (!hModule)
	{
		return Return;
	}

	if (!HcImageRemoteExportDirectoryFromModule64(hProcess, hModule, &ExportDirectory))
	{
		return Return;
	}

	ULONG NumberOfFunctions = ExportDirectory.NumberOfFunctions;
	ULONG NumberOfNames = ExportDirectory.NumberOfNames;

	pExportNames = (PDWORD) HcAllocPage(NumberOfNames * sizeof(*pExportNames));
	if (!pExportNames)
	{
		goto done;
	}

	if (!HcProcessReadMemory64(hProcess,
		(PVOID64) ((ULONG64) hModule + ExportDirectory.AddressOfNames),
		pExportNames, 
		NumberOfNames * sizeof(*pExportNames),
		NULL))
	{
		goto done;
	}

	pExportFunctions = (PDWORD) HcAllocPage(NumberOfFunctions * sizeof(*pExportFunctions));
	if (!pExportFunctions)
	{
		goto done;
	}

	if (!HcProcessReadMemory64(hProcess,
		(PVOID64) ((ULONG64) hModule + ExportDirectory.AddressOfFunctions),
		pExportFunctions, 
		NumberOfFunctions * sizeof(*pExportFunctions),
		NULL))
	{
		goto done;
	}

	pExportOrdinals = (PWORD) HcAllocPage(NumberOfFunctions * sizeof(NumberOfNames));
	if (!pExportOrdinals)
	{
		goto done;
	}

	if (!HcProcessReadMemory64(hProcess,
		(PVOID64) ((ULONG64) hModule + ExportDirectory.AddressOfNameOrdinals),
		pExportOrdinals, 
		NumberOfNames * sizeof(NumberOfNames), 
		NULL))
	{
		goto done;
	}

	for (ULONG_PTR i = 0; i < ExportDirectory.NumberOfFunctions; i++)
	{
		lpName = (LPSTR) HcAlloc(1024); /* Since we have no idea what the size of the function name is,
										 * we dont know where to terminate. Meaning we don't know how to account for shorter/larger strings.
										 * Meaning Allocating/Dellocating is the way to go as it nullifies the entire size. HcInternalSet is fine too. */

		if (HcProcessReadMemory64(hProcess, (PVOID64) ((ULONG64) hModule + pExportNames[i]), lpName, 1024, NULL))
		{
			if (HcStringEqualA(lpName, lpExportSymbolName, TRUE))
			{
				Return = hModule + pExportFunctions[pExportOrdinals[i]];
			}
		}

		if (Return)
		{
			goto done;
		}

		if (lpName)
		{
			HcFree(lpName);
		}
	}

done:
	if (pExportNames)
	{
		HcFreePage(pExportNames);
	}

	if (pExportFunctions)
	{
		HcFreePage(pExportFunctions);
	}

	if (pExportOrdinals)
	{
		HcFreePage(pExportOrdinals);
	}

	return Return;
}

DECL_EXTERN_API(DWORD, ProcessGetCommandLineA, CONST IN HANDLE hProcess, OUT LPSTR* lpszCommandline, CONST IN BOOLEAN bAlloc)
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

DECL_EXTERN_API(DWORD, ProcessGetCommandLineW, CONST IN HANDLE hProcess, OUT LPWSTR* lpszCommandline, CONST IN BOOLEAN bAlloc)
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

DECL_EXTERN_API(DWORD, ProcessGetCurrentDirectoryW, CONST IN HANDLE hProcess, OUT LPWSTR lpszDirectory)
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
		lpszDirectory, 
		upp.CurrentDirectory.DosPath.Length))
	{
		return 0;
	}

	return dwReturnLength;
}

DECL_EXTERN_API(DWORD, ProcessGetCurrentDirectoryA, CONST IN HANDLE hProcess, OUT LPSTR szDirectory)
{
	LPWSTR lpCopy = HcStringAllocW(MAX_PATH);
	DWORD dwCount;

	if (szDirectory == NULL)
	{
		/* just give the count */
		return HcProcessGetCurrentDirectoryW(hProcess, NULL);
	}

	dwCount = HcProcessGetCurrentDirectoryW(hProcess, lpCopy);
	if (dwCount)
	{
		if (!HcStringCopyConvertWtoA(lpCopy, szDirectory, dwCount))
		{
			dwCount = 0;
		}
	}

	HcFree(lpCopy);
	return dwCount;
}

DECL_EXTERN_API(BOOLEAN, ProcessQueryWorkingSetEx, IN HANDLE hProcess, OUT PWORKING_SET_EX_DATA Data)
{
	NTSTATUS Status;
	BOOLEAN Result;

	Status = HcQueryVirtualMemoryEx(hProcess, NULL, MemoryWorkingSetExInformation, Data, sizeof(*Data), NULL);
	if (NT_SUCCESS(Status))
	{
		Result = TRUE;
	}
	else
	{
		Result = FALSE;
		HcErrorSetNtStatus(Status);
	}
	return Result;
}

NTSTATUS
NTAPI
RtlpMapFile(PUNICODE_STRING ImageFileName,
	ULONG Attributes,
	PHANDLE Section)
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS Status;
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK IoStatusBlock;

	/* Open the Image File */
	InitializeObjectAttributes(&ObjectAttributes,
		ImageFileName,
		Attributes & (OBJ_CASE_INSENSITIVE | OBJ_INHERIT),
		NULL,
		NULL);

	Status = HcOpenFile(&hFile,
		SYNCHRONIZE | FILE_EXECUTE | FILE_READ_DATA,
		&ObjectAttributes,
		&IoStatusBlock,
		FILE_SHARE_DELETE | FILE_SHARE_READ,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	/* Now create a section for this image */
	Status = HcCreateSection(Section,
		SECTION_ALL_ACCESS,
		NULL,
		NULL,
		PAGE_EXECUTE,
		SEC_IMAGE,
		hFile);

	if (!NT_SUCCESS(Status))
	{
	}

	HcClose(hFile);
	return Status;
}

#define FLG_ENABLE_CSRDEBUG                     0x00020000


NTSTATUS
NTAPI
RtlpInitEnvironment(HANDLE ProcessHandle,
	PPEB Peb,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters)
{
	NTSTATUS Status;
	PVOID BaseAddress = NULL;
	SIZE_T EnviroSize;
	SIZE_T Size;
	PWCHAR Environment = NULL;

	/* Give the caller 1MB if he requested it */
	if (ProcessParameters->Flags & RTL_USER_PROCESS_PARAMETERS_RESERVE_1MB)
	{
		/* Give 1MB starting at 0x4 */
		BaseAddress = (PVOID) 4;
		EnviroSize = (1024 * 1024) - 256;
		Status = HcAllocateVirtualMemory(ProcessHandle,
			&BaseAddress,
			0,
			&EnviroSize,
			MEM_RESERVE,
			PAGE_READWRITE);
		if (!NT_SUCCESS(Status))
		{
			return Status;
		}
	}

	/* Find the end of the Enviroment Block */
	if ((Environment = (PWCHAR) ProcessParameters->Environment))
	{
		while (*Environment++) while (*Environment++);

		/* Calculate the size of the block */
		EnviroSize = (ULONG) ((ULONG_PTR) Environment -
			(ULONG_PTR) ProcessParameters->Environment);

		/* Allocate and Initialize new Environment Block */
		Size = EnviroSize;
		Status = HcAllocateVirtualMemory(ProcessHandle,
			&BaseAddress,
			0,
			&Size,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE);
		if (!NT_SUCCESS(Status))
		{
			return Status;
		}

		/* Write the Environment Block */
		HcWriteVirtualMemory(ProcessHandle,
			BaseAddress,
			ProcessParameters->Environment,
			EnviroSize,
			NULL);

		/* Save pointer */
		ProcessParameters->Environment = BaseAddress;
	}

	/* Now allocate space for the Parameter Block */
	BaseAddress = NULL;
	Size = ProcessParameters->MaximumLength;
	Status = HcAllocateVirtualMemory(ProcessHandle,
		&BaseAddress,
		0,
		&Size,
		MEM_COMMIT,
		PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	/* Write the Parameter Block */
	Status = HcWriteVirtualMemory(ProcessHandle,
		BaseAddress,
		ProcessParameters,
		ProcessParameters->Length,
		NULL);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	/* Write pointer to Parameter Block */
	Status = HcWriteVirtualMemory(ProcessHandle,
		&Peb->ProcessParameters,
		&BaseAddress,
		sizeof(BaseAddress),
		NULL);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	/* Return */
	return STATUS_SUCCESS;
}

DECL_EXTERN_API(BOOLEAN, ProcessCreateNativeW, IN LPWSTR lpPath, IN LPWSTR lpCommandLine)
{
	PRTL_USER_PROCESS_PARAMETERS UserProcessParam;
	UNICODE_STRING FileName, CommandLine;
	RTL_USER_PROCESS_INFORMATION ProcessInfo;
	LPWSTR lpFullPath = HcStringAllocW(MAX_PATH);
	BOOLEAN bReturn = FALSE;

	if (!HcPathGetFullPathNameW(lpPath, lpFullPath))
	{
		goto done;
	}

	if (!HcDosPathNameToNtPathName_U(lpFullPath, &FileName, NULL, NULL))
	{
		goto done;
	}

	HcInitUnicodeString(&CommandLine, lpCommandLine);

	if (!NT_SUCCESS(RtlCreateProcessParameters(&UserProcessParam, &FileName, NULL, NULL, lpCommandLine != NULL ? &CommandLine : NULL, NULL, NULL, NULL, NULL, NULL)))
	{
		goto done;
	}

	if (!NT_SUCCESS(RtlCreateUserProcess(&FileName, OBJ_CASE_INSENSITIVE, UserProcessParam, NULL, NULL, NULL, FALSE, NULL, NULL, &ProcessInfo)))
	{
		RtlDestroyProcessParameters(UserProcessParam);
		goto done;
	}

	HcResumeThread(ProcessInfo.ThreadHandle, NULL);
	HcWaitForSingleObject(ProcessInfo.ProcessHandle, FALSE, NULL);
	RtlDestroyProcessParameters(UserProcessParam);
	HcClose(ProcessInfo.ThreadHandle);
	HcClose(ProcessInfo.ProcessHandle);
	
	bReturn = TRUE;

done:
	if (lpFullPath)
	{
		HcFree(lpFullPath);
	}

	return bReturn;
}


/*
* @implemented
*
* Creates a process and its initial thread.
*
* NOTES:
*  - The first thread is created suspended, so it needs a manual resume!!!
*  - If ParentProcess is NULL, current process is used
*  - ProcessParameters must be normalized
*  - Attributes are object attribute flags used when opening the ImageFileName.
*    Valid flags are OBJ_INHERIT and OBJ_CASE_INSENSITIVE.
*
* -Gunnar
*/
NTSTATUS
NTAPI
RtlCreateUserProcess(IN PUNICODE_STRING ImageFileName,
	IN ULONG Attributes,
	IN OUT PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	IN PSECURITY_DESCRIPTOR ProcessSecurityDescriptor OPTIONAL,
	IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
	IN HANDLE ParentProcess OPTIONAL,
	IN BOOLEAN InheritHandles,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	OUT PRTL_USER_PROCESS_INFORMATION ProcessInfo)
{
	NTSTATUS Status;
	HANDLE hSection;
	PROCESS_BASIC_INFORMATION ProcessBasicInfo;
	OBJECT_ATTRIBUTES ObjectAttributes;

	/* Map and Load the File */
	Status = RtlpMapFile(ImageFileName,
		Attributes,
		&hSection);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	/* Clean out the current directory handle if we won't use it */
	if (!InheritHandles) ProcessParameters->CurrentDirectory.Handle = NULL;

	/* Use us as parent if none other specified */
	if (!ParentProcess) ParentProcess = NtCurrentProcess();

	/* Initialize the Object Attributes */
	InitializeObjectAttributes(&ObjectAttributes,
		NULL,
		0,
		NULL,
		ProcessSecurityDescriptor);

	/* Create Kernel Process Object */
	Status = HcCreateProcess(&ProcessInfo->ProcessHandle,
		PROCESS_ALL_ACCESS,
		&ObjectAttributes,
		ParentProcess,
		InheritHandles,
		hSection,
		DebugPort,
		ExceptionPort);
	if (!NT_SUCCESS(Status))
	{
		HcClose(hSection);
		return Status;
	}

	/* Get some information on the image */
	Status = HcQuerySection(hSection,
		SectionImageInformation,
		&ProcessInfo->ImageInformation,
		sizeof(SECTION_IMAGE_INFORMATION),
		NULL);
	if (!NT_SUCCESS(Status))
	{
		HcClose(ProcessInfo->ProcessHandle);
		HcClose(hSection);
		return Status;
	}

	/* Get some information about the process */
	Status = HcQueryInformationProcess(ProcessInfo->ProcessHandle,
		ProcessBasicInformation,
		&ProcessBasicInfo,
		sizeof(ProcessBasicInfo),
		NULL);
	if (!NT_SUCCESS(Status))
	{
		HcClose(ProcessInfo->ProcessHandle);
		HcClose(hSection);
		return Status;
	}

	/* Duplicate the standard handles */
	Status = STATUS_SUCCESS;
	/*__try
	{
		if (ProcessParameters->StandardInput)
		{
			Status = ZwDuplicateObject(ParentProcess,
				ProcessParameters->StandardInput,
				ProcessInfo->ProcessHandle,
				&ProcessParameters->StandardInput,
				0,
				0,
				DUPLICATE_SAME_ACCESS |
				DUPLICATE_SAME_ATTRIBUTES);
			if (!NT_SUCCESS(Status))
			{
				_SEH2_LEAVE;
			}
		}

	if (ProcessParameters->StandardOutput)
	{
		Status = ZwDuplicateObject(ParentProcess,
			ProcessParameters->StandardOutput,
			ProcessInfo->ProcessHandle,
			&ProcessParameters->StandardOutput,
			0,
			0,
			DUPLICATE_SAME_ACCESS |
			DUPLICATE_SAME_ATTRIBUTES);
		if (!NT_SUCCESS(Status))
		{
			_SEH2_LEAVE;
		}
	}

	if (ProcessParameters->StandardError)
	{
		Status = ZwDuplicateObject(ParentProcess,
			ProcessParameters->StandardError,
			ProcessInfo->ProcessHandle,
			&ProcessParameters->StandardError,
			0,
			0,
			DUPLICATE_SAME_ACCESS |
			DUPLICATE_SAME_ATTRIBUTES);
		if (!NT_SUCCESS(Status))
		{
			_SEH2_LEAVE;
		}
	}
	}
		_SEH2_FINALLY
	{
		if (!NT_SUCCESS(Status))
		{
			ZwClose(ProcessInfo->ProcessHandle);
			ZwClose(hSection);
		}
	}
	_SEH2_END;*/

	if (!NT_SUCCESS(Status))
		return Status;

	/* Create Process Environment */
	Status = RtlpInitEnvironment(ProcessInfo->ProcessHandle,
		ProcessBasicInfo.PebBaseAddress,
		ProcessParameters);
	if (!NT_SUCCESS(Status))
	{
		HcClose(ProcessInfo->ProcessHandle);
		HcClose(hSection);
		return Status;
	}

	/* Create the first Thread */
	Status = RtlCreateUserThread(ProcessInfo->ProcessHandle,
		ThreadSecurityDescriptor,
		TRUE,
		ProcessInfo->ImageInformation.ZeroBits,
		ProcessInfo->ImageInformation.MaximumStackSize,
		ProcessInfo->ImageInformation.CommittedStackSize,
		(PTHREAD_START_ROUTINE) ProcessInfo->ImageInformation.TransferAddress,
		ProcessBasicInfo.PebBaseAddress,
		&ProcessInfo->ThreadHandle,
		&ProcessInfo->ClientId);
	if (!NT_SUCCESS(Status))
	{
		HcClose(ProcessInfo->ProcessHandle);
		HcClose(hSection); /* Don't try to optimize this on top! */
		return Status;
	}

	/* Close the Section Handle and return */
	HcClose(hSection);
	return STATUS_SUCCESS;
}

//NTSTATUS
//NTAPI
//HcExecuteImage(IN PUNICODE_STRING FileName,
//	IN PUNICODE_STRING Directory,
//	IN PUNICODE_STRING CommandLine,
//	IN ULONG MuSessionId,
//	IN ULONG Flags,
//	IN PRTL_USER_PROCESS_INFORMATION ProcessInformation)
//{
//	PRTL_USER_PROCESS_INFORMATION ProcessInfo;
//	NTSTATUS Status;
//	RTL_USER_PROCESS_INFORMATION LocalProcessInfo;
//	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
//
//	/* Use the input process information if we have it, otherwise use local */
//	ProcessInfo = ProcessInformation;
//	if (!ProcessInfo) ProcessInfo = &LocalProcessInfo;
//
//	/* Create parameters for the target process */
//	Status = RtlCreateProcessParameters(&ProcessParameters,
//		FileName,
//		SmpDefaultLibPath.Length ?
//		&SmpDefaultLibPath : NULL,
//		Directory,
//		CommandLine,
//		SmpDefaultEnvironment,
//		NULL,
//		NULL,
//		NULL,
//		0);
//
//	if (!NT_SUCCESS(Status))
//	{
//		return Status;
//	}
//
//	/* Set the size field as required */
//	ProcessInfo->Size = sizeof(RTL_USER_PROCESS_INFORMATION);
//
//	/* And always force NX for anything that SMSS launches */
//	ProcessParameters->Flags |= RTL_USER_PROCESS_PARAMETERS_NX;
//
//	/* Now create the process */
//	Status = RtlCreateUserProcess(FileName,
//		OBJ_CASE_INSENSITIVE,
//		ProcessParameters,
//		NULL,
//		NULL,
//		NULL,
//		FALSE,
//		NULL,
//		NULL,
//		ProcessInfo);
//
//	RtlDestroyProcessParameters(ProcessParameters);
//	if (!NT_SUCCESS(Status))
//	{
//		return Status;
//	}
//
//	/* Otherwise, get ready to start it, but make sure it's a native app */
//	if (ProcessInfo->ImageInformation.SubSystemType == IMAGE_SUBSYSTEM_NATIVE)
//	{
//		/* Resume it */
//		HcResumeThread(ProcessInfo->ThreadHandle, NULL);
//
//		/* Block on it unless Async was requested */
//		HcWaitForSingleObject(ProcessInfo->ThreadHandle, FALSE, NULL);
//
//		/* It's up and running now, close our handles */
//		HcClose(ProcessInfo->ThreadHandle);
//		HcClose(ProcessInfo->ProcessHandle);
//	}
//	else
//	{
//		/* This image is invalid, so kill it, close our handles, and fail */
//		Status = STATUS_INVALID_IMAGE_FORMAT;
//		HcTerminateProcess(ProcessInfo->ProcessHandle, Status);
//		HcWaitForSingleObject(ProcessInfo->ThreadHandle, 0, 0);
//		HcClose(ProcessInfo->ThreadHandle);
//		HcClose(ProcessInfo->ProcessHandle);
//	}
//
//	/* Return the outcome of the process create */
//	return Status;
//}

static __inline VOID
RtlpCopyParameterString(PWCHAR *Ptr,
	PUNICODE_STRING Destination,
	PUNICODE_STRING Source,
	USHORT Size)
{
	Destination->Length = Source->Length;
	Destination->MaximumLength = Size ? Size : Source->MaximumLength;
	Destination->Buffer = (PWCHAR) (*Ptr);
	if (Source->Length)
		HcInternalMove(Destination->Buffer, Source->Buffer, Source->Length);
	Destination->Buffer[Destination->Length / sizeof(WCHAR)] = 0;
	*Ptr += Destination->MaximumLength / sizeof(WCHAR);
}

#define NORMALIZE(x,addr)   {if(x) x=(PVOID)((ULONG_PTR)(x)+(ULONG_PTR)(addr));}
#define DENORMALIZE(x,addr) {if(x) x=(PVOID)((ULONG_PTR)(x)-(ULONG_PTR)(addr));}
#define ALIGN(x,align)      (((ULONG)(x)+(align)-1UL)&(~((align)-1UL)))

/*
* denormalize process parameters (Pointer-->Offset)
*
* @implemented
*/
PRTL_USER_PROCESS_PARAMETERS NTAPI RtlDeNormalizeProcessParams(PRTL_USER_PROCESS_PARAMETERS Params)
{
	if (Params && (Params->Flags & RTL_USER_PROCESS_PARAMETERS_NORMALIZED))
	{
		DENORMALIZE(Params->CurrentDirectory.DosPath.Buffer, Params);
		DENORMALIZE(Params->DllPath.Buffer, Params);
		DENORMALIZE(Params->ImagePathName.Buffer, Params);
		DENORMALIZE(Params->CommandLine.Buffer, Params);
		DENORMALIZE(Params->WindowTitle.Buffer, Params);
		DENORMALIZE(Params->DesktopInfo.Buffer, Params);
		DENORMALIZE(Params->ShellInfo.Buffer, Params);
		DENORMALIZE(Params->RuntimeData.Buffer, Params);

		Params->Flags &= ~RTL_USER_PROCESS_PARAMETERS_NORMALIZED;
	}

	return Params;
}

NTSTATUS
NTAPI
RtlDestroyProcessParameters(IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters)
{
	HcFree(ProcessParameters);
	return STATUS_SUCCESS;
}

/*
* @implemented
*/
NTSTATUS NTAPI RtlCreateProcessParameters(PRTL_USER_PROCESS_PARAMETERS *ProcessParameters,
	PUNICODE_STRING ImagePathName,
	PUNICODE_STRING DllPath,
	PUNICODE_STRING CurrentDirectory,
	PUNICODE_STRING CommandLine,
	PWSTR Environment,
	PUNICODE_STRING WindowTitle,
	PUNICODE_STRING DesktopInfo,
	PUNICODE_STRING ShellInfo,
	PUNICODE_STRING RuntimeData)
{
	PRTL_USER_PROCESS_PARAMETERS Param = NULL;
	ULONG Length = 0;
	PWCHAR Dest;
	UNICODE_STRING EmptyString;
	HANDLE CurrentDirectoryHandle;
	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;

	EmptyString.Length = 0;
	EmptyString.MaximumLength = sizeof(WCHAR);
	EmptyString.Buffer = L"";

	if (DllPath == NULL)
		DllPath = &NtCurrentPeb()->ProcessParameters->DllPath;

	if (Environment == NULL)
		Environment = NtCurrentPeb()->ProcessParameters->Environment;

	if (CurrentDirectory == NULL)
		CurrentDirectory = &NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath;

	CurrentDirectoryHandle = NtCurrentPeb()->ProcessParameters->CurrentDirectory.Handle;
	ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
	ConsoleFlags = NtCurrentPeb()->ProcessParameters->ConsoleFlags;

	if (CommandLine == NULL)
		CommandLine = &EmptyString;
	if (WindowTitle == NULL)
		WindowTitle = &EmptyString;
	if (DesktopInfo == NULL)
		DesktopInfo = &EmptyString;
	if (ShellInfo == NULL)
		ShellInfo = &EmptyString;
	if (RuntimeData == NULL)
		RuntimeData = &EmptyString;

	/* size of process parameter block */
	Length = sizeof(RTL_USER_PROCESS_PARAMETERS);

	/* size of current directory buffer */
	Length += (MAX_PATH * sizeof(WCHAR));

	/* add string lengths */
	Length += ALIGN(DllPath->MaximumLength, sizeof(ULONG));
	Length += ALIGN(ImagePathName->Length + sizeof(WCHAR), sizeof(ULONG));
	Length += ALIGN(CommandLine->Length + sizeof(WCHAR), sizeof(ULONG));
	Length += ALIGN(WindowTitle->MaximumLength, sizeof(ULONG));
	Length += ALIGN(DesktopInfo->MaximumLength, sizeof(ULONG));
	Length += ALIGN(ShellInfo->MaximumLength, sizeof(ULONG));
	Length += ALIGN(RuntimeData->MaximumLength, sizeof(ULONG));

	/* Calculate the required block size */
	Param = HcAlloc(Length);
	if (!Param)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	Param->MaximumLength = Length;
	Param->Length = Length;
	Param->Flags = RTL_USER_PROCESS_PARAMETERS_NORMALIZED;
	Param->Environment = Environment;
	Param->CurrentDirectory.Handle = CurrentDirectoryHandle;
	Param->ConsoleHandle = ConsoleHandle;
	Param->ConsoleFlags = ConsoleFlags;

	Dest = (PWCHAR) (((PBYTE) Param) + sizeof(RTL_USER_PROCESS_PARAMETERS));

	/* copy current directory */
	RtlpCopyParameterString(&Dest,
		&Param->CurrentDirectory.DosPath,
		CurrentDirectory,
		MAX_PATH * sizeof(WCHAR));

	/* make sure the current directory has a trailing backslash */
	if (Param->CurrentDirectory.DosPath.Length > 0)
	{
		Length = Param->CurrentDirectory.DosPath.Length / sizeof(WCHAR);
		if (Param->CurrentDirectory.DosPath.Buffer[Length - 1] != L'\\')
		{
			Param->CurrentDirectory.DosPath.Buffer[Length] = L'\\';
			Param->CurrentDirectory.DosPath.Buffer[Length + 1] = 0;
			Param->CurrentDirectory.DosPath.Length += sizeof(WCHAR);
		}
	}

	/* copy dll path */
	RtlpCopyParameterString(&Dest,
		&Param->DllPath,
		DllPath,
		0);

	/* copy image path name */
	RtlpCopyParameterString(&Dest,
		&Param->ImagePathName,
		ImagePathName,
		ImagePathName->Length + sizeof(WCHAR));

	/* copy command line */
	RtlpCopyParameterString(&Dest,
		&Param->CommandLine,
		CommandLine,
		CommandLine->Length + sizeof(WCHAR));

	/* copy title */
	RtlpCopyParameterString(&Dest,
		&Param->WindowTitle,
		WindowTitle,
		0);

	/* copy desktop */
	RtlpCopyParameterString(&Dest,
		&Param->DesktopInfo,
		DesktopInfo,
		0);

	/* copy shell info */
	RtlpCopyParameterString(&Dest,
		&Param->ShellInfo,
		ShellInfo,
		0);

	/* copy runtime info */
	RtlpCopyParameterString(&Dest,
		&Param->RuntimeData,
		RuntimeData,
		0);

	RtlDeNormalizeProcessParams(Param);
	*ProcessParameters = Param;

	return STATUS_SUCCESS;
}

#define AddToHandle(x,y)  (x) = (HANDLE)((ULONG_PTR)(x) | (y));
#define RemoveFromHandle(x,y)  (x) = (HANDLE)((ULONG_PTR)(x) & ~(y));

BOOLEAN
WINAPI
BasePushProcessParameters(IN ULONG ParameterFlags,
	IN HANDLE ProcessHandle,
	IN PPEB RemotePeb,
	IN LPCWSTR ApplicationPathName,
	IN LPWSTR lpCurrentDirectory,
	IN LPWSTR lpCommandLine,
	IN LPVOID lpEnvironment,
	IN LPSTARTUPINFOW StartupInfo,
	IN DWORD CreationFlags,
	IN BOOL InheritHandles,
	IN ULONG ImageSubsystem,
	IN PVOID AppCompatData,
	IN ULONG AppCompatDataSize)
{
	WCHAR FullPath[MAX_PATH + 5];
	PWCHAR ScanChar;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters, RemoteParameters;
	PVOID RemoteAppCompatData;
	UNICODE_STRING DllPath, ImageName, CommandLine, CurrentDirectory;
	UNICODE_STRING Desktop, Shell, Runtime, Title;
	NTSTATUS Status;
	ULONG EnviroSize;
	SIZE_T Size;
	BOOLEAN HavePebLock = FALSE, Result;
	PPEB Peb = NtCurrentPeb();

	HcInternalZero(&DllPath, sizeof(DllPath));
	HcInternalZero(&ImageName, sizeof(ImageName));
	HcInternalZero(&CommandLine, sizeof(CommandLine));
	HcInternalZero(&CurrentDirectory, sizeof(CurrentDirectory));

	/* Get the full path name */
	Size = HcPathGetFullPathNameW(ApplicationPathName,FullPath);

	if ((Size) && (Size <= (MAX_PATH + 4)))
	{
		/* Initialize Strings */
		HcInitUnicodeString(&ImageName, FullPath);
	}

	/* Initialize Strings */
	HcInitUnicodeString(&CommandLine, lpCommandLine);
	HcInitUnicodeString(&CurrentDirectory, lpCurrentDirectory);

	/* Initialize more Strings from the Startup Info */
	if (StartupInfo->lpDesktop)
	{
		HcInitUnicodeString(&Desktop, StartupInfo->lpDesktop);
	}
	else
	{
		HcInitUnicodeString(&Desktop, L"");
	}
	if (StartupInfo->lpReserved)
	{
		HcInitUnicodeString(&Shell, StartupInfo->lpReserved);
	}
	else
	{
		HcInitUnicodeString(&Shell, L"");
	}
	if (StartupInfo->lpTitle)
	{
		HcInitUnicodeString(&Title, StartupInfo->lpTitle);
	}
	else
	{
		HcInitUnicodeString(&Title, ApplicationPathName);
	}

	/* This one is special because the length can differ */
	Runtime.Buffer = (LPWSTR) StartupInfo->lpReserved2;
	Runtime.MaximumLength = Runtime.Length = StartupInfo->cbReserved2;

	/* Enforce no app compat data if the pointer was NULL */
	if (!AppCompatData) AppCompatDataSize = 0;

	/* Create the Parameter Block */
	ProcessParameters = NULL;

	Status = RtlCreateProcessParameters(&ProcessParameters,
		&ImageName,
		&DllPath,
		lpCurrentDirectory ?
		&CurrentDirectory : NULL,
		&CommandLine,
		lpEnvironment,
		&Title,
		&Desktop,
		&Shell,
		&Runtime);

	if (!NT_SUCCESS(Status)) goto FailPath;

	/* Clear the current directory handle if not inheriting */
	if (!InheritHandles) ProcessParameters->CurrentDirectory.Handle = NULL;

	/* Check if the user passed in an environment */
	if (lpEnvironment)
	{
		/* We should've made it part of the parameters block, enforce this */
		ASSERT(ProcessParameters->Environment == lpEnvironment);
		lpEnvironment = ProcessParameters->Environment;
	}
	else
	{
		/* The user did not, so use the one from the current PEB */
		HavePebLock = TRUE;
		lpEnvironment = Peb->ProcessParameters->Environment;
	}

	/* Save pointer and start lookup */
	ScanChar = lpEnvironment;
	if (lpEnvironment)
	{
		/* Find the environment size */
		while (*ScanChar++) while (*ScanChar++);
		EnviroSize = (ULONG) ((ULONG_PTR) ScanChar - (ULONG_PTR) lpEnvironment);

		/* Allocate and Initialize new Environment Block */
		Size = EnviroSize;
		ProcessParameters->Environment = NULL;
		Status = HcAllocateVirtualMemory(ProcessHandle,
			(PVOID*) &ProcessParameters->Environment,
			0,
			&Size,
			MEM_COMMIT,
			PAGE_READWRITE);
		if (!NT_SUCCESS(Status)) goto FailPath;

		/* Write the Environment Block */
		Status = HcWriteVirtualMemory(ProcessHandle,
			ProcessParameters->Environment,
			lpEnvironment,
			EnviroSize,
			NULL);

		/* No longer need the PEB lock anymore */
		if (HavePebLock)
		{
			/* Release it */
			HavePebLock = FALSE;
		}

		/* Check if the write failed */
		if (!NT_SUCCESS(Status)) goto FailPath;
	}

	/* Write new parameters */
	ProcessParameters->StartingX = StartupInfo->dwX;
	ProcessParameters->StartingY = StartupInfo->dwY;
	ProcessParameters->CountX = StartupInfo->dwXSize;
	ProcessParameters->CountY = StartupInfo->dwYSize;
	ProcessParameters->CountCharsX = StartupInfo->dwXCountChars;
	ProcessParameters->CountCharsY = StartupInfo->dwYCountChars;
	ProcessParameters->FillAttribute = StartupInfo->dwFillAttribute;
	ProcessParameters->WindowFlags = StartupInfo->dwFlags;
	ProcessParameters->ShowWindowFlags = StartupInfo->wShowWindow;

	/* Check if there's a .local file present */
	if (ParameterFlags & 1)
	{
		ProcessParameters->Flags |= RTL_USER_PROCESS_PARAMETERS_LOCAL_DLL_PATH;
	}

	/* Check if we failed to open the IFEO key */
	if (ParameterFlags & 2)
	{
		ProcessParameters->Flags |= RTL_USER_PROCESS_PARAMETERS_IMAGE_KEY_MISSING;
	}

	/* Allocate memory for the parameter block */
	Size = ProcessParameters->Length;
	RemoteParameters = NULL;
	Status = HcAllocateVirtualMemory(ProcessHandle,
		(PVOID*) &RemoteParameters,
		0,
		&Size,
		MEM_COMMIT,
		PAGE_READWRITE);

	if (!NT_SUCCESS(Status)) goto FailPath;

	/* Set the allocated size */
	ProcessParameters->MaximumLength = (ULONG) Size;

	/* Handle some Parameter Flags */
	ProcessParameters->Flags |= (CreationFlags & PROFILE_USER) ?
		RTL_USER_PROCESS_PARAMETERS_PROFILE_USER : 0;
	ProcessParameters->Flags |= (CreationFlags & PROFILE_KERNEL) ?
		RTL_USER_PROCESS_PARAMETERS_PROFILE_KERNEL : 0;
	ProcessParameters->Flags |= (CreationFlags & PROFILE_SERVER) ?
		RTL_USER_PROCESS_PARAMETERS_PROFILE_SERVER : 0;
	ProcessParameters->Flags |= (Peb->ProcessParameters->Flags &
		RTL_USER_PROCESS_PARAMETERS_DISABLE_HEAP_CHECKS);

	/* Write the Parameter Block */
	Status = HcWriteVirtualMemory(ProcessHandle,
		RemoteParameters,
		ProcessParameters,
		ProcessParameters->Length,
		NULL);
	if (!NT_SUCCESS(Status)) goto FailPath;

	/* Write the PEB Pointer */
	Status = HcWriteVirtualMemory(ProcessHandle,
		&RemotePeb->ProcessParameters,
		&RemoteParameters,
		sizeof(PVOID),
		NULL);

	if (!NT_SUCCESS(Status)) goto FailPath;

	/* Check if there's any app compat data to write */
	RemoteAppCompatData = NULL;
	if (AppCompatData)
	{
		/* Allocate some space for the application compatibility data */
		Size = AppCompatDataSize;
		Status = HcAllocateVirtualMemory(ProcessHandle,
			&RemoteAppCompatData,
			0,
			&Size,
			MEM_COMMIT,
			PAGE_READWRITE);
		if (!NT_SUCCESS(Status)) goto FailPath;

		/* Write the application compatibility data */
		Status = HcWriteVirtualMemory(ProcessHandle,
			RemoteAppCompatData,
			AppCompatData,
			AppCompatDataSize,
			NULL);
		if (!NT_SUCCESS(Status)) goto FailPath;
	}

	/* Write the PEB Pointer to the app compat data (might be NULL) */
	Status = HcWriteVirtualMemory(ProcessHandle,
		&RemotePeb->pShimData,
		&RemoteAppCompatData,
		sizeof(PVOID),
		NULL);
	if (!NT_SUCCESS(Status)) goto FailPath;

	/* Now write Peb->ImageSubSystem */
	if (ImageSubsystem)
	{
		HcWriteVirtualMemory(ProcessHandle,
			&RemotePeb->ImageSubsystem,
			&ImageSubsystem,
			sizeof(ImageSubsystem),
			NULL);
	}

	/* Success path */
	Result = TRUE;

Quickie:
	/* Cleanup */
	HcFree(DllPath.Buffer);
	if (ProcessParameters) RtlDestroyProcessParameters(ProcessParameters);
	return Result;
FailPath:
	HcErrorSetNtStatus(Status);
	Result = FALSE;
	goto Quickie;
}

/*
* @implemented
*/
BOOL
WINAPI
CreateProcessInternalW(IN HANDLE hUserToken,
	IN LPCWSTR lpApplicationName,
	IN LPWSTR lpCommandLine,
	IN LPSECURITY_ATTRIBUTES lpProcessAttributes,
	IN LPSECURITY_ATTRIBUTES lpThreadAttributes,
	IN BOOL bInheritHandles,
	IN DWORD dwCreationFlags,
	IN LPVOID lpEnvironment,
	IN LPCWSTR lpCurrentDirectory,
	IN LPSTARTUPINFOW lpStartupInfo,
	IN LPPROCESS_INFORMATION lpProcessInformation,
	OUT PHANDLE hNewToken)
{
	//
	// Core variables used for creating the initial process and thread
	//
	SECURITY_ATTRIBUTES LocalThreadAttributes, LocalProcessAttributes;
	OBJECT_ATTRIBUTES LocalObjectAttributes;
	POBJECT_ATTRIBUTES ObjectAttributes;
	SECTION_IMAGE_INFORMATION ImageInformation;
	IO_STATUS_BLOCK IoStatusBlock;
	CLIENT_ID ClientId;
	ULONG NoWindow, StackSize, ErrorCode, Flags;
	ULONG ParameterFlags, PrivilegeValue, HardErrorMode;
	BOOLEAN InJob, HavePrivilege;
	BOOLEAN QuerySection, SkipSaferAndAppCompat;
	CONTEXT Context;
	PVOID BaseAddress, PrivilegeState, RealTimePrivilegeState;
	HANDLE DebugHandle, TokenHandle, JobHandle, ThreadHandle;
	HANDLE FileHandle, SectionHandle, ProcessHandle;
	ULONG ResumeCount;
	NTSTATUS Status;
	PPEB Peb, RemotePeb;
	PROCESS_BASIC_INFORMATION ProcInfo;
	ULONG Len = 0;
	PTEB Teb;
	PROCESS_PRIORITY_CLASS PriorityClass;
	INITIAL_TEB InitialTeb;
	PVOID TibValue;
	STARTUPINFOW StartupInfo;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	UNICODE_STRING DebuggerString;
	BOOL Result;
	//
	// Variables used for command-line and argument parsing
	//
	WCHAR SaveChar;
	ULONG Length;
	PWCHAR QuotedCmdLine, CurrentDirectory;
	PWCHAR NullBuffer, NameBuffer, _SearchPath, DebuggerCmdLine;
	UNICODE_STRING PathName;
	BOOLEAN SearchRetry, QuotesNeeded, CmdLineIsAppName, HasQuotes;

#if _SXS_SUPPORT_ENABLED_
	PRTL_BUFFER ByteBuffer;
	PRTL_UNICODE_STRING_BUFFER ThisBuffer, Buffer, SxsStaticBuffers[5];
	PRTL_UNICODE_STRING_BUFFER* BufferHead, SxsStringBuffer;
	RTL_UNICODE_STRING_BUFFER SxsWin32ManifestPath, SxsNtManifestPath;
	RTL_UNICODE_STRING_BUFFER SxsWin32PolicyPath, SxsNtPolicyPath;
	RTL_UNICODE_STRING_BUFFER SxsWin32AssemblyDirectory;
	BASE_MSG_SXS_HANDLES MappedHandles, Handles, FileHandles;
	PVOID CapturedStrings[3];
	SXS_WIN32_NT_PATH_PAIR ExePathPair, ManifestPathPair, PolicyPathPair;
	SXS_OVERRIDE_MANIFEST OverrideManifest;
	UNICODE_STRING FreeString, SxsNtExePath;
	PWCHAR SxsConglomeratedBuffer, StaticBuffer;
	ULONG ConglomeratedBufferSizeBytes, StaticBufferSize, i;
#endif
	ULONG FusionFlags;

	//
	// Variables used for path conversion (and partially Fusion/SxS)
	//
	PWCHAR FilePart, PathBuffer, FreeBuffer;
	BOOLEAN TranslationStatus;
	RTL_RELATIVE_NAME_U SxsWin32RelativePath;
	UNICODE_STRING SxsWin32ExePath;

	//
	// Variables used by Application Compatibility (and partially Fusion/SxS)
	//
	PVOID AppCompatSxsData, AppCompatData;
	ULONG AppCompatSxsDataSize, AppCompatDataSize;
	//
	// Variables used by VDM (Virtual Dos Machine) and WOW32 (16-bit Support)
	//
	ULONG VdmBinaryType, VdmTask, VdmReserve;
	ULONG VdmUndoLevel;
	BOOLEAN UseVdmReserve;
	HANDLE VdmWaitObject;
	ANSI_STRING VdmAnsiEnv;
	UNICODE_STRING VdmString, VdmUnicodeEnv;
	BOOLEAN IsWowApp;

	ZERO(&ProcInfo);

	/* Zero out the initial core variables and handles */
	QuerySection = FALSE;
	InJob = FALSE;
	SkipSaferAndAppCompat = FALSE;
	ParameterFlags = 0;
	Flags = 0;
	DebugHandle = NULL;
	JobHandle = NULL;
	TokenHandle = NULL;
	FileHandle = NULL;
	SectionHandle = NULL;
	ProcessHandle = NULL;
	ThreadHandle = NULL;
	BaseAddress = (PVOID) 1;

	/* Zero out initial SxS and Application Compatibility state */
	AppCompatData = NULL;
	AppCompatDataSize = 0;
	AppCompatSxsData = NULL;
	AppCompatSxsDataSize = 0;
#if _SXS_SUPPORT_ENABLED_
	SxsConglomeratedBuffer = NULL;
#endif
	FusionFlags = 0;

	/* Zero out initial parsing variables -- others are initialized later */
	DebuggerCmdLine = NULL;
	PathBuffer = NULL;
	_SearchPath = NULL;
	NullBuffer = 0;
	FreeBuffer = NULL;
	NameBuffer = NULL;
	CurrentDirectory = NULL;
	FilePart = NULL;
	DebuggerString.Buffer = NULL;
	HasQuotes = FALSE;
	QuotedCmdLine = NULL;

	/* Zero out initial VDM state */
	VdmAnsiEnv.Buffer = NULL;
	VdmUnicodeEnv.Buffer = NULL;
	VdmString.Buffer = NULL;
	VdmTask = 0;
	VdmUndoLevel = 0;
	VdmBinaryType = 0;
	VdmReserve = 0;
	VdmWaitObject = NULL;
	UseVdmReserve = FALSE;
	IsWowApp = FALSE;

	/* Clear the more complex structures by zeroing out their entire memory */
	HcInternalZero(&Context, sizeof(Context));
#if _SXS_SUPPORT_ENABLED_
	HcInternalZero(&FileHandles, sizeof(FileHandles));
	HcInternalZero(&MappedHandles, sizeof(MappedHandles));
	HcInternalZero(&Handles, sizeof(Handles));
#endif
	HcInternalZero(&RemotePeb, sizeof(RemotePeb));
	HcInternalZero(&LocalProcessAttributes, sizeof(LocalProcessAttributes));
	HcInternalZero(&LocalThreadAttributes, sizeof(LocalThreadAttributes));

	/* Zero out output arguments as well */
	HcInternalZero(lpProcessInformation, sizeof(*lpProcessInformation));
	if (hNewToken) *hNewToken = NULL;

	/* Capture the special window flag */
	NoWindow = dwCreationFlags & CREATE_NO_WINDOW;
	dwCreationFlags &= ~CREATE_NO_WINDOW;

#if _SXS_SUPPORT_ENABLED_
	/* Setup the SxS static string arrays and buffers */
	SxsStaticBuffers[0] = &SxsWin32ManifestPath;
	SxsStaticBuffers[1] = &SxsWin32PolicyPath;
	SxsStaticBuffers[2] = &SxsWin32AssemblyDirectory;
	SxsStaticBuffers[3] = &SxsNtManifestPath;
	SxsStaticBuffers[4] = &SxsNtPolicyPath;
	ExePathPair.Win32 = &SxsWin32ExePath;
	ExePathPair.Nt = &SxsNtExePath;
	ManifestPathPair.Win32 = &SxsWin32ManifestPath.String;
	ManifestPathPair.Nt = &SxsNtManifestPath.String;
	PolicyPathPair.Win32 = &SxsWin32PolicyPath.String;
	PolicyPathPair.Nt = &SxsNtPolicyPath.String;
#endif

	/* Finally, set our TEB and PEB */
	Teb = NtCurrentTeb();
	Peb = NtCurrentPeb();

	/* This combination is illegal (see MSDN) */
	if ((dwCreationFlags & (DETACHED_PROCESS | CREATE_NEW_CONSOLE)) ==
		(DETACHED_PROCESS | CREATE_NEW_CONSOLE))
	{
		HcErrorSetDosError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	/* Convert the priority class */
	if (dwCreationFlags & IDLE_PRIORITY_CLASS)
	{
		PriorityClass.PriorityClass = PROCESS_PRIORITY_CLASS_IDLE;
	}
	else if (dwCreationFlags & BELOW_NORMAL_PRIORITY_CLASS)
	{
		PriorityClass.PriorityClass = PROCESS_PRIORITY_CLASS_BELOW_NORMAL;
	}
	else if (dwCreationFlags & NORMAL_PRIORITY_CLASS)
	{
		PriorityClass.PriorityClass = PROCESS_PRIORITY_CLASS_NORMAL;
	}
	else if (dwCreationFlags & ABOVE_NORMAL_PRIORITY_CLASS)
	{
		PriorityClass.PriorityClass = PROCESS_PRIORITY_CLASS_ABOVE_NORMAL;
	}
	else if (dwCreationFlags & HIGH_PRIORITY_CLASS)
	{
		PriorityClass.PriorityClass = PROCESS_PRIORITY_CLASS_HIGH;
	}
	else
	{
		PriorityClass.PriorityClass = PROCESS_PRIORITY_CLASS_INVALID;
	}

	/* Done with the priority masks, so get rid of them */
	PriorityClass.Foreground = FALSE;
	dwCreationFlags &= ~(NORMAL_PRIORITY_CLASS |
		IDLE_PRIORITY_CLASS |
		HIGH_PRIORITY_CLASS |
		REALTIME_PRIORITY_CLASS |
		BELOW_NORMAL_PRIORITY_CLASS |
		ABOVE_NORMAL_PRIORITY_CLASS);

	/* You cannot request both a shared and a separate WoW VDM */
	if ((dwCreationFlags & CREATE_SEPARATE_WOW_VDM) &&
		(dwCreationFlags & CREATE_SHARED_WOW_VDM))
	{
		/* Fail such nonsensical attempts */
		HcErrorSetDosError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	///* Convert the environment */
	//if ((lpEnvironment) && !(dwCreationFlags & CREATE_UNICODE_ENVIRONMENT))
	//{
	//	/* Scan the environment to calculate its Unicode size */
	//	AnsiEnv.Buffer = pcScan = (PCHAR) lpEnvironment;
	//	while ((*pcScan) || (*(pcScan + 1))) ++pcScan;

	//	/* Create our ANSI String */
	//	AnsiEnv.Length = pcScan - (PCHAR) lpEnvironment + sizeof(ANSI_NULL);
	//	AnsiEnv.MaximumLength = AnsiEnv.Length + sizeof(ANSI_NULL);

	//	/* Allocate memory for the Unicode Environment */
	//	UnicodeEnv.Buffer = NULL;
	//	RegionSize = AnsiEnv.MaximumLength * sizeof(WCHAR);
	//	Status = NtAllocateVirtualMemory(NtCurrentProcess(),
	//		(PVOID) &UnicodeEnv.Buffer,
	//		0,
	//		&RegionSize,
	//		MEM_COMMIT,
	//		PAGE_READWRITE);
	//	if (!NT_SUCCESS(Status))
	//	{
	//		/* Fail */
	//		HcErrorSetNtStatus(Status);
	//		return FALSE;
	//	}

	//	/* Use the allocated size and convert */
	//	UnicodeEnv.MaximumLength = (USHORT) RegionSize;
	//	Status = RtlAnsiStringToUnicodeString(&UnicodeEnv, &AnsiEnv, FALSE);
	//	if (!NT_SUCCESS(Status))
	//	{
	//		/* Fail */
	//		NtFreeVirtualMemory(NtCurrentProcess(),
	//			(PVOID) &UnicodeEnv.Buffer,
	//			&RegionSize,
	//			MEM_RELEASE);
	//		HcErrorSetNtStatus(Status);
	//		return FALSE;
	//	}

	//	/* Now set the Unicode environment as the environment string pointer */
	//	lpEnvironment = UnicodeEnv.Buffer;
	//}

	/* Make a copy of the caller's startup info since we'll modify it */
	StartupInfo = *lpStartupInfo;

	/* New iteration -- free any existing name buffer */
	if (NameBuffer)
	{
		HcFree(NameBuffer);
		NameBuffer = NULL;
	}

	/* New iteration -- free any existing free buffer */
	if (FreeBuffer)
	{
		HcFree(FreeBuffer);
		FreeBuffer = NULL;
	}

	/* New iteration -- close any existing file handle */
	if (FileHandle)
	{
		HcClose(FileHandle);
		FileHandle = NULL;
	}

	/* Set the initial parsing state. This code can loop -- don't move this! */
	ErrorCode = 0;
	SearchRetry = TRUE;
	QuotesNeeded = FALSE;
	CmdLineIsAppName = FALSE;

	/* Convert the application name to its NT path */
	TranslationStatus = HcDosPathNameToNtPathName_U(lpApplicationName,
		&PathName,
		NULL,
		&SxsWin32RelativePath);

	if (!TranslationStatus)
	{
		/* Path must be invalid somehow, bail out */
		HcErrorSetDosError(ERROR_PATH_NOT_FOUND);
		Result = FALSE;
		goto Quickie;
	}

	/* Setup the buffer that needs to be freed at the end */
	ASSERT(FreeBuffer == NULL);
	FreeBuffer = PathName.Buffer;

	/* Check what kind of path the application is, for SxS (Fusion) purposes */
	HcInitUnicodeString(&SxsWin32ExePath, lpApplicationName);

	if (SxsWin32RelativePath.RelativeName.Length)
	{
		/* If it's relative, capture the relative name */
		PathName = SxsWin32RelativePath.RelativeName;
	}
	else
	{
		/* Otherwise, it's absolute, make sure no relative dir is used */
		SxsWin32RelativePath.ContainingDirectory = NULL;
	}

	/* Now use the path name, and the root path, to try opening the app */
	InitializeObjectAttributes(&LocalObjectAttributes,
		&PathName,
		OBJ_CASE_INSENSITIVE,
		SxsWin32RelativePath.ContainingDirectory,
		NULL);

	Status = HcOpenFile(&FileHandle,
		SYNCHRONIZE |
		FILE_READ_ATTRIBUTES |
		FILE_READ_DATA |
		FILE_EXECUTE,
		&LocalObjectAttributes,
		&IoStatusBlock,
		FILE_SHARE_READ | FILE_SHARE_DELETE,
		FILE_SYNCHRONOUS_IO_NONALERT |
		FILE_NON_DIRECTORY_FILE);

	if (!NT_SUCCESS(Status))
	{
		/* Try to open the app just for execute purposes instead */
		Status = HcOpenFile(&FileHandle,
			SYNCHRONIZE | FILE_EXECUTE,
			&LocalObjectAttributes,
			&IoStatusBlock,
			FILE_SHARE_READ | FILE_SHARE_DELETE,
			FILE_SYNCHRONOUS_IO_NONALERT |
			FILE_NON_DIRECTORY_FILE);
	}


	/* Did the caller specify a desktop? */
	if (!StartupInfo.lpDesktop)
	{
		/* Use the one from the current process */
		StartupInfo.lpDesktop = Peb->ProcessParameters->DesktopInfo.Buffer;
	}

	/* Create a section for this file */
	Status = HcCreateSection(&SectionHandle,
		SECTION_ALL_ACCESS,
		NULL,
		NULL,
		PAGE_EXECUTE,
		SEC_IMAGE,
		FileHandle);

	/* The last step is to figure out why the section object was not created */
	switch (Status)
	{
		case STATUS_FILE_IS_OFFLINE:
		{
			/* Set the correct last error for this */
			HcErrorSetDosError(ERROR_FILE_OFFLINE);
			break;
		}

		default:
		{
			/* Any other error, convert it to a generic Win32 error */
			if (!NT_SUCCESS(Status))
			{
				HcErrorSetDosError(ERROR_BAD_EXE_FORMAT);
				Result = FALSE;
				goto Quickie;
			}

			/* Otherwise, this must be success */
			ASSERT(Status == STATUS_SUCCESS);
			break;
		}
	}

	/* Is this not a WOW application, but a WOW32 VDM was requested for it? */
	if (!(IsWowApp) && (dwCreationFlags & CREATE_SEPARATE_WOW_VDM))
	{
		/* Ignore the nonsensical request */
		dwCreationFlags &= ~CREATE_SEPARATE_WOW_VDM;
	}

	/* Did we already check information for the section? */
	if (!QuerySection)
	{
		/* Get some information about the executable */
		Status = HcQuerySection(SectionHandle,
			SectionImageInformation,
			&ImageInformation,
			sizeof(ImageInformation),
			NULL);
		if (!NT_SUCCESS(Status))
		{
			/* We failed, bail out */
			HcErrorSetNtStatus(Status);
			Result = FALSE;
			goto Quickie;
		}

		/* Don't check this later */
		QuerySection = TRUE;
	}

	/* Check if this was linked as a DLL */
	if (ImageInformation.ImageCharacteristics & IMAGE_FILE_DLL)
	{
		/* These aren't valid images to try to execute! */
		HcErrorSetDosError(ERROR_BAD_EXE_FORMAT);
		Result = FALSE;
		goto Quickie;
	}

	/* Clear the IFEO-missing flag, before we know for sure... */
	ParameterFlags &= ~2;

	/* Initialize the process object attributes */
	ObjectAttributes = HcUtilFormatObjectAttributes(&LocalObjectAttributes,
		lpProcessAttributes,
		NULL);

	if ((hUserToken) && (lpProcessAttributes))
	{
		/* Augment them with information from the user */

		LocalProcessAttributes = *lpProcessAttributes;
		LocalProcessAttributes.lpSecurityDescriptor = NULL;
		ObjectAttributes = HcUtilFormatObjectAttributes(&LocalObjectAttributes,
			&LocalProcessAttributes,
			NULL);
	}

	/* Set inherit flag */
	if (bInheritHandles) Flags |= PROCESS_CREATE_FLAGS_INHERIT_HANDLES;

	/* Check if the process should be created with large pages */
	HavePrivilege = FALSE;
	PrivilegeState = NULL;
	if (Flags & PROCESS_CREATE_FLAGS_LARGE_PAGES)
	{
		/* Acquire the required privilege so that the kernel won't fail the call */
		PrivilegeValue = SE_LOCK_MEMORY_PRIVILEGE;
		//Status = RtlAcquirePrivilege(&PrivilegeValue, 1, 0, &PrivilegeState);
		//if (NT_SUCCESS(Status))
		//{
		//	/* Remember to release it later */
		//	HavePrivilege = TRUE;
		//}
	}

	/* Save the current TIB value since kernel overwrites it to store PEB */
	TibValue = Teb->NtTib.ArbitraryUserPointer;

	/* Tell the kernel to create the process */
	Status = HcCreateProcessEx(&ProcessHandle,
		PROCESS_ALL_ACCESS,
		ObjectAttributes,
		NtCurrentProcess(),
		Flags,
		SectionHandle,
		DebugHandle,
		NULL,
		InJob);

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcessEx(ProcessHandle,
		ProcessBasicInformation,
		&ProcInfo,
		sizeof(ProcInfo),
		&Len);

	if (!NT_SUCCESS(Status))
	{
	}

	if (ProcInfo.PebBaseAddress == NULL)
	{
	}
	else
	{
		RemotePeb = (PPEB) ProcInfo.PebBaseAddress;
	}

	/* And restore the old TIB value */
	Teb->NtTib.ArbitraryUserPointer = TibValue;

	///* Release the large page privilege if we had acquired it */
	//if (HavePrivilege) RtlReleasePrivilege(PrivilegeState);

	/* And now check if the kernel failed to create the process */
	if (!NT_SUCCESS(Status))
	{
		/* Go to failure path */
		HcErrorSetNtStatus(Status);
		Result = FALSE;
		goto Quickie;
	}

	/* Check if there is a priority class to set */
	if (PriorityClass.PriorityClass)
	{
		/* Reset current privilege state */
		RealTimePrivilegeState = NULL;

		/* Set the new priority class and release the privilege */
		Status = HcSetInformationProcess(ProcessHandle,
			ProcessPriorityClass,
			&PriorityClass,
			sizeof(PROCESS_PRIORITY_CLASS));

		/* Check if we failed to set the priority class */
		if (!NT_SUCCESS(Status))
		{
			HcErrorSetNtStatus(Status);
			Result = FALSE;
			goto Quickie;
		}
	}

	/* Check if the caller wants the default error mode */
	if (dwCreationFlags & CREATE_DEFAULT_ERROR_MODE)
	{
		/* Set Error Mode to only fail on critical errors */
		HardErrorMode = SEM_FAILCRITICALERRORS;
		HcSetInformationProcess(ProcessHandle,
			ProcessDefaultHardErrorMode,
			&HardErrorMode,
			sizeof(ULONG));
	}

	/* Check if we've already queried information on the section */
	if (!QuerySection)
	{
		/* We haven't, so get some information about the executable */
		Status = HcQuerySection(SectionHandle,
			SectionImageInformation,
			&ImageInformation,
			sizeof(ImageInformation),
			NULL);
		if (!NT_SUCCESS(Status))
		{
			/* Bail out on failure */
			HcErrorSetNtStatus(Status);
			Result = FALSE;
			goto Quickie;
		}

		/* If we encounter a restart, don't re-query this information again */
		QuerySection = TRUE;
	}

	/* Check if we have a current directory */
	if (lpCurrentDirectory)
	{
		/* Allocate a buffer so we can keep a Unicode copy */
		CurrentDirectory = HcAlloc((MAX_PATH * sizeof(WCHAR)) +
			sizeof(UNICODE_NULL));
		if (!CurrentDirectory)
		{
			/* Bail out if this failed */
			HcErrorSetNtStatus(STATUS_NO_MEMORY);
			Result = FALSE;
			goto Quickie;
		}

		/* Get the length in Unicode */
		Length = HcPathGetFullPathNameW(lpCurrentDirectory, CurrentDirectory);

		if (Length > MAX_PATH)
		{
			/* The directory is too long, so bail out */
			HcErrorSetDosError(ERROR_DIRECTORY);
			Result = FALSE;
			goto Quickie;
		}
	}

	/* Insert quotes if needed */
	if ((QuotesNeeded) || (CmdLineIsAppName))
	{
		/* Allocate our buffer, plus enough space for quotes and a NULL */
		QuotedCmdLine = HcAlloc((HcStringLenW(lpCommandLine) * sizeof(WCHAR)) +
			(2 * sizeof(L'\"') + sizeof(UNICODE_NULL)));
		if (QuotedCmdLine)
		{
			/* Copy the first quote */
			HcStringCopyExW(QuotedCmdLine, L"\"");

			/* Save the current null-character */
			if (QuotesNeeded)
			{
				SaveChar = *NullBuffer;
				*NullBuffer = UNICODE_NULL;
			}

			/* Copy the command line and the final quote */
			HcStringAppendExW(QuotedCmdLine, lpCommandLine);
			HcStringAppendExW(QuotedCmdLine, L"\"");

			/* Copy the null-char back */
			if (QuotesNeeded)
			{
				*NullBuffer = SaveChar;
				HcStringAppendExW(QuotedCmdLine, NullBuffer);
			}
		}
		else
		{
			/* We can't put quotes around the thing, so try it anyway */
			if (QuotesNeeded) QuotesNeeded = FALSE;
			if (CmdLineIsAppName) CmdLineIsAppName = FALSE;
		}
	}

	/* Set the new command-line if needed */
	if ((QuotesNeeded) || (CmdLineIsAppName)) lpCommandLine = QuotedCmdLine;

	/* Call the helper function in charge of RTL_USER_PROCESS_PARAMETERS */
	Result = BasePushProcessParameters(ParameterFlags,
		ProcessHandle,
		RemotePeb,
		lpApplicationName,
		CurrentDirectory,
		lpCommandLine,
		lpEnvironment,
		&StartupInfo,
		dwCreationFlags | NoWindow,
		bInheritHandles,
		IsWowApp ? IMAGE_SUBSYSTEM_WINDOWS_GUI : 0,
		AppCompatData,
		AppCompatDataSize);

	if (!Result)
	{
		/* The remote process would have an undefined state, so fail the call */
		goto Quickie;
	}

	/* Non-VDM console applications usually inherit handles unless specified */
	if (!(VdmBinaryType) &&
		!(bInheritHandles) &&
		!(StartupInfo.dwFlags & STARTF_USESTDHANDLES) &&
		!(dwCreationFlags & (CREATE_NO_WINDOW |
			CREATE_NEW_CONSOLE |
			DETACHED_PROCESS)) &&
			(ImageInformation.SubSystemType == IMAGE_SUBSYSTEM_WINDOWS_CUI))
	{
		/* Get the remote parameters */
		Status = HcReadVirtualMemory(ProcessHandle,
			&RemotePeb->ProcessParameters,
			&ProcessParameters,
			sizeof(PRTL_USER_PROCESS_PARAMETERS),
			NULL);
	}

	/* Create the Thread's Stack */
	StackSize = max(256 * 1024, ImageInformation.MaximumStackSize);
	Status = BaseCreateStack(ProcessHandle,
		ImageInformation.CommittedStackSize,
		StackSize,
		&InitialTeb);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		Result = FALSE;
		goto Quickie;
	}

	/* Create the Thread's Context */
	BaseInitializeContext(&Context,
		Peb,
		ImageInformation.TransferAddress,
		InitialTeb.StackBase,
		0);

	/* Convert the thread attributes */
	ObjectAttributes = HcUtilFormatObjectAttributes(&LocalObjectAttributes,
		lpThreadAttributes,
		NULL);
	if ((hUserToken) && (lpThreadAttributes))
	{
		/* If the caller specified a user token, zero the security descriptor */
		LocalThreadAttributes = *lpThreadAttributes;
		LocalThreadAttributes.lpSecurityDescriptor = NULL;
		ObjectAttributes = HcUtilFormatObjectAttributes(&LocalObjectAttributes,
			&LocalThreadAttributes,
			NULL);
	}

	/* Create the Kernel Thread Object */
	Status = HcCreateThread(&ThreadHandle,
		THREAD_ALL_ACCESS,
		ObjectAttributes,
		ProcessHandle,
		&ClientId,
		&Context,
		&InitialTeb,
		TRUE);

	if (!NT_SUCCESS(Status))
	{
		/* A process is not allowed to exist without a main thread, so fail */
		HcErrorSetNtStatus(Status);
		Result = FALSE;
		goto Quickie;
	}

	RemotePeb = NULL;

	/* Finally, resume the thread to actually get the process started */
	if (!(dwCreationFlags & CREATE_SUSPENDED))
	{
		HcResumeThread(ThreadHandle, &ResumeCount);
	}

	/* We made it this far, meaning we have a fully created process and thread */
	Result = TRUE;

	/* This is a regular process, so return the real process handle */
	lpProcessInformation->hProcess = ProcessHandle;

	/* Return the rest of the process information based on what we have so far */
	lpProcessInformation->hThread = ThreadHandle;
	lpProcessInformation->dwProcessId = HandleToUlong(ClientId.UniqueProcess);
	lpProcessInformation->dwThreadId = HandleToUlong(ClientId.UniqueThread);

	/* NULL these out here so we know to treat this as a success scenario */
	ProcessHandle = NULL;
	ThreadHandle = NULL;

Quickie:
	/* Free the debugger command line if one was allocated */
	if (DebuggerCmdLine) HcFree(DebuggerCmdLine);

	///* Check if an SxS full path as queried */
	//if (PathBuffer)
	//{
	//	/* Reinitialize the executable path */
	//	HcInitEmptyUnicodeString(&SxsWin32ExePath, NULL, 0);
	//	SxsWin32ExePath.Length = 0;

	//	/* Free the path buffer */
	//	RtlFreeHeap(RtlGetProcessHeap(), 0, PathBuffer);
	//}

#if _SXS_SUPPORT_ENABLED_
	/* Check if this was a non-VDM process */
	if (!VdmBinaryType)
	{
		/* Then it must've had SxS data, so close the handles used for it */
		BasepSxsCloseHandles(&Handles);
		BasepSxsCloseHandles(&FileHandles);

		/* Check if we built SxS byte buffers for this create process request */
		if (SxsConglomeratedBuffer)
		{
			/* Loop all of them */
			for (i = 0; i < 5; i++)
			{
				/* Check if this one was allocated */
				ThisBuffer = SxsStaticBuffers[i];
				if (ThisBuffer)
				{
					/* Get the underlying RTL_BUFFER structure */
					ByteBuffer = &ThisBuffer->ByteBuffer;
					if ((ThisBuffer != (PVOID) -8) && (ByteBuffer->Buffer))
					{
						/* Check if it was dynamic */
						if (ByteBuffer->Buffer != ByteBuffer->StaticBuffer)
						{
							/* Free it from the heap */
							FreeString.Buffer = (PWCHAR) ByteBuffer->Buffer;
							HcFreeUnicodeString(&FreeString);
						}

						/* Reset the buffer to its static data */
						ByteBuffer->Buffer = ByteBuffer->StaticBuffer;
						ByteBuffer->Size = ByteBuffer->StaticSize;
					}

					/* Reset the string to the static buffer */
					RtlInitEmptyUnicodeString(&ThisBuffer->String,
						(PWCHAR) ByteBuffer->StaticBuffer,
						ByteBuffer->StaticSize);
					if (ThisBuffer->String.Buffer)
					{
						/* Also NULL-terminate it */
						*ThisBuffer->String.Buffer = UNICODE_NULL;
					}
				}
			}
		}
	}
#endif

	/* Unconditionally free all the name parsing buffers we always allocate */
	HcFree(QuotedCmdLine);
	HcFree(NameBuffer);
	HcFree(CurrentDirectory);
	HcFree(FreeBuffer);

	/* Close open file/section handles */
	if (FileHandle) HcClose(FileHandle);
	if (SectionHandle) HcClose(SectionHandle);

	/* If we have a thread handle, this was a failure path */
	if (ThreadHandle)
	{
		/* So kill the process and close the thread handle */
		HcTerminateProcess(ProcessHandle, 0);
		HcClose(ThreadHandle);
	}

	/* If we have a process handle, this was a failure path, so close it */
	if (ProcessHandle) HcClose(ProcessHandle);

	/* Thread/process handles, if any, are now processed. Now close this one. */
	if (JobHandle) HcClose(JobHandle);

	/* Check if we had created a token */
	if (TokenHandle)
	{
		/* And if the user asked for one */
		if (hUserToken)
		{
			/* Then return it */
			*hNewToken = TokenHandle;
		}
		else
		{
			/* User didn't want it, so we used it temporarily -- close it */
			HcClose(TokenHandle);
		}
	}

	/* Check if we ended up here with an allocated search path, and free it */
	if (_SearchPath) HcFree(_SearchPath);

	/* Finally, return the API's result */
	return Result;
}

/*
* Creates the Initial Context for a Thread or Fiber
*/
VOID
WINAPI
BaseInitializeContext(IN PCONTEXT Context,
	IN PVOID Parameter,
	IN PVOID StartAddress,
	IN PVOID StackAddress,
	IN ULONG ContextType)
{
#ifdef _M_IX86
	ULONG ContextFlags;

	/* Setup the Initial Win32 Thread Context */
	Context->Eax = (ULONG) StartAddress;
	Context->Ebx = (ULONG) Parameter;
	Context->Esp = (ULONG) StackAddress;
	Context->Eip = (ULONG) StartAddress;
	/* The other registers are undefined */

	/* Setup the Segments */
	Context->SegFs = KGDT_R3_TEB;
	Context->SegEs = KGDT_R3_DATA;
	Context->SegDs = KGDT_R3_DATA;
	Context->SegCs = KGDT_R3_CODE;
	Context->SegSs = KGDT_R3_DATA;
	Context->SegGs = 0;

	/* Set the Context Flags */
	ContextFlags = Context->ContextFlags;
	Context->ContextFlags = CONTEXT_FULL;

	/* Give it some room for the Parameter */
	Context->Esp -= sizeof(PVOID);

	/* Set the EFLAGS */
	Context->EFlags = 0x3000; /* IOPL 3 */

							  /* What kind of context is being created? */

#elif defined(_M_AMD64)
	/* Setup the Initial Win32 Thread Context */
	Context->Rax = (ULONG_PTR) StartAddress;
	Context->Rbx = (ULONG_PTR) Parameter;
	Context->Rsp = (ULONG_PTR) StackAddress;
	Context->Rip = (ULONG_PTR) StartAddress;
	/* The other registers are undefined */

	/* Setup the Segments */
	Context->SegGs = KGDT64_R3_DATA | RPL_MASK;
	Context->SegEs = KGDT64_R3_DATA | RPL_MASK;
	Context->SegDs = KGDT64_R3_DATA | RPL_MASK;
	Context->SegCs = KGDT64_R3_CODE | RPL_MASK;
	Context->SegSs = KGDT64_R3_DATA | RPL_MASK;
	Context->SegFs = KGDT64_R3_CMTEB | RPL_MASK;

	/* Set the EFLAGS */
	Context->EFlags = 0x3000; /* IOPL 3 */

	/* Set the Context Flags */
	Context->ContextFlags = CONTEXT_FULL;

	/* Give it some room for the Parameter */
	Context->Rsp -= sizeof(PVOID);
#elif defined(_M_ARM)
#endif
}

#define ROUND_DOWN(n, align) (((ULONG) n) & ~((align) -1l))
#define ROUND_UP(n, align) ROUND_DOWN(((ULONG) n) + (align) -1, (align))

NTSTATUS
WINAPI
BaseCreateStack(HANDLE hProcess,
	SIZE_T StackCommit,
	SIZE_T StackReserve,
	PINITIAL_TEB InitialTeb)
{
	NTSTATUS Status;
	PIMAGE_NT_HEADERS Headers;
	ULONG_PTR Stack;
	BOOLEAN UseGuard;
	ULONG PageSize, Dummy, AllocationGranularity;
	SIZE_T StackReserveHeader, StackCommitHeader, GuardPageSize, GuaranteedStackCommit;
	SYSTEM_BASIC_INFORMATION BasicInfo;

	HcInternalZero(&BasicInfo, sizeof(BasicInfo));

	Status = HcQuerySystemInformation(SystemBasicInformation,
		&BasicInfo,
		sizeof(BasicInfo),
		0);

	/* Read page size */
	PageSize = BasicInfo.PageSize;
	AllocationGranularity = BasicInfo.AllocationGranularity;

	/* Get the Image Headers */
	Headers = HcImageGetNtHeader(NtCurrentPeb()->ImageBaseAddress);
	if (!Headers) return STATUS_INVALID_IMAGE_FORMAT;

	StackCommitHeader = Headers->OptionalHeader.SizeOfStackCommit;
	StackReserveHeader = Headers->OptionalHeader.SizeOfStackReserve;

	if (!StackReserve) StackReserve = StackReserveHeader;

	if (!StackCommit)
	{
		StackCommit = StackCommitHeader;
	}
	else if (StackCommit >= StackReserve)
	{
		StackReserve = ROUND_UP(StackCommit, 1024 * 1024);
	}

	StackCommit = ROUND_UP(StackCommit, PageSize);
	StackReserve = ROUND_UP(StackReserve, AllocationGranularity);

	GuaranteedStackCommit = NtCurrentTeb()->GuaranteedStackBytes;
	if ((GuaranteedStackCommit) && (StackCommit < GuaranteedStackCommit))
	{
		StackCommit = GuaranteedStackCommit;
	}

	if (StackCommit >= StackReserve)
	{
		StackReserve = ROUND_UP(StackCommit, 1024 * 1024);
	}

	StackCommit = ROUND_UP(StackCommit, PageSize);
	StackReserve = ROUND_UP(StackReserve, AllocationGranularity);

	/* Reserve memory for the stack */
	Stack = 0;
	Status = HcAllocateVirtualMemory(hProcess,
		(PVOID*) &Stack,
		0,
		&StackReserve,
		MEM_RESERVE,
		PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	/* Now set up some basic Initial TEB Parameters */
	InitialTeb->AllocatedStackBase = (PVOID) Stack;
	InitialTeb->StackBase = (PVOID) (Stack + StackReserve);
	InitialTeb->PreviousStackBase = NULL;
	InitialTeb->PreviousStackLimit = NULL;

	/* Update the Stack Position */
	Stack += StackReserve - StackCommit;

	/* Check if we will need a guard page */
	if (StackReserve > StackCommit)
	{
		Stack -= PageSize;
		StackCommit += PageSize;
		UseGuard = TRUE;
	}
	else
	{
		UseGuard = FALSE;
	}

	/* Allocate memory for the stack */
	Status = HcAllocateVirtualMemory(hProcess,
		(PVOID*) &Stack,
		0,
		&StackCommit,
		MEM_COMMIT,
		PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		GuardPageSize = 0;
		HcFreeVirtualMemory(hProcess, (PVOID*) &Stack, &GuardPageSize, MEM_RELEASE);
		return Status;
	}

	/* Now set the current Stack Limit */
	InitialTeb->StackLimit = (PVOID) Stack;

	/* Create a guard page */
	if (UseGuard)
	{
		/* Set the guard page */
		GuardPageSize = BasicInfo.PageSize;
		Status = HcProtectVirtualMemory(hProcess,
			(PVOID*) &Stack,
			&GuardPageSize,
			PAGE_GUARD | PAGE_READWRITE,
			&Dummy);
		if (!NT_SUCCESS(Status))
		{
			return Status;
		}

		/* Update the Stack Limit keeping in mind the Guard Page */
		InitialTeb->StackLimit = (PVOID) ((ULONG_PTR) InitialTeb->StackLimit +
			GuardPageSize);
	}

	/* We are done! */
	return STATUS_SUCCESS;
}