#include <highcall.h>

#include "../../public/imports.h"
#include "../sys/syscall.h"

#include <windows.h>

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

DECL_EXTERN_API(BOOLEAN, ProcessExitCodeEx, CONST IN HANDLE hProcess, OUT LPDWORD lpExitCode)
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

DECL_EXTERN_API(HANDLE, ProcessOpen, CONST IN SIZE_T dwProcessId, CONST IN ACCESS_MASK DesiredAccess)
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

DECL_EXTERN_API(BOOLEAN, ProcessReady, CONST IN SIZE_T dwProcessId)
{
	BOOLEAN Success;
	HANDLE hProcess;

	hProcess = HcProcessOpen(dwProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
	if (!hProcess)
	{
		return FALSE;
	}

	/* Ensure we didn't find it before ntdll was loaded */
	Success = HcProcessReadyEx(hProcess);

	HcClose(hProcess);
	return Success;
}

DECL_EXTERN_API(BOOLEAN, ProcessSuspend, CONST IN SIZE_T dwProcessId)
{
	NTSTATUS Status;
	HANDLE hProcess;

	hProcess = HcProcessOpen(dwProcessId, PROCESS_SUSPEND_RESUME);
	if (!hProcess)
	{
		return FALSE;
	}

	Status = HcSuspendProcess(hProcess);

	HcClose(hProcess);
	return NT_SUCCESS(Status);
}

DECL_EXTERN_API(BOOLEAN, ProcessSuspendEx, CONST IN HANDLE hProcess)
{
	/* Suspend and return */
	return NT_SUCCESS(HcSuspendProcess(hProcess));
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

	Status = HcResumeProcess(hProcess);

	HcClose(hProcess);
	return NT_SUCCESS(Status);
}

DECL_EXTERN_API(BOOLEAN, ProcessResumeEx, CONST IN HANDLE hProcess)
{
	return NT_SUCCESS(HcResumeProcess(hProcess));
}

DECL_EXTERN_API(BOOLEAN, ProcessWriteMemory, CONST IN HANDLE hProcess,
	CONST IN LPVOID lpBaseAddress,
	CONST IN LPVOID lpBuffer,
	IN SIZE_T nSize,
	OUT PSIZE_T lpNumberOfBytesWritten)
{
	NTSTATUS Status;
	ULONG OldValue = 0;
	SIZE_T RegionSize;
	PVOID Base;
	BOOLEAN UnProtect;

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

DECL_EXTERN_API(BOOLEAN, ProcessWriteMemoryWow64, CONST IN HANDLE hProcess,
	CONST IN PVOID64 lpBaseAddress,
	CONST IN PVOID64 lpBuffer,
	IN ULONG64 nSize,
	OUT PULONG64 lpNumberOfBytesWritten)
{
	NTSTATUS Status;
	ULONG OldValue = 0;

	/* Write the memory */
	Status = HcWow64WriteVirtualMemory64(hProcess,
		lpBaseAddress,
		(LPVOID) lpBuffer,
		nSize,
		&nSize);

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

	/* Do the read */
	Status = HcReadVirtualMemory(hProcess,
		lpBaseAddress,
		lpBuffer,
		nSize,
		&ReadBytes);

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
	Status = HcWow64ReadVirtualMemory64(hProcess,
		lpBaseAddress,
		lpBuffer,
		nSize,
		&ReadBytes);

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
	Status = HcCreateThreadEx64((DWORD64) &hThread64, THREAD_ALL_ACCESS, 0, (DWORD64) hProcess, lpStartAddress, lpParameter, 0, 0, 0, 0, 0);
#else
	Status = HcCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, lpStartAddress, lpParamater, dwCreationFlags, 0, 0, 0, NULL);
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
	pInformation->Id = HandleToUlong(sysInfo->UniqueProcessId);
	pInformation->ParentProcessId = HandleToUlong(sysInfo->InheritedFromUniqueProcessId);

	/* Copy the name */
	HcStringCopyW(pInformation->Name,
		sysInfo->ImageName.Buffer,
		sysInfo->ImageName.Length / sizeof(WCHAR));
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
		HcClose(hProcess);
	}
}

static NTSTATUS internal_process_list(LPVOID* ppBuffer, PSYSTEM_PROCESS_INFORMATION* pSystemInformation)
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

DECL_EXTERN_API(BOOLEAN, ProcessEnumByNameExW, IN LPCWSTR lpProcessName,
	IN ProcessCallbackExW Callback,
	IN LPARAM lParam)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
	PROCESS_INFORMATION_EX_W hcpInformation;
	PVOID Buffer = NULL;

	/* Query the process list. */
	Status = internal_process_list(&Buffer, &processInfo);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	RtlInitUnicodeString(&processInfo->ImageName, L"IdleSystem");

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

	HcFree(Buffer);
	return FALSE;
}

DECL_EXTERN_API(BOOLEAN, ProcessGetById, CONST IN DWORD dwProcessId, OUT PPROCESS_INFORMATION_W pProcessInfo)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
	PVOID Buffer = NULL;
	BOOLEAN ReturnValue = FALSE;

	/* Query the process list. */
	Status = internal_process_list(&Buffer, &processInfo);
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
	HcFree(Buffer);
	return ReturnValue;
}

DECL_EXTERN_API(BOOLEAN, ProcessGetByNameW, IN LPCWSTR lpName, OUT PPROCESS_INFORMATION_W pProcessInfo)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
	PVOID Buffer = NULL;
	BOOLEAN ReturnValue = FALSE;

	/* Query the process list. */
	Status = internal_process_list(&Buffer, &processInfo);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return ReturnValue;
	}

	RtlInitUnicodeString(&processInfo->ImageName, L"IdleSystem");

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
	HcFree(Buffer);
	return ReturnValue;
}

DECL_EXTERN_API(BOOLEAN, ProcessGetAllByNameW, IN LPCWSTR lpName, OUT PROCESS_INFORMATION_W** pProcessInfo, OUT PULONG Count)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
	PVOID Buffer = NULL;
	BOOLEAN ReturnValue = FALSE;

	if (Count == NULL || pProcessInfo == NULL)
	{
		HcErrorSetDosError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	*Count = 0;

	/* Query the process list. */
	Status = internal_process_list(&Buffer, &processInfo);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return ReturnValue;
	}

	RtlInitUnicodeString(&processInfo->ImageName, L"IdleSystem");

	/* Loop through the process list */
	while (TRUE)
	{
		/* Check for a match */
		if (!HcStringIsNullOrEmpty(processInfo->ImageName.Buffer) && HcStringEqualW(processInfo->ImageName.Buffer, lpName, TRUE))
		{
			/* Insert process into PROCESS_INFORMATION_W[n] structure. */

			internal_spi_to_highcall_struct(processInfo, &(*pProcessInfo)[*Count]);

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

	/* Query the process list. */
	Status = internal_process_list(&Buffer, &processInfo);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	RtlInitUnicodeString(&processInfo->ImageName, L"IdleSystem");

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

DECL_EXTERN_API(BOOLEAN, ProcessGetPeb, CONST IN HANDLE hProcess, OUT PPEB pPeb)
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

DECL_EXTERN_API(BOOLEAN, ProcessGetPeb32, CONST IN HANDLE hProcess, OUT PPEB32 pPeb)
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

	Status = HcQueryVirtualMemory(hProcess, NULL, MemoryWorkingSetExInformation, Data, sizeof(*Data), NULL);
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