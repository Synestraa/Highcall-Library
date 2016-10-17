/*++

Module Name:

hcprocess.c

Abstract:

This module implements windows NT/WIN32 usermode to kernel "process" information handlers, declared in hcprocess.h.

Author:

Synestra 9/11/2016

Revision History:

Synestra 10/15/2016

--*/

#define _CRT_SECURE_NO_WARNINGS

//
// Used for multiple macros, such as STILL_ACTIVE.
//
#include <windows.h>

//
// Used for HcWriteVirtualMemory, HcSuspendProcess, HcResumeProcess, HcReadVirtualMemory...
//
#include "../sys/hcsyscall.h"

//
// Contains this module's declerations.
//
#include "../headers/hcprocess.h"

//
// Used for RtlInitUnicodeString
//
#include "../headers/hcimport.h"

//
// !! NOT_FINISHED !! used in HcProcessInjectModuleManual
//
#include "../headers/hcfile.h"
#include "../headers/hcpe.h"

//
// Used for HcLookupPrivilegeValue()
//
#include "../headers/hctoken.h"

//
// Used for HcObjectWait, HcObjectClose
//
#include "../headers/hcobject.h"

//
// Used for HcErrorSetNtStatus, HcErrorSetDosError
//
#include "../headers/hcerror.h"

//
// Used for HcFree, HcAlloc, HcVirtualFreeEx, HcVirtualAllocEx, HcVirtualAlloc
//
#include "../headers/hcvirtual.h"

//
// Used for HcStringEqualW, HcStringCopyW
//
#include "../headers/hcstring.h"

BOOLEAN
HCAPI
HcProcessIsWow64Ex(IN HANDLE hProcess)
{
	ULONG_PTR pbi;
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


BOOLEAN
HCAPI
HcProcessIsWow64(IN DWORD dwProcessId)
{
	HANDLE hProcess;
	BOOLEAN Result;

	if (!(hProcess = HcProcessOpen(dwProcessId,
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)))
	{
		return FALSE;
	}

	Result = HcProcessIsWow64Ex(hProcess);

	HcObjectClose(hProcess);
	return Result;
}


BOOLEAN
HCAPI
HcProcessExitCode(IN SIZE_T dwProcessId,
	IN LPDWORD lpExitCode)
{
	HANDLE hProcess;
	PROCESS_BASIC_INFORMATION ProcessBasic;
	NTSTATUS Status;

	if (!(hProcess = HcProcessOpen(dwProcessId,
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)))
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


BOOLEAN 
HCAPI
HcProcessExitCodeEx(IN HANDLE hProcess,
	IN LPDWORD lpExitCode)
{
	PROCESS_BASIC_INFORMATION ProcessBasic;
	NTSTATUS Status;

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


HANDLE
HCAPI
HcProcessOpen(SIZE_T dwProcessId,
	ACCESS_MASK DesiredAccess)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid;
	HANDLE hProcess;

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


BOOLEAN
HCAPI
HcProcessReadyEx(HANDLE hProcess)
{
	NTSTATUS Status;
	PPEB_LDR_DATA LoaderData;
	PROCESS_BASIC_INFORMATION ProcInfo;
	DWORD ExitCode;
	DWORD Len;

	/* Will fail if there is a mismatch in compiler architecture. */
	if (!HcProcessExitCodeEx(hProcess, &ExitCode) || ExitCode != STILL_ACTIVE)
	{
		return FALSE;
	}

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		&ProcInfo,
		sizeof(ProcInfo),
		&Len);

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


BOOLEAN
HCAPI
HcProcessReady(SIZE_T dwProcessId)
{
	BOOLEAN Success;
	HANDLE hProcess;

	if (!(hProcess = HcProcessOpen(dwProcessId,
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)))
	{
		return FALSE;
	}

	/* Ensure we didn't find it before ntdll was loaded */
	Success = HcProcessReadyEx(hProcess);

	HcClose(hProcess);

	return Success;
}

BOOLEAN
HCAPI
HcProcessSuspend(SIZE_T dwProcessId)
{
	NTSTATUS Status;
	HANDLE hProcess;

	/* Open the process */
	hProcess = HcProcessOpen(dwProcessId, PROCESS_ALL_ACCESS);

	/* Do the suspend */
	Status = HcSuspendProcess(hProcess);

	/* Close the process and return */
	HcClose(hProcess);
	return NT_SUCCESS(Status);
}


BOOLEAN
HCAPI
HcProcessSuspendEx(HANDLE hProcess)
{
	/* Suspend and return */
	return NT_SUCCESS(HcSuspendProcess(hProcess));
}


BOOLEAN
HCAPI
HcProcessResume(SIZE_T dwProcessId)
{
	NTSTATUS Status;
	HANDLE hProcess;

	/* Open the process */
	hProcess = HcProcessOpen(dwProcessId, PROCESS_ALL_ACCESS);

	/* Do the resume */
	Status = HcResumeProcess(hProcess);

	/* Close the handle and return */
	HcClose(hProcess);
	return NT_SUCCESS(Status);
}

BOOLEAN
HCAPI
HcProcessResumeEx(HANDLE hProcess)
{
	/* Do the resume */
	return NT_SUCCESS(HcResumeProcess(hProcess));
}

BOOLEAN
HCAPI
HcProcessWriteMemory(HANDLE hProcess,
	LPVOID lpBaseAddress,
	CONST VOID* lpBuffer,
	SIZE_T nSize,
	PSIZE_T lpNumberOfBytesWritten)
{
	NTSTATUS Status;
	ULONG OldValue;
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

BOOLEAN
HCAPI
HcProcessReadMemory(IN HANDLE hProcess,
	IN LPCVOID lpBaseAddress,
	IN LPVOID lpBuffer,
	IN SIZE_T nSize,
	OUT SIZE_T* lpNumberOfBytesRead)
{
	NTSTATUS Status;

	/* Do the read */
	Status = HcReadVirtualMemory(hProcess,
		(PVOID)lpBaseAddress,
		lpBuffer,
		nSize,
		&nSize);

	/* In user-mode, this parameter is optional */
	if (lpNumberOfBytesRead) *lpNumberOfBytesRead = nSize;

	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		return FALSE;
	}

	/* Return success */
	return TRUE;
}

HANDLE
HCAPI
HcProcessCreateThread(IN HANDLE hProcess,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParamater,
	IN DWORD dwCreationFlags)
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

BOOLEAN
HCAPI
HcProcessQueryInformationWindow(_In_ HANDLE ProcessHandle,
	PHC_WINDOW_INFORMATIONW HCWindowInformation)
{
	NTSTATUS Status;
	PVOID Buffer;
	ULONG ReturnLength;
	PPROCESS_WINDOW_INFORMATION WindowInformation;

	/* Query the length. */
	Status = HcQueryInformationProcess(ProcessHandle,
		ProcessWindowInformation,
		NULL,
		0,
		&ReturnLength);

	if (NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	Buffer = HcAlloc(ReturnLength);

	WindowInformation = (PPROCESS_WINDOW_INFORMATION)Buffer;

	/* Get the window information. */
	Status = HcQueryInformationProcess(ProcessHandle,
		ProcessWindowInformation,
		WindowInformation,
		ReturnLength,
		&ReturnLength);

	if (NT_SUCCESS(Status))
	{
		HCWindowInformation->WindowFlags = WindowInformation->WindowFlags;

		/* Copy the window's title. */
		HcStringCopyW(HCWindowInformation->WindowTitle,
			WindowInformation->WindowTitle,
			WindowInformation->WindowTitleLength);

		HcFree(Buffer);
		return TRUE;
	}

	HcFree(Buffer);
	return FALSE;
}

BOOLEAN
HCAPI
HcProcessReadNullifiedString(HANDLE hProcess,
	PUNICODE_STRING usStringIn,
	LPWSTR lpStringOut,
	SIZE_T lpSize)
{
	SIZE_T Len;

	/* Get the maximum len we have/can write in given size */
	Len = usStringIn->Length + sizeof(UNICODE_NULL);
	if (lpSize * sizeof(WCHAR) < Len)
	{
		Len = lpSize * sizeof(WCHAR);
	}

	/* Read the string */
	if (!HcProcessReadMemory(hProcess,
		usStringIn->Buffer,
		lpStringOut,
		Len,
		NULL))
	{
		return FALSE;
	}

	/* If we are at the end of the string, prepare to override to nullify string */
	if (Len == usStringIn->Length + sizeof(UNICODE_NULL))
	{
		Len -= sizeof(UNICODE_NULL);
	}

	/* Nullify at the end if needed */
	if (Len >= lpSize * sizeof(WCHAR))
	{
		if (lpSize)
		{
			ASSERT(lpSize >= sizeof(UNICODE_NULL));
			lpStringOut[lpSize - 1] = UNICODE_NULL;
		}
	}
	/* Otherwise, nullify at last writen char */
	else
	{
		ASSERT(Len + sizeof(UNICODE_NULL) <= lpSize * sizeof(WCHAR));
		lpStringOut[Len / sizeof(WCHAR)] = UNICODE_NULL;
	}

	return TRUE;
}

BOOLEAN
HCAPI
HcProcessLdrModuleToHighCallModule(IN HANDLE hProcess,
	IN PLDR_DATA_TABLE_ENTRY Module,
	OUT PHC_MODULE_INFORMATIONW phcModuleOut)
{
	/* Copy the modules name from the process. */
	if (!HcProcessReadNullifiedString(hProcess,
		&Module->BaseModuleName,
		phcModuleOut->Name,
		Module->BaseModuleName.Length))
	{
		return FALSE;
	}

	/* Copy the module's path from the process. */
	if (!HcProcessReadNullifiedString(hProcess,
		&Module->FullModuleName,
		phcModuleOut->Path,
		Module->FullModuleName.Length))
	{
		return FALSE;
	}

	phcModuleOut->Size = Module->SizeOfImage;
	phcModuleOut->Base = (SIZE_T)Module->ModuleBase;

	return TRUE;
}

BOOLEAN
HCAPI
HcProcessQueryInformationModule(IN HANDLE hProcess,
	IN HMODULE hModule OPTIONAL,
	OUT PHC_MODULE_INFORMATIONW phcModuleOut)
{
	SIZE_T Count;
	NTSTATUS Status;
	PPEB_LDR_DATA LoaderData;
	PLIST_ENTRY ListHead, ListEntry;
	PROCESS_BASIC_INFORMATION ProcInfo;
	LDR_DATA_TABLE_ENTRY Module;
	ULONG Len;

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		&ProcInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		&Len);

	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	/* If no module was provided, get base as module */
	if (hModule == NULL)
	{
		if (!HcProcessReadMemory(hProcess,
			&(ProcInfo.PebBaseAddress->ImageBaseAddress),
			&hModule,
			sizeof(hModule),
			NULL))
		{
			return FALSE;
		}
	}

	/* Read loader data address from PEB */
	if (!HcProcessReadMemory(hProcess,
		&(ProcInfo.PebBaseAddress->LoaderData),
		&LoaderData,
		sizeof(LoaderData),
		NULL))
	{
	return FALSE;
	}

	if (LoaderData == NULL)
	{
		HcErrorSetDosError(ERROR_INVALID_HANDLE);
		return FALSE;
	}

	/* Store list head address */
	ListHead = &(LoaderData->InMemoryOrderModuleList);

	/* Read first element in the modules list */
	if (!HcProcessReadMemory(hProcess,
		&(LoaderData->InMemoryOrderModuleList.Flink),
		&ListEntry,
		sizeof(ListEntry),
		NULL))
	{
		return FALSE;
	}

	Count = 0;

	/* Loop on the modules */
	while (ListEntry != ListHead)
	{
		/* Load module data */
		if (!HcProcessReadMemory(hProcess,
			CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
			&Module,
			sizeof(Module),
			NULL))
		{
			return FALSE;
		}

		/* Does that match the module we're looking for? */
		if (Module.ModuleBase == hModule)
		{
			return HcProcessLdrModuleToHighCallModule(hProcess,
				&Module,
				phcModuleOut);
		}

		++Count;
		if (Count > MAX_MODULES)
		{
			break;
		}

		/* Get to next listed module */
		ListEntry = Module.InMemoryOrderLinks.Flink;
	}

	HcErrorSetDosError(ERROR_INVALID_HANDLE);
	return FALSE;
}

BOOLEAN
HCAPI
HcProcessEnumModulesW(HANDLE hProcess,
	HC_MODULE_CALLBACK_EVENTW hcmCallback,
	LPARAM lParam)
{
	NTSTATUS Status;
	PPEB_LDR_DATA LoaderData;
	PLIST_ENTRY ListHead, ListEntry;
	PROCESS_BASIC_INFORMATION ProcInfo;
	LDR_DATA_TABLE_ENTRY ldrModule;
	PHC_MODULE_INFORMATIONW Module;
	SIZE_T Count;
	ULONG Len;

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

	Count = 0;

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

		Module = HcInitializeModuleInformationW(MAX_PATH * sizeof(WCHAR), MAX_PATH * sizeof(WCHAR));

		/* Attempt to convert to a HC module */
		if (HcProcessLdrModuleToHighCallModule(hProcess,
			&ldrModule,
			Module))
		{
			/* Give it to the caller */
			if (hcmCallback(Module, lParam))
			{
				HcDestroyModuleInformationW(Module);
				return TRUE;
			}

			Count += 1;
		}

		HcDestroyModuleInformationW(Module);

		if (Count > MAX_MODULES)
		{
			HcErrorSetDosError(ERROR_INVALID_HANDLE);
			return FALSE;
		}

		/* Get to next listed module */
		ListEntry = ldrModule.InLoadOrderLinks.Flink;
	}

	return FALSE;
}

BOOLEAN
HCAPI 
HcProcessEnumMappedImagesW(HANDLE ProcessHandle,
	HC_MODULE_CALLBACK_EVENTW hcmCallback,
	LPARAM lParam)
{
	BOOLEAN Continue;
	PVOID baseAddress;
	MEMORY_BASIC_INFORMATION basicInfo;
	PHC_MODULE_INFORMATIONW hcmInformation;
	SIZE_T allocationSize;

	baseAddress = NULL;

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
			hcmInformation = HcInitializeModuleInformationW(MAX_PATH * sizeof(WCHAR), MAX_PATH * sizeof(WCHAR));

			hcmInformation->Base = (SIZE_T) basicInfo.AllocationBase;
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
				MAX_PATH * sizeof(WCHAR)))
			{
				/* Temporary.
					The name should be stripped from the path.
					The path should be resolved from native to dos.
				*/
				HcStringCopyW(hcmInformation->Name, hcmInformation->Path, MAX_PATH * sizeof(WCHAR));
			}

			if (hcmCallback(hcmInformation, lParam))
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
ULONG 
HCAPI 
HcGetProcessListSize()
{
	ULONG Size;

	Size = 0;

	/* Query the Length. */
	HcQuerySystemInformation(SystemProcessInformation,
		NULL,
		0,
		&Size);

	if (Size == 0)
	{
		return Size;
	}

	/* In case any new processes show up meanwhile. */
	Size *= 2;

	return Size;
}

BOOLEAN
HCAPI
HcProcessQueryByNameExW(LPCWSTR lpProcessName,
	HC_PROCESS_CALLBACK_EVENT_EXW Callback,
	LPARAM lParam)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo;
	HANDLE CurrentHandle;
	PHC_PROCESS_INFORMATION_EXW hcpInformation;
	PVOID Buffer;
	ULONG Length;

	/* Query the required size. */
	Length = HcGetProcessListSize();
	if (!Length)
	{
		return FALSE;
	}

	/* Allocate the buffer with specified size. */
	if (!(Buffer = HcAlloc(Length)))
	{
		HcErrorSetNtStatus(STATUS_INSUFFICIENT_RESOURCES);
		return FALSE;
	}

	processInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer;

	/* Query the process list. */
	if (!NT_SUCCESS(Status = HcQuerySystemInformation(SystemProcessInformation,
		processInfo,
		Length,
		&Length)))
	{
		HcFree(Buffer);
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	RtlInitUnicodeString(&processInfo->ImageName, L"IdleSystem");

	/* Loop through the process list */
	while (TRUE)
	{
		hcpInformation = HcInitializeProcessInformationExW(MAX_PATH * sizeof(WCHAR));

		/* Check for a match */
		if (!lpProcessName || HcStringEqualW(processInfo->ImageName.Buffer, lpProcessName, TRUE))
		{
			hcpInformation->Id = HandleToUlong(processInfo->UniqueProcessId);

			/* Copy the name */
			HcStringCopyW(hcpInformation->Name,
				processInfo->ImageName.Buffer,
				processInfo->ImageName.Length);

			/* Try opening the process */
			if ((CurrentHandle = HcProcessOpen((SIZE_T)processInfo->UniqueProcessId,
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)))
			{
				hcpInformation->CanAccess = TRUE;

				/* Query main module */
				HcProcessQueryInformationModule(CurrentHandle,
					NULL,
					hcpInformation->MainModule);

				HcProcessQueryInformationWindow(CurrentHandle,
					hcpInformation->MainWindow);

				/* Close this handle. */
				HcClose(CurrentHandle);
			}

			/* Call the callback as long as the user doesn't return FALSE. */
			if (Callback(hcpInformation, lParam))
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

BOOLEAN
HCAPI
HcProcessQueryByNameW(LPCWSTR lpProcessName,
	HC_PROCESS_CALLBACK_EVENTW Callback,
	LPARAM lParam)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo;
	PHC_PROCESS_INFORMATIONW hcpInformation;
	PVOID Buffer;
	ULONG Length;

	/* Query the required size. */
	Length = HcGetProcessListSize();

	if (!Length)
	{
		return FALSE;
	}

	/* Allocate the buffer with specified size. */
	if (!(Buffer = HcAlloc(Length)))
	{
		HcErrorSetNtStatus(STATUS_INSUFFICIENT_RESOURCES);
		return FALSE;
	}

	processInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer;

	/* Query the process list. */
	if (!NT_SUCCESS(Status = HcQuerySystemInformation(SystemProcessInformation,
		processInfo,
		Length,
		&Length)))
	{
		HcFree(Buffer);
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	RtlInitUnicodeString(&processInfo->ImageName, L"IdleSystem");

	/* Loop through the process list */
	while (TRUE)
	{
		hcpInformation = HcInitializeProcessInformationW(MAX_PATH * sizeof(WCHAR));

		/* Check for a match */
		if (!lpProcessName || HcStringEqualW(processInfo->ImageName.Buffer, lpProcessName, TRUE))
		{
			hcpInformation->Id = HandleToUlong(processInfo->UniqueProcessId);

			/* Copy the name */
			HcStringCopyW(hcpInformation->Name,
				processInfo->ImageName.Buffer,
				processInfo->ImageName.Length);

			/* Call the callback as long as the user doesn't return FALSE. */
			if (Callback(hcpInformation, lParam))
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

SIZE_T
WINAPI
HcProcessModuleFileName(HANDLE hProcess,
	LPVOID lpv,
	LPWSTR lpFilename,
	DWORD nSize)
{
	SIZE_T Len;
	SIZE_T OutSize;
	NTSTATUS Status;

	struct
	{
		MEMORY_SECTION_NAME memSection;
		WCHAR CharBuffer[MAX_PATH];
	} SectionName;

	/* If no buffer, no need to keep going on */
	if (nSize == 0)
	{
		HcErrorSetDosError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}

	/* Query section name */
	Status = HcQueryVirtualMemory(hProcess, lpv, MemoryMappedFilenameInformation,
		&SectionName, sizeof(SectionName), &OutSize);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return 0;
	}

	/* Prepare to copy file name */
	Len = OutSize = SectionName.memSection.SectionFileName.Length / sizeof(WCHAR);
	if (OutSize + 1 > nSize)
	{
		Len = nSize - 1;
		OutSize = nSize;
		HcErrorSetDosError(ERROR_INSUFFICIENT_BUFFER);
	}
	else
	{
		HcErrorSetDosError(ERROR_SUCCESS);
	}

	/* Copy, zero and return */
	HcInternalCopy(lpFilename, SectionName.memSection.SectionFileName.Buffer, Len * sizeof(WCHAR));
	lpFilename[Len] = 0;

	return OutSize;
}

BOOLEAN
HCAPI
HcProcessSetPrivilegeA(HANDLE hProcess,
	LPCSTR Privilege, 
	BOOLEAN bEnablePrivilege 
){
	NTSTATUS Status;
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	PLUID pLuid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	/* Acquire handle to token */
	Status = HcOpenProcessToken(hProcess, 
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
		&hToken);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	/* Find the privilege */
	pLuid = HcLookupPrivilegeValueA(Privilege);
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

	// 
	// second pass.  set privilege based on previous setting
	// 
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

	Status = HcAdjustPrivilegesToken(hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		HcObjectClose(hToken);
		return FALSE;
	}

	HcObjectClose(hToken);
	return TRUE;
};

BOOLEAN
HCAPI
HcProcessSetPrivilegeW(HANDLE hProcess,
	LPCWSTR Privilege,
	BOOLEAN bEnablePrivilege) 
{
	NTSTATUS Status;
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	PLUID pLuid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	/* Acquire handle to token */
	Status = HcOpenProcessToken(hProcess,
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken);

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