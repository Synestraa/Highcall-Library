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
#include "../private/imports.h"

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

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessIsWow64Ex(IN HANDLE hProcess)
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

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessIsWow64(IN DWORD dwProcessId)
{
	HANDLE hProcess = NULL;
	BOOLEAN Result = FALSE;

	if (!(hProcess = HcProcessOpen(dwProcessId,
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)))
	{
		return FALSE;
	}

	Result = HcProcessIsWow64Ex(hProcess);

	HcObjectClose(hProcess);
	return Result;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessExitCode(IN SIZE_T dwProcessId,
	IN LPDWORD lpExitCode)
{
	HANDLE hProcess = NULL;
	PROCESS_BASIC_INFORMATION ProcessBasic = { 0 };
	NTSTATUS Status = STATUS_SUCCESS;

	if (!((hProcess = HcProcessOpen(dwProcessId,
	                                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ))))
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

HC_EXTERN_API
BOOLEAN 
HCAPI
HcProcessExitCodeEx(IN HANDLE hProcess,
	IN LPDWORD lpExitCode)
{
	PROCESS_BASIC_INFORMATION ProcessBasic = { 0 };
	NTSTATUS Status = STATUS_SUCCESS;

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

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessGetCurrentDirectoryW(HANDLE hProcess, LPWSTR szDirectory, PSIZE_T ptOutSize)
{
	PROCESS_BASIC_INFORMATION	pbi = { 0 };
	RTL_USER_PROCESS_PARAMETERS upp = { 0 };
	PEB							peb = { 0 };
	DWORD						queryLen = 0;
	SIZE_T						len = queryLen;
	NTSTATUS					Status;

	Status = HcQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi,
		sizeof(pbi), &queryLen);

	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	if (!HcProcessReadMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), &len))
	{
		return FALSE;
	}

	if (!HcProcessReadMemory(hProcess, peb.ProcessParameters, &upp, sizeof(RTL_USER_PROCESS_PARAMETERS), &len))
	{
		return FALSE;
	}

	if (!HcProcessReadNullifiedString(hProcess, &upp.CurrentDirectory.DosPath, szDirectory, upp.CurrentDirectory.DosPath.Length))
	{
		return FALSE;
	}

	*ptOutSize = upp.CurrentDirectory.DosPath.Length;

	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessGetCurrentDirectoryA(HANDLE hProcess, LPSTR szDirectory)
{
	LPWSTR lpCopy = (LPWSTR)HcAlloc(MAX_PATH * sizeof(WCHAR) + sizeof(WCHAR));
	SIZE_T dirSize = 0;

	if (!HcProcessGetCurrentDirectoryW(hProcess, lpCopy, &dirSize))
	{
		HcFree(lpCopy);
		return FALSE;
	}

	if (!HcStringCopyConvertWtoA(lpCopy, szDirectory, dirSize / sizeof(WCHAR) + 1))
	{
		HcFree(lpCopy);
		return FALSE;
	}

	HcFree(lpCopy);
	return TRUE;
}

HC_EXTERN_API
HANDLE
HCAPI
HcProcessOpen(SIZE_T dwProcessId,
	ACCESS_MASK DesiredAccess)
{
	NTSTATUS Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES oa = { 0 };
	CLIENT_ID cid = { 0 };
	HANDLE hProcess = NULL;

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

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessReadyEx(HANDLE hProcess)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PPEB_LDR_DATA LoaderData = NULL;
	PROCESS_BASIC_INFORMATION ProcInfo = { 0 };
	DWORD ExitCode = 0;
	DWORD Len = 0;

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

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessReady(SIZE_T dwProcessId)
{
	BOOLEAN Success = FALSE;
	HANDLE hProcess = NULL;

	if (!((hProcess = HcProcessOpen(dwProcessId,
	                                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ))))
	{
		return FALSE;
	}

	/* Ensure we didn't find it before ntdll was loaded */
	Success = HcProcessReadyEx(hProcess);

	HcClose(hProcess);

	return Success;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessSuspend(SIZE_T dwProcessId)
{
	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE hProcess = NULL;

	/* Open the process */
	hProcess = HcProcessOpen(dwProcessId, PROCESS_ALL_ACCESS);

	/* Do the suspend */
	Status = HcSuspendProcess(hProcess);

	/* Close the process and return */
	HcClose(hProcess);
	return NT_SUCCESS(Status);
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessSuspendEx(HANDLE hProcess)
{
	/* Suspend and return */
	return NT_SUCCESS(HcSuspendProcess(hProcess));
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessResume(SIZE_T dwProcessId)
{
	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE hProcess = NULL;

	/* Open the process */
	hProcess = HcProcessOpen(dwProcessId, PROCESS_ALL_ACCESS);

	/* Do the resume */
	Status = HcResumeProcess(hProcess);

	/* Close the handle and return */
	HcClose(hProcess);
	return NT_SUCCESS(Status);
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessResumeEx(HANDLE hProcess)
{
	/* Do the resume */
	return NT_SUCCESS(HcResumeProcess(hProcess));
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessWriteMemory(HANDLE hProcess,
	LPVOID lpBaseAddress,
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

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessReadMemory(IN HANDLE hProcess,
	IN LPCVOID lpBaseAddress,
	IN LPVOID lpBuffer,
	IN SIZE_T nSize,
	OUT SIZE_T* lpNumberOfBytesRead)
{
	NTSTATUS Status = STATUS_SUCCESS;

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

HC_EXTERN_API
HANDLE
HCAPI
HcProcessCreateThread(IN HANDLE hProcess,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParamater,
	IN DWORD dwCreationFlags)
{
	NTSTATUS Status = STATUS_SUCCESS;
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

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessReadNullifiedString(HANDLE hProcess,
	PUNICODE_STRING usStringIn,
	LPWSTR lpStringOut,
	SIZE_T lpSize)
{
	SIZE_T Len = 0;

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

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessLdrModuleToHighCallModule(IN HANDLE hProcess,
	IN PLDR_DATA_TABLE_ENTRY Module,
	OUT PHC_MODULE_INFORMATIONW phcModuleOut)
{
	//
	// Copy the modules name from the process to the out parameter, if specified.
	//
	HcProcessReadNullifiedString(hProcess,
		&Module->BaseModuleName,
		phcModuleOut->Name,
		Module->BaseModuleName.Length);

	//
	// Copy the module's path from the process to the out parameter, if specified.
	//
	HcProcessReadNullifiedString(hProcess,
		&Module->FullModuleName,
		phcModuleOut->Path,
		Module->FullModuleName.Length);

	phcModuleOut->Size = Module->SizeOfImage;
	phcModuleOut->Base = Module->ModuleBase;

	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessQueryInformationModule(IN HANDLE hProcess,
	IN HMODULE hModule OPTIONAL,
	OUT PHC_MODULE_INFORMATIONW phcModuleOut)
{
	SIZE_T Count = 0;
	NTSTATUS Status = STATUS_SUCCESS;
	PPEB_LDR_DATA LoaderData = NULL;
	PLIST_ENTRY ListHead = NULL, ListEntry = NULL;
	PROCESS_BASIC_INFORMATION ProcInfo = { 0 };
	LDR_DATA_TABLE_ENTRY Module = { 0 };
	ULONG Len = 0;

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

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessEnumModulesW(HANDLE hProcess,
	HC_MODULE_CALLBACK_EVENTW hcmCallback,
	LPARAM lParam)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PPEB_LDR_DATA LoaderData = NULL;
	PLIST_ENTRY ListHead = NULL, ListEntry = NULL;
	PROCESS_BASIC_INFORMATION ProcInfo = { 0 };
	LDR_DATA_TABLE_ENTRY ldrModule = { 0 };
	PHC_MODULE_INFORMATIONW Module = NULL;
	SIZE_T Count = 0;
	ULONG Len = 0;

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
			HcErrorSetDosError(ERROR_INVALID_HANDLE);
			return FALSE;
		}

		/* Get to next listed module */
		ListEntry = ldrModule.InLoadOrderLinks.Flink;
	}

	return FALSE;
}

HC_EXTERN_API
BOOLEAN
HCAPI 
HcProcessEnumMappedImagesW(HANDLE ProcessHandle,
	HC_MODULE_CALLBACK_EVENTW hcmCallback,
	LPARAM lParam)
{
	BOOLEAN Continue = FALSE;
	PVOID baseAddress = NULL;
	MEMORY_BASIC_INFORMATION basicInfo = { 0 };
	PHC_MODULE_INFORMATIONW hcmInformation = NULL;
	SIZE_T allocationSize = 0;

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
ULONG 
HCAPI 
HcGetProcessListSize()
{
	ULONG Size = 0;

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

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessQueryByNameExW(LPCWSTR lpProcessName,
	HC_PROCESS_CALLBACK_EVENT_EXW Callback,
	LPARAM lParam)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
	HANDLE CurrentHandle = NULL;
	PHC_PROCESS_INFORMATION_EXW hcpInformation = NULL;
	PVOID Buffer = NULL;
	ULONG Length = 0;

	/* Query the required size. */
	Length = HcGetProcessListSize();
	if (!Length)
	{
		return FALSE;
	}

	/* Allocate the buffer with specified size. */
	if (!((Buffer = HcAlloc(Length))))
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
		hcpInformation = HcInitializeProcessInformationExW(MAX_PATH);

		/* Check for a match */
		if (HcStringIsNullOrEmpty(lpProcessName) || HcStringEqualW(processInfo->ImageName.Buffer, lpProcessName, TRUE))
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

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessQueryByNameW(LPCWSTR lpProcessName,
	HC_PROCESS_CALLBACK_EVENTW Callback,
	LPARAM lParam)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
	PHC_PROCESS_INFORMATIONW hcpInformation = NULL;
	PVOID Buffer = NULL;
	ULONG Length = 0;

	/* Query the required size. */
	Length = HcGetProcessListSize();

	if (!Length)
	{
		return FALSE;
	}

	/* Allocate the buffer with specified size. */
	if (!((Buffer = HcAlloc(Length))))
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
		hcpInformation = HcInitializeProcessInformationW(MAX_PATH);

		/* Check for a match */
		if (HcStringIsNullOrEmpty(lpProcessName) || HcStringEqualW(processInfo->ImageName.Buffer, lpProcessName, TRUE))
		{
			hcpInformation->Id = HandleToUlong(processInfo->UniqueProcessId);

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

HC_EXTERN_API
SIZE_T
WINAPI
HcProcessModuleFileName(HANDLE hProcess,
	LPVOID lpv,
	LPWSTR lpFilename,
	DWORD nSize)
{
	SIZE_T Len = 0;
	SIZE_T OutSize = 0;
	NTSTATUS Status = STATUS_SUCCESS;

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

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessSetPrivilegeA(HANDLE hProcess,
	LPCSTR Privilege, 
	BOOLEAN bEnablePrivilege 
){
	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp = { 0 };
	PLUID pLuid = NULL;
	TOKEN_PRIVILEGES tpPrevious = { 0 };
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

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessSetPrivilegeW(HANDLE hProcess,
	LPCWSTR Privilege,
	BOOLEAN bEnablePrivilege) 
{
	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp = { 0 };
	PLUID pLuid = NULL;
	TOKEN_PRIVILEGES tpPrevious = { 0 };
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

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessGetPeb(HANDLE hProcess, PPEB pPeb)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PROCESS_BASIC_INFORMATION ProcInfo = { 0 };
	ULONG Len = 0;

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
		pPeb, sizeof(*pPeb),
		NULL))
	{
		return FALSE;
	}

	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcProcessGetCommandLineW(HANDLE hProcess,
	LPWSTR lpszCommandline,
	BOOLEAN bAlloc)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PROCESS_BASIC_INFORMATION ProcInfo = { 0 };
	RTL_USER_PROCESS_PARAMETERS processParameters = { 0 };
	PEB peb = { 0 };

	if (!HcProcessGetPeb(hProcess, &peb))
	{
		return FALSE;
	}

	if (!HcProcessReadMemory(hProcess,
		peb.ProcessParameters,
		&processParameters,
		sizeof(processParameters),
		NULL))
	{
		return FALSE;
	}

	if (bAlloc)
	{
		lpszCommandline = (LPWSTR)HcAlloc(processParameters.CommandLine.MaximumLength);
		if (!lpszCommandline)
		{
			HcErrorSetNtStatus(STATUS_NO_MEMORY);
			return FALSE;
		}
	}

	if (!HcProcessReadNullifiedString(hProcess,
		&(processParameters.CommandLine),
		lpszCommandline,
		processParameters.CommandLine.Length / 2))
	{
		return FALSE;
	}

	return TRUE;
}