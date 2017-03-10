/*
	@File: highcall.c
	@Purpose: Initialization of the highcall library.

	@Author: Synestraa
	@version: 9/11/2016
*/

#include "highcall.h"

#include "../../public/imports.h"
#include "../../private/sys/syscall.h"

#define BASESRV_SERVERDLL_INDEX     1
#define BASESRV_FIRST_API_NUMBER    0

UNICODE_STRING Restricted = RTL_CONSTANT_STRING(L"Restricted");

HcGlobalEnv HcGlobal;

static NTSTATUS INITIALIZATION_ROUTINE InitializeModules(VOID)
{
	PPEB pPeb = NtCurrentPeb();
	if (pPeb == NULL)
	{
		return STATUS_FAIL_CHECK;
	}

	if (pPeb->LoaderData == NULL)
	{
		return STATUS_FAIL_CHECK;
	}

	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry = NULL;
	PLIST_ENTRY pListHead = &(pPeb->LoaderData->InMemoryOrderModuleList), pListEntry = NULL;

	/* Loop through entry list till we find a match for the module's name
	the comparison is strict to the entire name, case sensitive. */
	for (pListEntry = pListHead->Flink; pListEntry != pListHead; pListEntry = pListEntry->Flink)
	{
		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pListEntry;
		if (pLdrDataTableEntry->FullModuleName.Buffer == NULL 
			|| pLdrDataTableEntry->FullModuleName.Length == 0)
		{
			continue;
		}

		/* Load anything we need from ntdll while we're at it. */
		if (HcStringCompareW(L"ntdll.dll", pLdrDataTableEntry->FullModuleName.Buffer))
		{
			HcGlobal.HandleNtdll = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
		else if (HcStringCompareW(L"user32.dll", pLdrDataTableEntry->FullModuleName.Buffer))
		{
			HcGlobal.HandleUser32 = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
		else if (HcStringCompareW(L"kernel32.dll", pLdrDataTableEntry->FullModuleName.Buffer))
		{
			HcGlobal.HandleKernel32 = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
	}

	if (!HcGlobal.HandleNtdll)
	{
		return STATUS_INVALID_ADDRESS;
	}

	return STATUS_SUCCESS;
}

static NTSTATUS INITIALIZATION_ROUTINE InitializeVersion(VOID)
{
	NTSTATUS Status = STATUS_SUCCESS;
	RTL_OSVERSIONINFOEXW versionInfo;
	ULONG majorVersion;
	ULONG minorVersion;

	ZERO(&versionInfo);
	versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);

	Status = RtlGetVersion((PRTL_OSVERSIONINFOW) &versionInfo);
	if (!NT_SUCCESS(Status))
	{
		HcGlobal.WindowsVersion = WINDOWS_NOT_DEFINED;
		return Status;
	}

	HcGlobal.IsWow64 = HcIsWow64();

	majorVersion = versionInfo.dwMajorVersion;
	minorVersion = versionInfo.dwMinorVersion;

	/* Windows 7 */
	if (majorVersion == 6 && minorVersion == 1)
	{
		HcGlobal.WindowsVersion = WINDOWS_7;
	}
	/* Windows 8.0 */
	else if (majorVersion == 6 && minorVersion == 2)
	{
		HcGlobal.WindowsVersion = WINDOWS_8;
	}
	/* Windows 8.1 */
	else if (majorVersion == 6 && minorVersion == 3)
	{
		HcGlobal.WindowsVersion = WINDOWS_8_1;
	}
	/* Windows 10 */
	else if (majorVersion == 10 && minorVersion == 0)
	{
		HcGlobal.WindowsVersion = WINDOWS_10_1507;
	}
	else
	{
		/* We dont support anything else. */
		HcGlobal.WindowsVersion = WINDOWS_NOT_SUPPORTED;
		Status = STATUS_INVALID_OWNER;
	}

	return Status;
}


static NTSTATUS InitializeSyscall(VOID)
{
	return HcSysInitializeNativeSystem() ? STATUS_SUCCESS : STATUS_FAIL_CHECK;
}

static NTSTATUS INITIALIZATION_ROUTINE InitializeSecurity(VOID)
{
	HANDLE hToken = NULL;
	NTSTATUS Status;

	HcGlobal.IsElevated = FALSE;

	Status = HcOpenProcessToken(NtCurrentProcess,
		TOKEN_QUERY,
		&hToken);

	if (NT_SUCCESS(Status))
	{
		HcTokenIsElevated(hToken, &(HcGlobal.IsElevated));
		HcObjectClose(&hToken);
	}

	if (NtCurrentPeb()->ReadOnlyStaticServerData == NULL)
	{
		return STATUS_INVALID_ADDRESS;
	}

	HcGlobal.BaseStaticServerData = (PBASE_STATIC_SERVER_DATA) NtCurrentPeb()->ReadOnlyStaticServerData[BASESRV_SERVERDLL_INDEX];

	return Status;
}

static NTSTATUS INITIALIZATION_ROUTINE InitializeNamedObjectDirectory()
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS Status;
	HANDLE DirHandle, BnoHandle, Token, NewToken;

	if (NtCurrentTeb()->IsImpersonating)
	{
		Status = HcOpenThreadToken(
			NtCurrentThread,
			TOKEN_IMPERSONATE,
			TRUE,
			&Token);

		if (!NT_SUCCESS(Status))
		{
			return Status;
		}

		NewToken = NULL;

		Status = HcSetInformationThread(
			NtCurrentThread,
			ThreadImpersonationToken,
			&NewToken,
			sizeof(HANDLE));

		if (!NT_SUCCESS(Status))
		{
			HcClose(Token);
			return Status;
		}
	}
	else
	{
		Token = NULL;
	}

	RtlAcquirePebLock();

	InitializeObjectAttributes(
		&ObjectAttributes,
		&HcGlobal.BaseStaticServerData->NamedObjectDirectory,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	Status = HcOpenDirectoryObject(
		&BnoHandle,
		DIRECTORY_QUERY |
		DIRECTORY_TRAVERSE |
		DIRECTORY_CREATE_OBJECT |
		DIRECTORY_CREATE_SUBDIRECTORY,
		&ObjectAttributes);

	if (!NT_SUCCESS(Status))
	{
		Status = HcOpenDirectoryObject(&DirHandle,
			DIRECTORY_TRAVERSE,
			&ObjectAttributes);

		if (NT_SUCCESS(Status))
		{
			InitializeObjectAttributes(
				&ObjectAttributes,
				(PUNICODE_STRING) &Restricted,
				OBJ_CASE_INSENSITIVE,
				DirHandle,
				NULL);

			Status = HcOpenDirectoryObject(&BnoHandle,
				DIRECTORY_QUERY |
				DIRECTORY_TRAVERSE |
				DIRECTORY_CREATE_OBJECT |
				DIRECTORY_CREATE_SUBDIRECTORY,
				&ObjectAttributes);

			HcClose(DirHandle);
		}
	}

	if (NT_SUCCESS(Status))
	{
		HcGlobal.BaseNamedObjectDirectory = BnoHandle;
	}

	RtlReleasePebLock();

	if (Token)
	{
		HcSetInformationThread(NtCurrentThread,
			ThreadImpersonationToken,
			&Token,
			sizeof(Token));

		HcClose(Token);
	}

	return Status;
}

NTSTATUS INITIALIZATION_ROUTINE HcInitialize()
{
	NTSTATUS Status;

	/* Mandatory modules */
	Status = InitializeModules(); 
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	/* Initialize windows version to identify some mandatory syscall identifiers. */
	Status = InitializeVersion();
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	/* Initialize all syscalls */
	Status = InitializeSyscall();
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	Status = InitializeSecurity();
	Status = InitializeNamedObjectDirectory();

	/* Set debug privilege, convenience. */
	HcProcessSetPrivilegeW(NtCurrentProcess, SE_DEBUG_NAME, TRUE);

	HcErrorSetNtStatus(Status);
	return STATUS_SUCCESS;
}

#ifdef _WINDLL

#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
) {

	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			NTSTATUS Status = HcInitialize();

			/* Check if we failed. */
			if (!NT_SUCCESS(Status))
			{
				char errornote[1024];
				HcErrorGetNoteA(errornote);
				
				char message[2048];
				sprintf_s(message, sizeof(message), "Could not start Highcall, Status: %x, Note: %s\n", Status, errornote);
				OutputDebugStringA(message);
				return FALSE;
			}

			return TRUE;
		}

		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}
#endif