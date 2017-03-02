/*
	@File: highcall.c
	@Purpose: Initialization of the highcall library.

	@Author: Synestraa
	@version: 9/11/2016
*/

#include "highcall.h"

#include "../../public/imports.h"
#include "../../private/sys/syscall.h"

HcGlobalEnv HcGlobal;

static HIGHCALL_STATUS InitializeModules(VOID)
{
	PPEB pPeb = NtCurrentPeb();
	if (pPeb == NULL)
	{
		return HIGHCALL_FAILED;
	}

	if (pPeb->LoaderData == NULL)
	{
		return HIGHCALL_FAILED;
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
		return HIGHCALL_FAILED;
	}

	return HIGHCALL_SUCCESS;
}

static HIGHCALL_STATUS InitializeVersion(VOID)
{
	HIGHCALL_STATUS HcStatus = HIGHCALL_SUCCESS;
	RTL_OSVERSIONINFOEXW versionInfo;
	ULONG majorVersion;
	ULONG minorVersion;

	ZERO(&versionInfo);
	versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);

	if (!NT_SUCCESS(
		RtlGetVersion((PRTL_OSVERSIONINFOW)&versionInfo)))
	{
		HcGlobal.WindowsVersion = WINDOWS_NOT_DEFINED;
		return HIGHCALL_WINDOWS_UNDEFINED;
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
		HcStatus = HIGHCALL_WINDOWS_UNDEFINED;
	}

	return HcStatus;
}


static HIGHCALL_STATUS InitializeSyscall(VOID)
{
	return HcSysInitializeNativeSystem() ? HIGHCALL_SUCCESS : HIGHCALL_FAILED;
}

static VOID InitializeSecurity(VOID)
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
}

HIGHCALL_STATUS HCAPI HcInitialize()
{
	HIGHCALL_STATUS Status;

	/* Mandatory modules */
	Status = InitializeModules(); 
	if (!HIGHCALL_ADVANCE(Status))
	{
		return Status;
	}

	/* Initialize windows version to identify some mandatory syscall identifiers. */
	Status = InitializeVersion();
	if (!HIGHCALL_ADVANCE(Status))
	{
		return Status;
	}

	/* Initialize all syscalls */
	Status = InitializeSyscall();
	if (!HIGHCALL_ADVANCE(Status))
	{
		return Status;
	}

	InitializeSecurity();

	/* Set debug privilege, convenience. */
	HcProcessSetPrivilegeW(NtCurrentProcess, SE_DEBUG_NAME, TRUE);
	return HIGHCALL_SUCCESS;
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
			HIGHCALL_STATUS Status = HcInitialize();

			/* Check if we failed. */
			if (!HIGHCALL_ADVANCE(Status))
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