/*
	@File: highcall.c
	@Purpose: Initialization of the highcall library.

	@Author: Synestraa
	@version: 9/11/2016
*/

#include "highcall.h"

HcGlobalEnv HcGlobal;
t_RtlGetVersion RtlGetVersion;

static HIGHCALL_STATUS InitializeModules(VOID)
{
	PPEB pPeb = NtCurrentPeb();
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry;
	PLIST_ENTRY pListHead, pListEntry;

	/* Get the module list in load order */
	pListHead = &(pPeb->LoaderData->InMemoryOrderModuleList);

	/* Loop through entry list till we find a match for the module's name
	the comparison is strict to the entire name, case sensitive. */
	for (pListEntry = pListHead->Flink; pListEntry != pListHead; pListEntry = pListEntry->Flink)
	{
		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pListEntry;

		/* Load anything we need from ntdll while we're at it. */
		if (!wcscmp(L"ntdll.dll", pLdrDataTableEntry->FullModuleName.Buffer))
		{
			HcGlobal.HandleNtdll = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;

			SIZE_T szModule;
			PIMAGE_EXPORT_DIRECTORY pExports;
			PDWORD pExportNames;
			PDWORD pExportFunctions;
			PWORD pExportOrdinals;
			LPCSTR lpCurrentFunction;

			szModule = (SIZE_T)HcGlobal.HandleNtdll;
			pExports = HcPEGetExportDirectory(HcGlobal.HandleNtdll);

			/* Get the address containg null terminated export names, in ASCII */
			pExportNames = (PDWORD)(pExports->AddressOfNames + szModule);

			/* List through functions */
			for (unsigned int i = 0; i < pExports->NumberOfFunctions; i++)
			{
				lpCurrentFunction = (LPCSTR)(pExportNames[i] + szModule);
				if (!lpCurrentFunction)
				{
					continue;
				}

				/* Check for version function.
				If by the end of the iteration this function is not found, highcall initialization will always fail. */
				if (!strcmp(lpCurrentFunction, "RtlGetVersion"))
				{
					pExportOrdinals = (PWORD)(pExports->AddressOfNameOrdinals + szModule);
					pExportFunctions = (PDWORD)(pExports->AddressOfFunctions + szModule);

					RtlGetVersion = (t_RtlGetVersion)(pExportFunctions[pExportOrdinals[i]] + szModule);
					break;
				}
			}
		}
		else if (!wcscmp(L"user32.dll", pLdrDataTableEntry->FullModuleName.Buffer))
		{
			HcGlobal.HandleUser32 = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
		else if (!wcscmp(L"kernel32.dll", pLdrDataTableEntry->FullModuleName.Buffer))
		{
			HcGlobal.HandleKernel32 = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
	}

	if (!HcGlobal.HandleNtdll)
	{
		return HIGHCALL_FAILED;
	}

	if (!RtlGetVersion)
	{
		return HIGHCALL_IMPORT_UNDEFINED;
	}

	return HIGHCALL_SUCCESS;
}

static HIGHCALL_STATUS InitializeVersion(VOID)
{
	HIGHCALL_STATUS Status;
	RTL_OSVERSIONINFOEXW versionInfo;
	ULONG majorVersion;
	ULONG minorVersion;

	versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	if (!NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&versionInfo)))
	{
		HcGlobal.WindowsVersion = WINDOWS_NOT_DEFINED;
		return HIGHCALL_WINDOWS_UNDEFINED;
	}

	HcGlobal.IsWow64 = HcIsWow64();

	majorVersion = versionInfo.dwMajorVersion;
	minorVersion = versionInfo.dwMinorVersion;

	Status = HIGHCALL_SUCCESS;

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
		Status = HIGHCALL_WINDOWS_UNDEFINED;
	}

	return Status;
}



static HIGHCALL_STATUS InitializeMandatorySyscall(VOID)
{
	/* x86_64 Architecture system call indexes for both wow64 and native */

	/* Windows 7 | Windows 8 | Windows 8.1 | Windows 10 1507 | Windows 10 1511 | Windows 10 1607 */

	/* NtClose 0x00c 0x00d 0x00e 0x00f */
	/* NtFreeVirtualMemory 0x001b 0x001c 0x001d 0x001e*/
	/* NtAllocateVirtualMemory 0x0015 0x0016 0x0017 0x0018 */

	/* x86 architecture system call indexes for native */

	/* Windows 7 | Windows 8 | Windows 8.1 | Windows 10 1507 | Windows 10 1511 | Windows 10 1607 */

	/* NtClose 0x32 0x00174 0x179 0x180 0x183 0x185 */
	/* NtFreeVirtualMemory 0x0083 0x00118 0x0011c 0x00121 0x123 0x125 */
	/* NtAllocateVirtualMemory 0x0013 0x00196 0x0019b 0x001a3 1a6 1a8 */

#ifdef _WIN64
	switch (HcGlobal.WindowsVersion)
	{
	case WINDOWS_7:
		sciClose = 0xc;
		sciFreeVirtualMemory = 0x1b;
		sciAllocateVirtualMemory = 0x15;
		sciQueryVirtualMemory = 0x20;
		break;
	case WINDOWS_8:
		sciClose = 0xd;
		sciFreeVirtualMemory = 0x1c;
		sciAllocateVirtualMemory = 0x16;
		sciQueryVirtualMemory = 0x21;
		break;
	case WINDOWS_8_1:
		sciClose = 0xe;
		sciFreeVirtualMemory = 0x1d;
		sciAllocateVirtualMemory = 0x17;
		sciQueryVirtualMemory = 0x22;
		break;
	case WINDOWS_10_1507:
	case WINDOWS_10_1511:
	case WINDOWS_10_1607:
		sciClose = 0xf;
		sciFreeVirtualMemory = 0x1e;
		sciAllocateVirtualMemory = 0x18;
		sciQueryVirtualMemory = 0x23;
		break;
	}
#else
	/* Wow64 32bit */
	if (HcGlobal.IsWow64)
	{
		switch (HcGlobal.WindowsVersion)
		{
		case WINDOWS_7:
			sciClose = 0xc;
			sciFreeVirtualMemory = 0x1b;
			sciAllocateVirtualMemory = 0x15;
			sciQueryVirtualMemory = 0x20;
			break;
		case WINDOWS_8:
			sciClose = 0xd;
			sciFreeVirtualMemory = 0x1c;
			sciAllocateVirtualMemory = 0x16;
			sciQueryVirtualMemory = 0x21;
			break;
		case WINDOWS_8_1:
			sciClose = 0xe;
			sciFreeVirtualMemory = 0x1d;
			sciAllocateVirtualMemory = 0x17;
			sciQueryVirtualMemory = 0x22;
			break;
		case WINDOWS_10_1507:
		case WINDOWS_10_1511:
		case WINDOWS_10_1607:
			sciClose = 0xf;
			sciFreeVirtualMemory = 0x1e;
			sciAllocateVirtualMemory = 0x18;
			sciQueryVirtualMemory = 0x23;
			break;
		}
	}
	/* Native 32bit */
	else
	{
		/* NtClose 0x32 0x00174 0x179 0x180 0x183 0x185 */
		/* NtFreeVirtualMemory 0x0083 0x00118 0x0011c 0x00121 0x123 0x125 */
		/* NtAllocateVirtualMemory 0x0013 0x00196 0x0019b 0x001a3 1a6 1a8 */

		switch (HcGlobal.WindowsVersion)
		{
		case WINDOWS_7:
			sciClose = 0x32;
			sciFreeVirtualMemory = 0x0083;
			sciAllocateVirtualMemory = 0x0013;
			sciQueryVirtualMemory = 0x10a;
			break;
		case WINDOWS_8:
			sciClose = 0x174;
			sciFreeVirtualMemory = 0x00118;
			sciAllocateVirtualMemory = 0x00118;
			sciQueryVirtualMemory = 0x90;
			break;
		case WINDOWS_8_1:
			sciClose = 0x179;
			sciFreeVirtualMemory = 0x0011c;
			sciAllocateVirtualMemory = 0x0011c;
			sciQueryVirtualMemory = 0x93;
			break;
		case WINDOWS_10_1507:
			sciClose = 0x180;
			sciFreeVirtualMemory = 0x00121;
			sciAllocateVirtualMemory = 0x00121;
			sciQueryVirtualMemory = 0x95;
			break;
		case WINDOWS_10_1511:
			sciClose = 0x183;
			sciFreeVirtualMemory = 0x123;
			sciAllocateVirtualMemory = 0x123;
			sciQueryVirtualMemory = 0x95;
			break;
		case WINDOWS_10_1607:
			sciClose = 0x185;
			sciFreeVirtualMemory = 0x95;
			sciAllocateVirtualMemory = 0x125;
			sciQueryVirtualMemory = 0x96;
			break;
		}
	}
#endif

	return HIGHCALL_SUCCESS;
}

t_LdrLoadDll LdrLoadDll;
t_RtlEqualUnicodeString RtlEqualUnicodeString;
t_RtlInitUnicodeString RtlInitUnicodeString;

static HIGHCALL_STATUS HCAPI InitializeImports(VOID)
{
	if (!(LdrLoadDll = (t_LdrLoadDll)HcModuleProcedureAddressA(HcGlobal.HandleNtdll,
		"LdrLoadDll")))
	{
		return HIGHCALL_IMPORT_UNDEFINED;
	}

	if (!(RtlEqualUnicodeString = (t_RtlEqualUnicodeString)HcModuleProcedureAddressA(HcGlobal.HandleNtdll,
		"RtlEqualUnicodeString")))
	{
		return HIGHCALL_IMPORT_UNDEFINED;
	}

	if (!(RtlInitUnicodeString = (t_RtlInitUnicodeString)HcModuleProcedureAddressA(HcGlobal.HandleNtdll,
		"RtlInitUnicodeString")))
	{
		return HIGHCALL_IMPORT_UNDEFINED;
	}

	return HIGHCALL_SUCCESS;
}

SYS_INDEX sciQueryInformationToken,
	sciOpenProcessToken,
	sciResumeProcess,
	sciSuspendProcess,
	sciAllocateVirtualMemory,
	sciFreeVirtualMemory,
	sciResumeThread,
	sciQueryInformationThread,
	sciCreateThread,
	sciFlushInstructionCache,
	sciOpenProcess,
	sciProtectVirtualMemory,
	sciReadVirtualMemory,
	sciWriteVirtualMemory,
	sciQueryInformationProcess,
	sciQuerySystemInformation,
	sciClose,
	sciQueryVirtualMemory,
	sciAdjustPrivilegesToken,
	sciSetInformationThread,
	sciOpenDirectoryObject,
	sciCreateThreadEx,
	sciWaitForSingleObject,
	sciWaitForMultipleObjects,
	sciLockVirtualMemory,
	sciUnlockVirtualMemory;

static HIGHCALL_STATUS InitializeSyscall(VOID)
{
	if ((sciOpenProcessToken = HcSyscallIndexA("NtOpenProcessToken")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtOpenProcessToken syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciQueryInformationToken = HcSyscallIndexA("NtQueryInformationToken")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtQueryInformationToken syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}
	
	if ((sciResumeProcess = HcSyscallIndexA("NtResumeProcess")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtResumeProcess syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciSuspendProcess = HcSyscallIndexA("NtSuspendProcess")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtSuspendProcess syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciResumeThread = HcSyscallIndexA("NtResumeThread")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtResumeThread syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciQueryInformationThread = HcSyscallIndexA("NtQueryInformationThread")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtQueryInformationThread syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciCreateThread = HcSyscallIndexA("NtCreateThread")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtCreateThread syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciFlushInstructionCache = HcSyscallIndexA("NtFlushInstructionCache")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtFlushInstructionCache syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciOpenProcess = HcSyscallIndexA("NtOpenProcess")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtOpenProcess syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciProtectVirtualMemory = HcSyscallIndexA("NtProtectVirtualMemory")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtProtectVirtualMemory syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciReadVirtualMemory = HcSyscallIndexA("NtReadVirtualMemory")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtReadVirtualMemory syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciWriteVirtualMemory = HcSyscallIndexA("NtWriteVirtualMemory")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtWriteVirtualMemory syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciQueryInformationProcess = HcSyscallIndexA("NtQueryInformationProcess")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtQueryInformationProcess syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciQuerySystemInformation = HcSyscallIndexA("NtQuerySystemInformation")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtQuerySystemInformation syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciAdjustPrivilegesToken = HcSyscallIndexA("NtAdjustPrivilegesToken")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtAdjustPrivilegesToken syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciSetInformationThread = HcSyscallIndexA("NtSetInformationThread")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtSetInformationThread syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciOpenDirectoryObject = HcSyscallIndexA("NtOpenDirectoryObject")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtOpenDirectoryObject syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciCreateThreadEx = HcSyscallIndexA("NtCreateThreadEx")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtCreateThreadEx syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciWaitForSingleObject = HcSyscallIndexA("NtWaitForSingleObject")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtWaitForSingleObject syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciWaitForMultipleObjects = HcSyscallIndexA("NtWaitForMultipleObjects")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtWaitForMultipleObjects syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciUnlockVirtualMemory = HcSyscallIndexA("NtUnlockVirtualMemory")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtUnlockVirtualMemory syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	if ((sciLockVirtualMemory = HcSyscallIndexA("NtLockVirtualMemory")) == -1)
	{
		HcErrorSetNoteA("[HcSyscallIndexA returned -1] NtLockVirtualMemory syscall identifier could not be found.");
		return HIGHCALL_SYSCALL_UNDEFINED;
	}

	return HIGHCALL_SUCCESS;
}

static VOID InitializeSecurity(VOID)
{
	HANDLE hToken;

	HcGlobal.IsElevated = FALSE;

	if (NT_SUCCESS(HcOpenProcessToken(NtCurrentProcess,
		TOKEN_QUERY,
		&hToken)))
	{
		HcTokenIsElevated(hToken, &(HcGlobal.IsElevated));
	}
}

static HIGHCALL_STATUS InitializeSystem()
{
	HIGHCALL_STATUS Status;

	return Status;
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

	Status = InitializeMandatorySyscall();
	if (!HIGHCALL_ADVANCE(Status))
	{
		return Status;
	}

	/* Mandatory imports */
	Status = InitializeImports();
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

	/* Load module if not loaded */
	if (!HcGlobal.HandleUser32)
	{
		HcGlobal.HandleUser32 = HcModuleLoadA("user32.dll");
	}

	if (!HcGlobal.HandleKernel32)
	{
		HcGlobal.HandleKernel32 = HcModuleLoadA("kernel32.dll");
	}

	InitializeSecurity();

	/* Set debug privilege, convenience. */
	HcProcessSetPrivilegeW(NtCurrentProcess, SE_DEBUG_NAME, TRUE);

	return HIGHCALL_SUCCESS;
}