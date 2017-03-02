#include <highcall.h>

#include "../../public/imports.h"

DECL_EXTERN_API(PLDR_DATA_TABLE_ENTRY, ModuleEntryW, IN LPCWSTR lpModuleName, CONST IN BOOLEAN CaseInSensitive)
{
	PPEB pPeb = NtCurrentPeb();
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry;
	PLIST_ENTRY pListHead, pListEntry;
	ULONG_PTR Cookie = 0;

	LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, NULL, &Cookie);

	/* Get the module list in load order */
	pListHead = &(pPeb->LoaderData->InLoadOrderModuleList);

	/* Loop through entry list till we find a match for the module's name */
	for (pListEntry = pListHead->Flink; pListEntry != pListHead;)
	{
		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pListEntry;

		/* Important note is that this is strict to the entire name */
		if (!lpModuleName || HcStringEqualW(lpModuleName, pLdrDataTableEntry->BaseModuleName.Buffer, CaseInSensitive))
		{
			return pLdrDataTableEntry;
		}

		pListEntry = pLdrDataTableEntry->InLoadOrderLinks.Flink;
	}

	LdrUnlockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, Cookie);
	return NULL;
}

DECL_EXTERN_API(PLDR_DATA_TABLE_ENTRY, ModuleEntryBaseW, CONST IN HMODULE hModule)
{
	PPEB pPeb = NtCurrentPeb();
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry;
	PLIST_ENTRY pListHead, pListEntry;
	ULONG_PTR Cookie = 0;

	LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, NULL, &Cookie);

	/* Get the module list in load order */
	pListHead = &(pPeb->LoaderData->InLoadOrderModuleList);

	/* Loop through entry list till we find a match for the module's name */
	for (pListEntry = pListHead->Flink; pListEntry != pListHead;)
	{
		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pListEntry;

		/* Important note is that this is strict to the entire name */
		if (!hModule || pLdrDataTableEntry->ModuleBase == hModule)
		{
			return pLdrDataTableEntry;
		}

		pListEntry = pLdrDataTableEntry->InLoadOrderLinks.Flink;
	}

	LdrUnlockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, Cookie);
	return NULL;
}

DECL_EXTERN_API(DWORD, ModuleFileNameA, CONST IN HANDLE hModule, OUT LPSTR lpModuleFileName)
{
	LPWSTR lpTemp = HcStringAllocW(MAX_PATH);
	DWORD Length;

	Length = HcModuleFileNameW(hModule, lpTemp);
	if (Length > 0)
	{
		HcStringCopyConvertWtoA(lpTemp, lpModuleFileName, Length);
	}

	HcFree(lpTemp);
	return Length;
}

DECL_EXTERN_API(DWORD, ModuleFileNameW, CONST IN HANDLE hModule, OUT LPWSTR lpModuleFileName)
{
	PLDR_DATA_TABLE_ENTRY Module;
	ULONG Length = 0;

	Module = HcModuleEntryBaseW(hModule);
	if (Module)
	{
		Length = Module->FullModuleName.Length;

		if (Module->FullModuleName.Buffer != NULL && Length > 0)
		{
			/* Copy contents */
			HcStringCopyW(lpModuleFileName, Module->FullModuleName.Buffer, Length);
		}
	}

	return Length;
}


DECL_EXTERN_API(DWORD, ModuleNameA, CONST IN HMODULE hModule, OUT LPSTR lpModuleFileName);
DECL_EXTERN_API(DWORD, ModuleNameW, CONST IN HMODULE hModule, OUT LPWSTR lpModuleFileName);
DECL_EXTERN_API(ULONG_PTR, ModuleChecksum, CONST IN HMODULE hModule);
DECL_EXTERN_API(ULONG_PTR, ModuleEntryPoint, CONST IN HMODULE hModule);
DECL_EXTERN_API(ULONG_PTR, ModuleSize, CONST IN HMODULE hModule);

DECL_EXTERN_API(ULONG64, ModuleProcedureAddress64A, CONST IN ULONG64 hModule, IN LPCSTR lpProcedureName)
{
	PIMAGE_EXPORT_DIRECTORY pExports;
	PDWORD pExportNames;
	PDWORD pExportFunctions;
	PWORD pExportOrdinals;
	LPSTR lpCurrentFunction;

	if (!hModule)
	{
		/* we don't accept null handles in this version of the function. */
		return 0;
	}

	pExports = HcPEGetExportDirectory64(hModule);
	if (!pExports)
	{
		return 0;
	}

	/* Get the address containg null terminated export names, in ASCII */
	pExportNames = (PDWORD)(pExports->AddressOfNames + hModule);

	/* Enumerate the exports */
	for (unsigned int i = 0; i < pExports->NumberOfFunctions; i++)
	{
		lpCurrentFunction = (LPSTR)(pExportNames[i] + hModule);
		if (!lpCurrentFunction)
		{
			continue;
		}
		
		if (HcStringCompareA(lpCurrentFunction, lpProcedureName))
		{
			pExportOrdinals = (PWORD)(pExports->AddressOfNameOrdinals + hModule);
			pExportFunctions = (PDWORD)(pExports->AddressOfFunctions + hModule);

			return (ULONG64) (pExportFunctions[pExportOrdinals[i]] + hModule);
		}
	}

	return 0;
}

DECL_EXTERN_API(ULONG64, ModuleProcedureAddress64W, CONST IN ULONG64 hModule, IN LPCWSTR lpProcedureName)
{
	ULONG64 ReturnValue = 0;
	LPSTR lpConvertedName;

	lpConvertedName = HcStringConvertWtoA(lpProcedureName);
	if (lpConvertedName)
	{
		ReturnValue = HcModuleProcedureAddress64A(hModule, lpConvertedName);
		HcFree(lpConvertedName);
	}

	return ReturnValue;
}

DECL_EXTERN_API(ULONG_PTR, ModuleProcedureAddress32A, CONST IN ULONG_PTR hModule, IN LPCSTR lpProcedureName)
{
	PIMAGE_EXPORT_DIRECTORY pExports;
	PDWORD pExportNames;
	PDWORD pExportFunctions;
	PWORD pExportOrdinals;
	LPSTR lpCurrentFunction;

	if (!hModule)
	{
		/* we don't accept null handles in this version of the function. */
		return 0;
	}

	pExports = HcPEGetExportDirectory32(hModule);
	if (!pExports)
	{
		return 0;
	}

	/* Get the address containg null terminated export names, in ASCII */
	pExportNames = (PDWORD)(pExports->AddressOfNames + hModule);

	/* Enumerate the exports */
	for (unsigned int i = 0; i < pExports->NumberOfFunctions; i++)
	{
		lpCurrentFunction = (LPSTR)(pExportNames[i] + hModule);
		if (!lpCurrentFunction)
		{
			continue;
		}

		if (HcStringEqualA(lpCurrentFunction, lpProcedureName, TRUE))
		{
			pExportOrdinals = (PWORD)(pExports->AddressOfNameOrdinals + hModule);
			pExportFunctions = (PDWORD)(pExports->AddressOfFunctions + hModule);

			return (ULONG_PTR) (pExportFunctions[pExportOrdinals[i]] + hModule);
		}
	}

	return 0;
}

DECL_EXTERN_API(ULONG_PTR, ModuleProcedureAddress32W, CONST IN ULONG_PTR hModule, IN LPCWSTR lpProcedureName)
{
	ULONG_PTR ReturnValue = 0;
	LPSTR lpConvertedName;

	lpConvertedName = HcStringConvertWtoA(lpProcedureName);
	if (lpConvertedName)
	{
		ReturnValue = HcModuleProcedureAddress32A(hModule, lpConvertedName);
		HcFree(lpConvertedName);
	}

	return ReturnValue;
}

DECL_EXTERN_API(HMODULE, ModuleHandleA, IN LPCSTR lpModuleName)
{
	LPWSTR lpConvertedName;
	HMODULE hReturn = NULL;

	lpConvertedName = HcStringConvertAtoW(lpModuleName);
	if (lpConvertedName)
	{
		hReturn = HcModuleHandleW(lpConvertedName);
		HcFree(lpConvertedName);
	}

	return hReturn;
}

DECL_EXTERN_API(HMODULE, ModuleHandleW, IN LPCWSTR lpModuleName)
{
	return HcModuleHandleExW(lpModuleName, TRUE);
}

DECL_EXTERN_API(HMODULE, ModuleHandleExW, IN LPCWSTR lpModuleName, CONST IN BOOLEAN CaseInSensitive)
{
	PPEB pPeb = NtCurrentPeb();
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry;

	/* if there is no name specified, return base address of main module */
	if (!lpModuleName)
	{
		return (HMODULE)pPeb->ImageBaseAddress;
	}

	pLdrDataTableEntry = HcModuleEntryW(lpModuleName, CaseInSensitive);
	if (!pLdrDataTableEntry)
	{
		return NULL;
	}

	return pLdrDataTableEntry->ModuleBase;
}

DECL_EXTERN_API(HMODULE, ModuleHandleWow64W, IN LPCWSTR lpModuleName)
{
	HMODULE hReturn = NULL;
#ifndef _WIN64
	PTEB32 pTeb32 = (PTEB32) (LPBYTE) NtCurrentTeb() + 0x2000;
	PPEB32 pPeb32 = POINTER32_HARDCODED(PPEB32) pTeb32->ProcessEnvironmentBlock;
	PPEB_LDR_DATA32 pLdr32 = POINTER32_HARDCODED(PPEB_LDR_DATA32) pPeb32->Ldr;
	PLIST_ENTRY32 pListHead = POINTER32_HARDCODED(PLIST_ENTRY32) &pLdr32->InLoadOrderModuleList;
	PLIST_ENTRY32 pListEntry = POINTER32_HARDCODED(PLIST_ENTRY32) pListHead->Flink;
	PLDR_DATA_TABLE_ENTRY32 pLdrDataTableEntry;

	/* Loop through entry list till we find a match for the module's name */
	for (; pListEntry != pListHead; )
	{
		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY32)pListEntry;

		/* Important note is that this is strict to the entire name */
		if (HcStringEqualW(lpModuleName, POINTER32_HARDCODED(LPWSTR) pLdrDataTableEntry->BaseDllName.Buffer, TRUE))
		{
			hReturn = POINTER32_HARDCODED(HMODULE) pLdrDataTableEntry->DllBase;
			break;
		}

		pListEntry = POINTER32_HARDCODED(PLIST_ENTRY32) pLdrDataTableEntry->InLoadOrderLinks.Flink;
	}
#endif

	return hReturn;
}

#define RemoveEntryList(x) (x).Blink->Flink = (x).Flink; \
	(x).Flink->Blink = (x).Blink;

DECL_EXTERN_API(BOOLEAN, ModuleHide, CONST IN HMODULE hModule)
{
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry;
	BOOLEAN bReturn = FALSE;

	pLdrDataTableEntry = HcModuleEntryBaseW(hModule);
	if (pLdrDataTableEntry)
	{
		HcInternalSet(pLdrDataTableEntry->FullModuleName.Buffer, 0, pLdrDataTableEntry->FullModuleName.Length);
		*(&pLdrDataTableEntry->FullModuleName.Length) = 0;
		*(&pLdrDataTableEntry->FullModuleName.MaximumLength) = 0;

		RemoveEntryList(pLdrDataTableEntry->InMemoryOrderLinks);
		RemoveEntryList(pLdrDataTableEntry->InInitializationOrderLinks);
		RemoveEntryList(pLdrDataTableEntry->InLoadOrderLinks);
		RemoveEntryList(pLdrDataTableEntry->HashLinks);

		bReturn = TRUE;
	}

	return bReturn;
}

DECL_EXTERN_API(HMODULE, ModuleLoadA, IN LPCSTR lpPath)
{
	NTSTATUS Status;
	UNICODE_STRING Path;
	LPWSTR lpConverted;
	HANDLE hModule = NULL;

	lpConverted = HcStringConvertAtoW(lpPath);
	if (!lpConverted)
	{
		return NULL;
	}

	RtlInitUnicodeString(&Path, lpConverted);

 	Status = LdrLoadDll(0, 0, &Path, &hModule);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		HcFree(lpConverted);

		return NULL;
	}

	HcFree(lpConverted);
	return (HMODULE)hModule;
}

DECL_EXTERN_API(HMODULE, ModuleLoadW, IN LPCWSTR lpPath)
{
	NTSTATUS Status;
	UNICODE_STRING Path;
	HANDLE hModule = NULL;

	RtlInitUnicodeString(&Path, lpPath);

	Status = LdrLoadDll(0, 0, &Path, &hModule);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return NULL;
	}

	return (HMODULE)hModule;
}

DECL_EXTERN_API(BOOLEAN, ModuleUnload, CONST IN HMODULE hModule)
{
	/* TODO: rewrite to avoi dmany of the "alerting" mechanisms of windows. */
	return NT_SUCCESS(LdrUnloadDll(hModule));
}

DECL_EXTERN_API(HMODULE, ModuleHandleAdv32W, IN LPCWSTR lpModuleName)
{
	return HcProcessGetModuleHandleByNameAdvW(NtCurrentProcess, lpModuleName, TRUE);
}

DECL_EXTERN_API(HMODULE, ModuleHandleAdv32A, IN LPCSTR lpModuleName)
{
	HMODULE hReturn = NULL;
	LPWSTR lpConverted;

	lpConverted = HcStringConvertAtoW(lpModuleName);
	if (!lpConverted)
	{
		return hReturn;
	}

	hReturn = HcModuleHandleAdv32W(lpConverted);

	HcFree(lpConverted);
	return hReturn;
}

DECL_EXTERN_API(HMODULE, ModuleHandleAdvW, IN LPCWSTR lpModuleName, CONST IN BOOLEAN bBit32)
{
	return HcProcessGetModuleHandleByNameAdvW(NtCurrentProcess, lpModuleName, bBit32);
}

DECL_EXTERN_API(HMODULE, ModuleHandleAdvA, IN LPCSTR lpModuleName, CONST IN BOOLEAN bBit32)
{
	HMODULE hReturn = NULL;
	LPWSTR lpConverted;

	lpConverted = HcStringConvertAtoW(lpModuleName);
	if (!lpConverted)
	{
		return hReturn;
	}

	hReturn = HcModuleHandleAdvW(lpConverted, bBit32);
	
	HcFree(lpConverted);
	return hReturn;
}