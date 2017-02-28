#include <highcall.h>

#include "../../public/imports.h"

DECL_EXTERN_API(DWORD, ModuleFileNameA, HANDLE hModule, LPSTR lpModuleFileName)
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

DECL_EXTERN_API(DWORD, ModuleFileNameW, HANDLE hModule, LPWSTR lpModuleFileName)
{
	PLIST_ENTRY ModuleListHead, Entry;
	PLDR_DATA_TABLE_ENTRY Module;
	ULONG Length = 0;
	ULONG_PTR Cookie = 0;

	if (!hModule)
	{
		hModule = (HANDLE)NtCurrentPeb()->ImageBaseAddress;
		if (!hModule)
		{
			return 0;
		}
	}

	LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, NULL, &Cookie);

	/* Traverse the module list */
	ModuleListHead = &NtCurrentPeb()->LoaderData->InLoadOrderModuleList;
	Entry = ModuleListHead->Flink;

	while (Entry != ModuleListHead)
	{
		Module = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		/* Check if this is the requested module */
		if (Module->ModuleBase == hModule)
		{
			Length = Module->FullModuleName.Length;

			if (Module->FullModuleName.Buffer == NULL || Length == 0)
			{
				break;
			}

			/* Copy contents */
			HcStringCopyW(lpModuleFileName, Module->FullModuleName.Buffer, Length);

			/* Break out of the loop */
			break;
		}

		/* Advance to the next entry */
		Entry = Entry->Flink;
	}

	/* Release the loader lock */
	LdrUnlockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, Cookie);

	return Length;
}

DECL_EXTERN_API(PBYTE, ModuleProcedureAddress64A, HANDLE hModule, LPCSTR lpProcedureName)
{
	PBYTE pbModule;
	PIMAGE_EXPORT_DIRECTORY pExports;
	PDWORD pExportNames;
	PDWORD pExportFunctions;
	PWORD pExportOrdinals;
	LPSTR lpCurrentFunction;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	pbModule = (PBYTE)hModule;

	pExports = HcPEGetExportDirectory(hModule);
	if (!pExports)
	{
		return 0;
	}

	/* Get the address containg null terminated export names, in ASCII */
	pExportNames = (PDWORD)(pExports->AddressOfNames + pbModule);

	/* Enumerate the exports */
	for (unsigned int i = 0; i < pExports->NumberOfFunctions; i++)
	{
		lpCurrentFunction = (LPSTR)(pExportNames[i] + pbModule);
		if (!lpCurrentFunction)
		{
			continue;
		}
		
		if (HcStringCompareContentA(lpCurrentFunction, lpProcedureName))
		{
			pExportOrdinals = (PWORD)(pExports->AddressOfNameOrdinals + pbModule);
			pExportFunctions = (PDWORD)(pExports->AddressOfFunctions + pbModule);

			return pExportFunctions[pExportOrdinals[i]] + pbModule;
		}
	}

	return 0;
}

DECL_EXTERN_API(PBYTE, ModuleProcedureAddress64W, HANDLE hModule, LPCWSTR lpProcedureName)
{
	SIZE_T Size;
	PBYTE ReturnValue;
	LPSTR lpConvertedName;

	Size = HcStringLenW(lpProcedureName);
	if (!Size)
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
		return 0;
	}

	lpConvertedName = HcStringConvertWtoA(lpProcedureName);

	ReturnValue = HcModuleProcedureAddressA(hModule, lpConvertedName);

	HcFree(lpConvertedName);
	return ReturnValue;
}

DECL_EXTERN_API(BOOLEAN, ModuleListExports, HMODULE hModule, HC_EXPORT_LIST_CALLBACK callback, LPARAM lpParam)
{
	PIMAGE_EXPORT_DIRECTORY pExports;
	PDWORD pExportNames;
	LPSTR lpCurrentFunction;
	LPBYTE lpbModule;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	lpbModule = (LPBYTE) hModule;

	pExports = HcPEGetExportDirectory(hModule);
	if (!pExports)
	{
		return FALSE;
	}

	/* Get the address containg null terminated export names, in ASCII */
	pExportNames = (PDWORD)(lpbModule + pExports->AddressOfNames);
	if (!pExportNames)
	{
		return FALSE;
	}

	/* List through functions */
	for (unsigned int i = 0; i < pExports->NumberOfNames; i++)
	{
		lpCurrentFunction = (LPSTR)(lpbModule + pExportNames[i]);
		if (!lpCurrentFunction)
		{
			continue;
		}

		if (callback(lpCurrentFunction, lpParam))
		{
			return TRUE;
		}
	}

	return TRUE;
}

DECL_EXTERN_API(HMODULE, ModuleHandle32A, LPCSTR lpModuleName)
{
	LPWSTR lpConvertedName;
	HMODULE ReturnValue;

	/* Check if the main module was requested */
	if (!lpModuleName)
	{
		/* Let the function handle the base. */
		return HcModuleHandle32W(NULL);
	}

	lpConvertedName = HcStringConvertAtoW(lpModuleName);
	if (!lpConvertedName)
	{
		return NULL;
	}

	ReturnValue = HcModuleHandle32W(lpConvertedName);

	HcFree(lpConvertedName);
	return ReturnValue;
}

DECL_EXTERN_API(HMODULE, ModuleHandle32W, LPCWSTR lpModuleName)
{
	PPEB pPeb = NtCurrentPeb();
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry;
	PLIST_ENTRY pListHead, pListEntry;
	ULONG_PTR Cookie = 0;
	HMODULE hReturn = NULL;

	/* if there is no name specified, return base address of main module */
	if (!lpModuleName)
	{
		return ((HMODULE)pPeb->ImageBaseAddress);
	}

	LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, NULL, &Cookie);

	/* Get the module list in load order */
	pListHead = &(pPeb->LoaderData->InMemoryOrderModuleList);

	/* Loop through entry list till we find a match for the module's name */
	for (pListEntry = pListHead->Flink; pListEntry != pListHead; pListEntry = pListEntry->Flink)
	{
		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pListEntry;

		/* Important note is that this is strict to the entire name */
		if (HcStringEqualW(lpModuleName, pLdrDataTableEntry->FullModuleName.Buffer, TRUE))
		{
			hReturn = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
			break;
		}
	}

	LdrUnlockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, Cookie);
	return hReturn;
}

DECL_EXTERN_API(HMODULE, ModuleHandle64A, LPCSTR lpModuleName)
{
	LPWSTR lpConvertedName;
	HMODULE ReturnValue;

	/* Check if the main module was requested */
	if (!lpModuleName)
	{
		/* Let the function handle the base. */
		return HcModuleHandle64W(NULL);
	}

	lpConvertedName = HcStringConvertAtoW(lpModuleName);
	if (!lpConvertedName)
	{
		return NULL;
	}

	ReturnValue = HcModuleHandle64W(lpConvertedName);

	HcFree(lpConvertedName);
	return ReturnValue;
}

DECL_EXTERN_API(HMODULE, ModuleHandle64W, LPCWSTR lpModuleName)
{
	PPEB pPeb = NtCurrentPeb();
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry;
	PLIST_ENTRY pListHead, pListEntry;
	ULONG_PTR Cookie = 0;
	HMODULE hReturn = NULL;

	/* if there is no name specified, return base address of main module */
	if (!lpModuleName)
	{
		return ((HMODULE)pPeb->ImageBaseAddress);
	}

	LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, NULL, &Cookie);

	/* Get the module list in load order */
	pListHead = &(pPeb->LoaderData->InMemoryOrderModuleList);

	/* Loop through entry list till we find a match for the module's name */
	for (pListEntry = pListHead->Flink; pListEntry != pListHead; pListEntry = pListEntry->Flink)
	{
		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pListEntry;

		/* Important note is that this is strict to the entire name */
		if (HcStringEqualW(lpModuleName, pLdrDataTableEntry->FullModuleName.Buffer, TRUE))
		{
			hReturn = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
			break;
		}
	}

	LdrUnlockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, Cookie);
	return hReturn;
}

#define RemoveEntryList(x) (x).Blink->Flink = (x).Flink; \
	(x).Flink->Blink = (x).Blink;

DECL_EXTERN_API(BOOLEAN, ModuleHide, CONST IN HMODULE hModule)
{
	PPEB pPeb = NtCurrentPeb();
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry;
	PLIST_ENTRY pListHead, pListEntry;
	BOOLEAN bReturn = FALSE;
	ULONG_PTR Cookie = 0;

	/* if there is no name specified, return base address of main module */
	if (!hModule)
	{
		/* we shouldn't unlink ourselves imo */
		return FALSE;
	}

	LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, NULL, &Cookie);

	/* Get the module list in load order */
	pListHead = &(pPeb->LoaderData->InInitializationOrderModuleList);

	/* Loop through entry list till we find a match for the module's name */
	for (pListEntry = pListHead->Blink; pListEntry != pListHead; pListEntry = pListEntry->Blink)
	{
		pLdrDataTableEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);

		if (pLdrDataTableEntry->ModuleBase == hModule)
		{
			HcInternalSet(pLdrDataTableEntry->FullModuleName.Buffer, 0, pLdrDataTableEntry->FullModuleName.Length);
			*(&pLdrDataTableEntry->FullModuleName.Length) = 0;
			*(&pLdrDataTableEntry->FullModuleName.MaximumLength) = 0;

			RemoveEntryList(pLdrDataTableEntry->InMemoryOrderLinks);
			RemoveEntryList(pLdrDataTableEntry->InInitializationOrderLinks);
			RemoveEntryList(pLdrDataTableEntry->InLoadOrderLinks);
			RemoveEntryList(pLdrDataTableEntry->HashLinks);

			bReturn = TRUE;
			break;
		}
	}

	LdrUnlockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, Cookie);
	return bReturn;
}

DECL_EXTERN_API(HMODULE, ModuleLoadA, LPCSTR lpPath)
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

DECL_EXTERN_API(HMODULE, ModuleLoadW, LPCWSTR lpPath)
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

DECL_EXTERN_API(BOOLEAN, ModuleUnload, HMODULE hModule)
{
	return NT_SUCCESS(LdrUnloadDll(hModule));
}
