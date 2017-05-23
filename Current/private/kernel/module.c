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
			LdrUnlockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, Cookie);
			return pLdrDataTableEntry;
		}

		pListEntry = pLdrDataTableEntry->InLoadOrderLinks.Flink;
	}

	LdrUnlockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, Cookie);
	return NULL;
}
DECL_EXTERN_API(BOOLEAN, ModuleRemoteEntry64W, CONST IN HANDLE hProcess, IN LPCWSTR lpModuleName, CONST IN BOOLEAN CaseInsensitive, PLDR_DATA_TABLE_ENTRY64 pLdrEntry)
{
	PEB64 Peb;
	LDR_DATA_TABLE_ENTRY64 LdrDataTableEntry;
	LIST_ENTRY64 ListEntry;
	ULONG64 pListHead, pListEntry;
	BOOLEAN Result = FALSE;
	LPWSTR lpBuffer = NULL;

	ZERO(&Peb);

	if (!HcProcessGetPeb64(hProcess, &Peb))
	{
		goto done;
	}

	ZERO(&LdrDataTableEntry);
	ZERO(&ListEntry);

	pListHead = (ULONG64) Peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA64, InLoadOrderModuleList);

	if (!HcProcessReadMemory64(hProcess, (PVOID64) (pListHead), &ListEntry, sizeof(ListEntry), NULL))
	{
		goto done;
	}

	pListEntry = ListEntry.Flink;

	lpBuffer = HcStringAllocW(1024);
	if (!lpBuffer)
	{
		goto done;
	}

	/* Loop through entry list till we find a match for the module's name */
	for (; pListEntry != pListHead;)
	{
		if (!HcProcessReadMemory64(hProcess, (PVOID64) pListEntry, &LdrDataTableEntry, sizeof(LdrDataTableEntry), NULL))
		{
			break;
		}

		if (!HcProcessReadMemory64(hProcess,
			(PVOID64) LdrDataTableEntry.BaseDllName.Buffer,
			lpBuffer,
			LdrDataTableEntry.BaseDllName.MaximumLength,
			NULL))
		{
			break;
		}

		/* Important note is that this is strict to the entire name */
		if (!lpModuleName || HcStringEqualW(lpModuleName, lpBuffer, CaseInsensitive))
		{
			HcInternalCopy(pLdrEntry, &LdrDataTableEntry, sizeof(LdrDataTableEntry));
			Result = TRUE;
			break;
		}

		pListEntry = LdrDataTableEntry.InLoadOrderLinks.Flink;
	}

done:
	if (lpBuffer != NULL)
	{
		HcFree(lpBuffer);
	}

	return Result;
}

DECL_EXTERN_API(BOOLEAN, ModuleEntryExW, IN HANDLE hProcess, IN HMODULE hModule OPTIONAL, OUT PLDR_DATA_TABLE_ENTRY pEntry)
{
	PEB Peb;
	PPEB_LDR_DATA LoaderData;
	PLIST_ENTRY ListHead, ListEntry;
	LDR_DATA_TABLE_ENTRY Module;

	ZERO(&Peb);

	if (!HcProcessGetPeb(hProcess, &Peb))
	{
		return FALSE;
	}

	/* If no module was provided, get base as module */
	if (hModule == NULL)
	{
		hModule = (HMODULE) Peb.ImageBaseAddress;
	}

	LoaderData = Peb.LoaderData;
	if (LoaderData == NULL)
	{
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
			HcInternalCopy(pEntry, &Module, sizeof(Module));
			return TRUE;
		}

		/* Get to next listed module */
		ListEntry = Module.InMemoryOrderLinks.Flink;
	}

	return FALSE;
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

	pExports = HcImageGetExportDirectory64(hModule);
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

	pExports = HcImageGetExportDirectory32(hModule);
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

	if (!lpModuleName)
	{
		return HcModuleHandleW(NULL);
	}

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
		return pPeb->ImageBaseAddress;
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
#ifdef _WIN64
	PTEB32 pTeb32 = (PTEB32) ((LPBYTE) NtCurrentTeb() + 0x2000);
	PPEB32 pPeb32 = POINTER32_HARDCODED(PPEB32) pTeb32->ProcessEnvironmentBlock;
	PPEB_LDR_DATA32 pLdr32 = POINTER32_HARDCODED(PPEB_LDR_DATA32) pPeb32->Ldr;
	PLIST_ENTRY32 pListHead = POINTER32_HARDCODED(PLIST_ENTRY32) &(pLdr32->InLoadOrderModuleList);
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

		pListEntry = POINTER32_HARDCODED(PLIST_ENTRY32) pListEntry->Flink;
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
	/* TODO: rewrite to avoid many of the "alerting" mechanisms of windows. 
	** TODO: rewrite to call ModuleLoadW 
	*/

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
	/* TODO: rewrite to avoid many of the "alerting" mechanisms of windows. */

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
	/* TODO: rewrite to avoid many of the "alerting" mechanisms of windows. */
	return NT_SUCCESS(LdrUnloadDll(hModule));
}

DECL_EXTERN_API(HMODULE, ModuleHandleAdvancedExW, CONST IN HANDLE ProcessHandle, IN LPCWSTR lpModuleName, IN BOOLEAN Bit32, IN BOOLEAN Bit64)
{
	MEMORY_BASIC_INFORMATION basicInfo;
	HMODULE hModule;
	SIZE_T allocationSize = 0;
	LPWSTR lpPath;
	LPWSTR lpModuleNameExtracted;
	PVOID baseAddress = NULL;
	HMODULE hReturn = NULL;
	NTSTATUS Status;

	ZERO(&basicInfo);

	Status = HcQueryVirtualMemory(
		ProcessHandle,
		baseAddress,
		MemoryBasicInformation,
		&basicInfo,
		sizeof(MEMORY_BASIC_INFORMATION),
		NULL);

	while (NT_SUCCESS(Status))
	{
		if (basicInfo.Type == MEM_IMAGE)
		{
			lpPath = HcStringAllocW(MAX_PATH);
			lpModuleNameExtracted = HcStringAllocW(MAX_PATH);

			hModule = basicInfo.AllocationBase;

			allocationSize = 0;

			/* Calculate destination of next module. */
			do
			{
				baseAddress = (PVOID) ((ULONG_PTR) baseAddress + basicInfo.RegionSize);
				allocationSize += basicInfo.RegionSize;

				Status = HcQueryVirtualMemory(ProcessHandle,
					baseAddress,
					MemoryBasicInformation,
					&basicInfo,
					sizeof(MEMORY_BASIC_INFORMATION),
					NULL);

				if (!NT_SUCCESS(Status))
				{
					break;
				}

			} while (basicInfo.AllocationBase == (PVOID) hModule);

			if (((ULONG_PTR) hModule <= USER_MAX_ADDRESS_32 && Bit32 || !Bit32) && ((ULONG64) hModule >= USER_MAX_ADDRESS_32 && Bit64 || !Bit64))
			{
				if (!lpModuleName)
				{
					/* Give us this module. */
					hReturn = hModule;
				}
				else if (HcModulePathAdvancedExW(ProcessHandle, (PVOID) hModule, lpPath))
				{
					if (HcPathGetFileW(lpPath, lpModuleNameExtracted))
					{
						if (HcStringEqualW(lpModuleName, lpModuleNameExtracted, TRUE))
						{
							hReturn = hModule;
						}
					}
				}
			}

			HcFree(lpPath);
			HcFree(lpModuleNameExtracted);

			if (hReturn)
			{
				break;
			}
		}
		else
		{
			baseAddress = (PVOID) ((ULONG_PTR) baseAddress + basicInfo.RegionSize);

			Status = HcQueryVirtualMemory(ProcessHandle,
				baseAddress,
				MemoryBasicInformation,
				&basicInfo,
				sizeof(MEMORY_BASIC_INFORMATION),
				NULL);
		}
	}

	return hReturn;
}

DECL_EXTERN_API(HMODULE, ModuleHandleAdvancedExA, CONST IN HANDLE ProcessHandle, IN LPCSTR lpModuleName, IN BOOLEAN Bit32, IN BOOLEAN Bit64)
{
	LPWSTR lpConverted;
	HMODULE hReturn = NULL;

	if (!lpModuleName)
	{
		return HcModuleHandleAdvancedExW(ProcessHandle, NULL, Bit32, Bit64);
	}

	lpConverted = HcStringConvertAtoW(lpModuleName);
	if (lpConverted)
	{
		hReturn = HcModuleHandleAdvancedExW(ProcessHandle, lpConverted, Bit32, Bit64);

		HcFree(lpConverted);
	}

	return hReturn;
}

DECL_EXTERN_API(HMODULE, ModuleHandleAdvancedW, IN LPCWSTR lpModuleName, CONST IN BOOLEAN bBit32, IN BOOLEAN bBit64)
{
	return HcModuleHandleAdvancedExW(NtCurrentProcess(), lpModuleName, bBit32, bBit64);
}

DECL_EXTERN_API(HMODULE, ModuleHandleAdvancedA, IN LPCSTR lpModuleName, CONST IN BOOLEAN bBit32, IN BOOLEAN bBit64)
{
	HMODULE hReturn = NULL;
	LPWSTR lpConverted;

	if (!lpModuleName)
	{
		return HcModuleHandleAdvancedW(NULL, bBit32, bBit64);
	}

	lpConverted = HcStringConvertAtoW(lpModuleName);
	if (!lpConverted)
	{
		return hReturn;
	}

	hReturn = HcModuleHandleAdvancedW(lpConverted, bBit32, bBit64);
	
	HcFree(lpConverted);
	return hReturn;
}

DECL_EXTERN_API(ULONG64, ModuleRemoteHandle64W, CONST IN HANDLE hProcess, IN LPCWSTR lpModuleName)
{
	ULONG64 hReturn = 0;
	PEB64 Peb;
	LDR_DATA_TABLE_ENTRY64 Entry;

	ZERO(&Entry);
	ZERO(&Peb);

	if (!lpModuleName)
	{
		HcProcessGetPeb64(hProcess, &Peb);

		hReturn = (ULONG64) Peb.ImageBaseAddress;
		return hReturn;
	}

	if (!HcModuleRemoteEntry64W(hProcess, lpModuleName, TRUE, &Entry))
	{
		return hReturn;
	}

	hReturn = (ULONG64) Entry.DllBase;

	return hReturn;
}

DECL_EXTERN_API(DWORD, ModulePathAdvancedExA, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, OUT LPSTR lpPath)
{
	LPWSTR lpTemp;
	DWORD Length = 0;

	lpTemp = HcStringAllocW(MAX_PATH);
	if (lpTemp)
	{
		Length = HcModulePathAdvancedExW(hProcess, hModule, lpTemp);
		if (Length > 0)
		{
			HcStringCopyConvertWtoA(lpTemp, lpPath, Length);
		}

		HcFree(lpTemp);
	}

	return Length;
}

DECL_EXTERN_API(DWORD, ModulePathAdvancedExW, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, OUT LPWSTR lpPath)
{
	SIZE_T tFileNameSize = 0;
	NTSTATUS Status;
	DWORD Length;
	HMODULE Module = hModule;

	struct {
		MEMORY_SECTION_NAME memSection;
		WCHAR CharBuffer[MAX_PATH];
	} SectionName;

	if (!Module)
	{
		Module = HcModuleHandleAdvancedExW(hProcess, NULL, FALSE, FALSE);
		if (!Module)
		{
			return 0;
		}
	}

	/* Query section name */
	Status = HcQueryVirtualMemory(hProcess, Module, MemoryMappedFilenameInformation,
		&SectionName, sizeof(SectionName), &tFileNameSize);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return 0;
	}

	Length = SectionName.memSection.SectionFileName.Length / sizeof(WCHAR);

	HcStringCopyW(lpPath, SectionName.memSection.SectionFileName.Buffer, Length);
	return Length;
}

DECL_EXTERN_API(DWORD, ModuleNameAdvancedExA, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, OUT LPSTR lpName)
{
	LPWSTR lpTemp;
	DWORD dwReturn = 0;
	
	lpTemp = HcStringAllocW(MAX_PATH);
	if (lpTemp)
	{
		dwReturn = HcModuleNameAdvancedExW(hProcess, hModule, lpTemp);
		if (dwReturn > 0)
		{
			HcStringCopyConvertWtoA(lpTemp, lpName, dwReturn);
		}

		HcFree(lpTemp);
	}

	return dwReturn;
}

DECL_EXTERN_API(DWORD, ModuleNameAdvancedExW, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, OUT LPWSTR lpName)
{
	SIZE_T tFileNameSize = 0;
	NTSTATUS Status;
	DWORD Length;
	HMODULE Module = hModule;

	struct {
		MEMORY_SECTION_NAME memSection;
		WCHAR CharBuffer[MAX_PATH];
	} SectionName;

	if (!Module)
	{
		Module = HcModuleHandleAdvancedExW(hProcess, NULL, FALSE, FALSE);
		if (!Module)
		{
			return 0;
		}
	}

	/* Query section name */
	Status = HcQueryVirtualMemory(hProcess, Module, MemoryMappedFilenameInformation,
		&SectionName, sizeof(SectionName), &tFileNameSize);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return 0;
	}

	Length = SectionName.memSection.SectionFileName.Length / sizeof(WCHAR);
	if (Length > 0)
	{
		HcStringCopyW(lpName, SectionName.memSection.SectionFileName.Buffer, Length);
		HcPathGetFileW(lpName, lpName);
	}

	return Length;
}

DECL_EXTERN_API(BOOLEAN, ModuleQueryInformationExW, CONST IN HANDLE hProcess, IN HMODULE hModule OPTIONAL, OUT PModuleInformationW phcModuleOut)
{
	LDR_DATA_TABLE_ENTRY Entry;
	ZERO(&Entry);

	if (HcModuleEntryExW(hProcess, hModule, &Entry))
	{
		return HcModuleConvertLdrEntryExW(hProcess, &Entry, phcModuleOut);
	}

	return FALSE;
}

DECL_EXTERN_API(BOOLEAN, ModuleEnumExW, CONST IN HANDLE hProcess, CONST IN ModuleCallbackW pCallback, IN LPARAM lParam)
{
	PEB Peb;
	PPEB_LDR_DATA LoaderData;
	PLIST_ENTRY ListHead, ListEntry;
	LDR_DATA_TABLE_ENTRY Entry;
	ModuleInformationW Module;

	ZERO(&Peb);

	if (!HcProcessGetPeb(hProcess, &Peb))
	{
		return FALSE;
	}

	/* Read loader data address from PEB */
	if (!HcProcessReadMemory(hProcess,
		&(Peb.LoaderData),
		&LoaderData,
		sizeof(LoaderData),
		NULL))
	{
		return FALSE;
	}

	if (LoaderData == NULL)
	{
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

	/* Loop on the modules */
	while (ListEntry != ListHead)
	{
		ZERO(&Module);

		/* Load module data */
		if (!HcProcessReadMemory(hProcess,
			CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
			&Entry,
			sizeof(Entry),
			NULL))
		{
			return FALSE;
		}

		HcModuleConvertLdrEntryExW(hProcess, &Entry, &Module);
		
		if (pCallback(Module, lParam))
		{
			return TRUE;
		}

		/* Get to next listed module */
		ListEntry = Entry.InMemoryOrderLinks.Flink;
	}

	return FALSE;
}

DECL_EXTERN_API(BOOLEAN, ModuleEnumAdvancedExW, CONST IN HANDLE ProcessHandle, CONST IN ModuleCallbackW pCallback, IN LPARAM lParam)
{
	MEMORY_BASIC_INFORMATION basicInfo;
	BOOLEAN bSuccess = FALSE;
	SIZE_T allocationSize = 0;
	PVOID baseAddress = NULL;
	HMODULE hModule;
	ModuleInformationW Module;
	ModuleInformationW Temp;
	NTSTATUS Status;

	ZERO(&Module);
	ZERO(&basicInfo);

	Status = HcQueryVirtualMemory(
		ProcessHandle,
		baseAddress,
		MemoryBasicInformation,
		&basicInfo,
		sizeof(MEMORY_BASIC_INFORMATION),
		NULL);

	while (NT_SUCCESS(Status))
	{
		if (basicInfo.Type == MEM_IMAGE)
		{
			ZERO(&Temp);

			hModule = basicInfo.AllocationBase;
			allocationSize = 0;

			/* Calculate destination of next module. */
			do
			{
				baseAddress = (PVOID) ((ULONG_PTR) baseAddress + basicInfo.RegionSize);
				allocationSize += basicInfo.RegionSize;

				Status = HcQueryVirtualMemory(ProcessHandle,
					baseAddress,
					MemoryBasicInformation,
					&basicInfo,
					sizeof(MEMORY_BASIC_INFORMATION),
					NULL);

				if (!NT_SUCCESS(Status))
				{
					break;
				}

			} while (basicInfo.AllocationBase == (PVOID) hModule);

			Module.Size = allocationSize;
			Module.Base = hModule;
		
			if (!HcModulePathAdvancedExW(ProcessHandle, hModule, Module.Path))
			{
				if (HcModuleQueryInformationExW(ProcessHandle, hModule, &Temp))
				{
					HcStringCopyW(Module.Path, Temp.Path, HcStringLenW(Temp.Path));
				}
			}

			if (!HcModuleNameAdvancedExW(ProcessHandle, hModule, Module.Name))
			{
				if (HcModuleQueryInformationExW(ProcessHandle, hModule, &Temp))
				{
					HcStringCopyW(Module.Name, Temp.Name, HcStringLenW(Temp.Name));
				}
			}

			if (pCallback(Module, lParam))
			{
				bSuccess = TRUE;
				break;
			}
		}
		else
		{
			baseAddress = (PVOID) ((ULONG_PTR) baseAddress + basicInfo.RegionSize);

			Status = HcQueryVirtualMemory(ProcessHandle,
				baseAddress,
				MemoryBasicInformation,
				&basicInfo,
				sizeof(MEMORY_BASIC_INFORMATION),
				NULL);
		}
	}

	return bSuccess;
}

DECL_EXTERN_API(BOOLEAN, ModuleEnumW, CONST IN ModuleCallbackW pCallback, IN LPARAM lParam)
{
	PPEB pPeb = NtCurrentPeb();
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry;
	PLIST_ENTRY pListHead, pListEntry;
	ModuleInformationW Module;
	ULONG_PTR Cookie = 0;

	LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, NULL, &Cookie);

	/* Get the module list in load order */
	pListHead = &(pPeb->LoaderData->InLoadOrderModuleList);

	/* Loop through entry list till we find a match for the module's name */
	for (pListEntry = pListHead->Flink; pListEntry != pListHead;)
	{
		ZERO(&Module);

		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY) pListEntry;

		if (HcModuleConvertLdrEntryW(pLdrDataTableEntry, &Module))
		{
			if (pCallback(Module, lParam))
			{
				LdrUnlockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, Cookie);
				return TRUE;
			}
		}

		pListEntry = pLdrDataTableEntry->InLoadOrderLinks.Flink;
	}

	LdrUnlockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, Cookie);
	return FALSE;
}

DECL_EXTERN_API(BOOLEAN, ModuleEnumAdvancedW, CONST IN ModuleCallbackW pCallback, IN LPARAM lParam)
{
	return HcModuleEnumAdvancedExW(NtCurrentProcess(), pCallback, lParam);
}

DECL_EXTERN_API(DWORD, ModulePathA, CONST IN HANDLE hModule, OUT LPSTR lpModulePath)
{
	LPWSTR lpTemp;
	DWORD Length;

	lpTemp = HcStringAllocW(MAX_PATH);
	if (lpTemp)
	{
		Length = HcModulePathW(hModule, lpTemp);
		if (Length > 0)
		{
			HcStringCopyConvertWtoA(lpTemp, lpModulePath, Length);
		}

		HcFree(lpTemp);
	}

	return Length;
}

DECL_EXTERN_API(DWORD, ModulePathW, CONST IN HANDLE hModule, OUT LPWSTR lpModulePath)
{
	PLDR_DATA_TABLE_ENTRY Module;
	ULONG Length = 0;

	Module = HcModuleEntryBaseW(hModule);
	if (Module)
	{
		Length = Module->FullModuleName.Length / sizeof(WCHAR);

		if (Module->FullModuleName.Buffer != NULL && Length > 0)
		{
			/* Copy contents */
			HcStringCopyW(lpModulePath, Module->FullModuleName.Buffer, Length);
		}
	}

	return Length;
}

DECL_EXTERN_API(DWORD, ModuleNameA, CONST IN HMODULE hModule, OUT LPSTR lpModuleName)
{
	LPWSTR lpTemp;
	DWORD Length;

	lpTemp = HcStringAllocW(MAX_PATH);
	if (lpTemp)
	{
		Length = HcModuleNameW(hModule, lpTemp);
		if (Length > 0)
		{
			HcStringCopyConvertWtoA(lpTemp, lpModuleName, Length);
		}

		HcFree(lpTemp);
	}

	return Length;
}

DECL_EXTERN_API(DWORD, ModuleNameW, CONST IN HMODULE hModule, OUT LPWSTR lpModuleName)
{
	PLDR_DATA_TABLE_ENTRY Module;
	ULONG Length = 0;

	Module = HcModuleEntryBaseW(hModule);
	if (Module)
	{
		Length = Module->BaseModuleName.Length / sizeof(WCHAR);

		if (Module->BaseModuleName.Buffer != NULL && Length > 0)
		{
			/* Copy contents */
			HcStringCopyW(lpModuleName, Module->BaseModuleName.Buffer, Length);
		}
	}

	return Length;
}


DECL_EXTERN_API(DWORD, ModulePathAdvancedA, CONST IN HMODULE hModule, OUT LPSTR lpPath)
{
	return HcModulePathAdvancedExA(NtCurrentProcess(), hModule, lpPath);
}

DECL_EXTERN_API(DWORD, ModulePathAdvancedW, CONST IN HMODULE hModule, OUT LPWSTR lpPath)
{
	return HcModulePathAdvancedExW(NtCurrentProcess(), hModule, lpPath);
}

DECL_EXTERN_API(DWORD, ModuleNameAdvancedA, CONST IN HMODULE hModule, OUT LPSTR lpName)
{
	return HcModuleNameAdvancedExA(NtCurrentProcess(), hModule, lpName);
}

DECL_EXTERN_API(DWORD, ModuleNameAdvancedW, CONST IN HMODULE hModule, OUT LPWSTR lpName)
{
	return HcModuleNameAdvancedExW(NtCurrentProcess(), hModule, lpName);
}

DECL_EXTERN_API(ULONG, ModuleChecksum, CONST IN HMODULE hModule)
{
	PLDR_DATA_TABLE_ENTRY Module;
	ULONG Checksum = 0;

	Module = HcModuleEntryBaseW(hModule);
	if (Module)
	{
		Checksum = Module->CheckSum;
	}

	return Checksum;
}

DECL_EXTERN_API(PVOID, ModuleEntryPoint, CONST IN HMODULE hModule)
{
	PLDR_DATA_TABLE_ENTRY Module;
	PVOID EntryPoint = 0;

	Module = HcModuleEntryBaseW(hModule);
	if (Module)
	{
		EntryPoint = Module->EntryPoint;
	}

	return EntryPoint;
}

DECL_EXTERN_API(ULONG, ModuleSize, CONST IN HMODULE hModule)
{
	PLDR_DATA_TABLE_ENTRY Module;
	ULONG Size = 0;

	Module = HcModuleEntryBaseW(hModule);
	if (Module)
	{
		Size = Module->SizeOfImage;
	}

	return Size;
}

DECL_EXTERN_API(BOOLEAN, ModuleConvertLdrEntryExW, CONST IN HANDLE hProcess, CONST IN PLDR_DATA_TABLE_ENTRY Module, OUT PModuleInformationW phcModuleOut)
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

DECL_EXTERN_API(BOOLEAN, ModuleConvertLdrEntryW, CONST IN PLDR_DATA_TABLE_ENTRY Module, OUT PModuleInformationW phcModuleOut)
{
	HcStringCopyW(phcModuleOut->Name, Module->BaseModuleName.Buffer, Module->BaseModuleName.Length / sizeof(WCHAR));
	HcStringCopyW(phcModuleOut->Path, Module->FullModuleName.Buffer, Module->FullModuleName.Length / sizeof(WCHAR));

	phcModuleOut->Size = Module->SizeOfImage;
	phcModuleOut->Base = Module->ModuleBase;

	return TRUE;
}