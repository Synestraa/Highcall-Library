// Requires documentation

#include "../public/hcmodule.h"
#include "../public/hcstring.h"
#include "../public/imports.h"
#include "../public/hcpe.h"
#include "../public/hcvirtual.h"
#include "../public/hcerror.h"

HC_EXTERN_API
SIZE_T
HCAPI
HcModuleProcedureAddressA(HANDLE hModule, LPCSTR lpProcedureName)
{
	SIZE_T szModule = 0;
	PIMAGE_EXPORT_DIRECTORY pExports = NULL;
	PDWORD pExportNames = NULL;
	PDWORD pExportFunctions = NULL;
	PWORD pExportOrdinals = NULL;
	LPSTR lpCurrentFunction = NULL;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	szModule = (SIZE_T)hModule;

	pExports = HcPEGetExportDirectory(hModule);
	if (!pExports)
	{
		return 0;
	}

	/* Get the address containg null terminated export names, in ASCII */
	pExportNames = (PDWORD)(pExports->AddressOfNames + szModule);

	/* List through functions */
	for (unsigned int i = 0; i < pExports->NumberOfFunctions; i++)
	{
		lpCurrentFunction = (LPSTR)(pExportNames[i] + szModule);
		if (!lpCurrentFunction)
		{
			continue;
		}
		
		if (!strcmp(lpCurrentFunction, lpProcedureName))
		{
			/* Check for a match*/
			if (HcStringEqualA(lpCurrentFunction, lpProcedureName, TRUE))
			{
				pExportOrdinals = (PWORD)(pExports->AddressOfNameOrdinals + szModule);
				pExportFunctions = (PDWORD)(pExports->AddressOfFunctions + szModule);

				return pExportFunctions[pExportOrdinals[i]] + szModule;
			}
		}
	}

	return 0;
}

//
// Crashes. FIXME
//
HC_EXTERN_API
SIZE_T
HCAPI
HcModuleProcedureAddressW(HANDLE hModule, LPCWSTR lpProcedureName)
{
	SIZE_T Size = 0;
	SIZE_T ReturnValue = 0;
	LPSTR lpConvertedName = NULL;

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

HC_EXTERN_API
BOOLEAN 
HCAPI
HcModuleListExports(HMODULE hModule, HC_EXPORT_LIST_CALLBACK callback, LPARAM lpParam)
{
	PIMAGE_EXPORT_DIRECTORY pExports = NULL;
	PDWORD pExportNames = NULL;
	LPSTR lpCurrentFunction = NULL;
	SIZE_T dwModule = 0;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	dwModule = (SIZE_T)hModule;

	pExports = HcPEGetExportDirectory(hModule);
	if (!pExports)
	{
		return FALSE;
	}

	/* Get the address containg null terminated export names, in ASCII */
	pExportNames = (PDWORD)(pExports->AddressOfNames + dwModule);
	if (!pExportNames)
	{
		return FALSE;
	}

	/* List through functions */
	for (unsigned int i = 0; i < pExports->NumberOfNames; i++)
	{
		lpCurrentFunction = (LPSTR)(pExportNames[i] + dwModule);
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

HC_EXTERN_API
HMODULE
HCAPI
HcModuleHandleW(LPCWSTR lpModuleName)
{
	PPEB pPeb = NtCurrentPeb();
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry = NULL;
	PLIST_ENTRY pListHead = NULL, pListEntry = NULL;

	/* if there is no name specified, return base address of main module */
	if (!lpModuleName)
	{
		return ((HMODULE)pPeb->ImageBaseAddress);
	}

	/* Get the module list in load order */
	pListHead = &(pPeb->LoaderData->InMemoryOrderModuleList);

	/* Loop through entry list till we find a match for the module's name */
	for (pListEntry = pListHead->Flink; pListEntry != pListHead; pListEntry = pListEntry->Flink)
	{
		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pListEntry;

		/* Important note is that this is strict to the entire name */
		if (HcStringEqualW(lpModuleName, pLdrDataTableEntry->FullModuleName.Buffer, TRUE))
		{
			return (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
	}

	return 0;
}

HC_EXTERN_API
HMODULE
HCAPI
HcModuleHandleA(LPCSTR lpModuleName)
{
	LPWSTR lpConvertedName = NULL;
	HMODULE ReturnValue = NULL;

	/* Check if the main module was requested */
	if (!lpModuleName)
	{
		/* Let the function handle the base. */
		return HcModuleHandleW(NULL);
	}

	//
	// Otherwise convert the path.
	//

	lpConvertedName = HcStringConvertAtoW(lpModuleName);
	if (!lpConvertedName)
	{
		return NULL;
	}

	ReturnValue = HcModuleHandleW(lpConvertedName);

	HcFree(lpConvertedName);
	return ReturnValue;
}

HC_EXTERN_API
HMODULE
HCAPI
HcModuleLoadA(LPCSTR lpPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING Path = { 0 };
	LPWSTR lpConverted = NULL;
	HANDLE hModule = NULL;

	if (HcStringIsBad(lpPath))
		return NULL;

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

HC_EXTERN_API
HMODULE
HCAPI
HcModuleLoadW(LPCWSTR lpPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING Path = { 0 };
	HANDLE hModule = NULL;

	if (HcStringIsBad(lpPath))
		return NULL;

	RtlInitUnicodeString(&Path, lpPath);

	Status = LdrLoadDll(0, 0, &Path, &hModule);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return NULL;
	}

	return (HMODULE)hModule;
}
