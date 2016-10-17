/*
	@File: hcmodule.c
	@Purpose: Retrieving information about modules.

	@Author: Synestraa
	@version 9/11/2016
*/

#include "../headers/hcmodule.h"
#include "../headers/hcstring.h"
#include "../headers/hcimport.h"
#include "../headers/hcpe.h"
#include "../headers/hcvirtual.h"
#include "../headers/hcerror.h"


SIZE_T
HCAPI
HcModuleProcedureAddressA(HANDLE hModule, LPCSTR lpProcedureName)
{
	SIZE_T szModule;
	PIMAGE_EXPORT_DIRECTORY pExports;
	PDWORD pExportNames;
	PDWORD pExportFunctions;
	PWORD pExportOrdinals;
	LPCSTR lpCurrentFunction;

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
		lpCurrentFunction = (LPCSTR)(pExportNames[i] + szModule);
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


SIZE_T
HCAPI
HcModuleProcedureAddressW(HANDLE hModule, LPCWSTR lpProcedureName)
{
	DWORD Size;
	SIZE_T ReturnValue;
	LPSTR lpConvertedName;

	Size = HcStringSecureLengthW(lpProcedureName);
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

BOOLEAN 
HCAPI
HcModuleListExports(HMODULE hModule, HC_EXPORT_LIST_CALLBACK callback, LPARAM lpParam)
{
	PIMAGE_EXPORT_DIRECTORY pExports;
	PDWORD pExportNames;
	LPCSTR lpCurrentFunction;
	SIZE_T dwModule;

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
		lpCurrentFunction = (LPCSTR)(pExportNames[i] + dwModule);
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


HMODULE
HCAPI
HcModuleHandleW(LPCWSTR lpModuleName)
{
	PPEB pPeb = NtCurrentPeb();
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry;
	PLIST_ENTRY pListHead, pListEntry;

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


HMODULE
HCAPI
HcModuleHandleA(LPCSTR lpModuleName)
{
	LPWSTR lpConvertedName;
	HMODULE ReturnValue;

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


HMODULE
HCAPI
HcModuleLoadA(LPCSTR lpPath)
{
	NTSTATUS Status;
	UNICODE_STRING Path;
	LPWSTR lpConverted;
	HANDLE hModule = NULL;

	if (HcStringIsBad(lpPath))
	{
		return NULL;
	}

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

HMODULE
HCAPI
HcModuleLoadW(LPCWSTR lpPath)
{
	NTSTATUS Status;
	UNICODE_STRING Path;
	HANDLE hModule;

	if (HcStringIsBad(lpPath))
	{
		return NULL;
	}

	RtlInitUnicodeString(&Path, lpPath);

	Status = LdrLoadDll(0, 0, &Path, &hModule);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return NULL;
	}

	return (HMODULE)hModule;
}
