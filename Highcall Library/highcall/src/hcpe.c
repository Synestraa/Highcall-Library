/*
	@File: hcpe.c
	@Purpose: Portable Executable parsing

	@Author: Synestraa
	@version ? not specified
*/

#include "../headers/hcpe.h"

BOOLEAN
HCAPI
HcPEIsValid(LPVOID lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS;
	PIMAGE_NT_HEADERS pHeaderNT;

	pHeaderDOS = HcPEGetDosHeader(lpModule);
	pHeaderNT = HcPEGetNtHeader(lpModule);

	if (!pHeaderDOS || !pHeaderNT)
	{
		return FALSE;
	}

	return TRUE;
}

PIMAGE_DOS_HEADER
HCAPI
HcPEGetDosHeader(LPVOID lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS;

	pHeaderDOS = lpModule;
	if (pHeaderDOS->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	return pHeaderDOS;
}

PIMAGE_NT_HEADERS
HCAPI
HcPEGetNtHeader(LPVOID lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS;
	PIMAGE_NT_HEADERS pHeaderNT;
	
	pHeaderDOS = HcPEGetDosHeader(lpModule);
	if (!pHeaderDOS)
	{
		return 0;
	}

	pHeaderNT = (PIMAGE_NT_HEADERS)(pHeaderDOS->e_lfanew + (SIZE_T)lpModule);
	if (pHeaderNT->Signature != IMAGE_NT_SIGNATURE)
	{
		return 0;
	}

	return pHeaderNT;
}

PIMAGE_EXPORT_DIRECTORY
HCAPI
HcPEGetExportDirectory(LPVOID lpModule)
{
	PIMAGE_EXPORT_DIRECTORY lpExportDirectory;
	PIMAGE_NT_HEADERS pHeaderNT;

	pHeaderNT = HcPEGetNtHeader(lpModule);
	if (!pHeaderNT)
	{
		return 0;
	}

	lpExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
		(pHeaderNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (SIZE_T)lpModule);

	return lpExportDirectory;
}


DWORD
HCAPI
HcPEGetRawFromRva(PIMAGE_NT_HEADERS pImageHeader, SIZE_T RVA)
{
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pImageHeader);

	/* Search through all sections */
	for (unsigned i = 0, sections = pImageHeader->FileHeader.NumberOfSections; i < sections; i++, sectionHeader++)
	{
		/* Check if the section we hit is the one we need */
		if (sectionHeader->VirtualAddress <= RVA)
		{
			if ((sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) > RVA)
			{
				/* The section is good, calculate our offset */

				RVA -= sectionHeader->VirtualAddress;
				RVA += sectionHeader->PointerToRawData;

				return (DWORD)RVA;
			}
		}
	}
	return 0;
}
