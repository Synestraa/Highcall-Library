// Requires documentation

#include "../public/hcpe.h"

HC_EXTERN_API
BOOLEAN
HCAPI
HcPEIsValid(LPVOID lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS = HcPEGetDosHeader(lpModule);
	PIMAGE_NT_HEADERS pHeaderNT = HcPEGetNtHeader(lpModule);

	return (pHeaderDOS != NULL && pHeaderNT != NULL);
}

HC_EXTERN_API
PIMAGE_DOS_HEADER
HCAPI
HcPEGetDosHeader(LPVOID lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS = (PIMAGE_DOS_HEADER)lpModule;

	if (pHeaderDOS->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	return pHeaderDOS;
}

HC_EXTERN_API
PIMAGE_NT_HEADERS
HCAPI
HcPEGetNtHeader(LPVOID lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS = HcPEGetDosHeader(lpModule);
	PIMAGE_NT_HEADERS pHeaderNT = NULL;
	
	if (!pHeaderDOS)
		return NULL;

	pHeaderNT = (PIMAGE_NT_HEADERS)(pHeaderDOS->e_lfanew + (SIZE_T)lpModule);
	if (pHeaderNT->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return pHeaderNT;
}

HC_EXTERN_API
PIMAGE_EXPORT_DIRECTORY
HCAPI
HcPEGetExportDirectory(LPVOID lpModule)
{
	PIMAGE_EXPORT_DIRECTORY lpExportDirectory = NULL;
	PIMAGE_NT_HEADERS pHeaderNT = HcPEGetNtHeader(lpModule);

	if (!pHeaderNT)
		return NULL;

	lpExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
		(pHeaderNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (SIZE_T)lpModule);

	return lpExportDirectory;
}

HC_EXTERN_API
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
