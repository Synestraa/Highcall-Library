#include <highcall.h>

HC_EXTERN_API
BOOLEAN
HCAPI
HcPEIsValid(HMODULE lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS = HcPEGetDosHeader(lpModule);
	PIMAGE_NT_HEADERS pHeaderNT = HcPEGetNtHeader(lpModule);

	return (pHeaderDOS != NULL && pHeaderNT != NULL);
}

HC_EXTERN_API
PIMAGE_DOS_HEADER
HCAPI
HcPEGetDosHeader(HMODULE lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS = (PIMAGE_DOS_HEADER)lpModule;
	if (pHeaderDOS->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	return pHeaderDOS;
}

HC_EXTERN_API
PIMAGE_NT_HEADERS
HCAPI
HcPEGetNtHeader(HMODULE lpModule)
{
	PIMAGE_NT_HEADERS pHeaderNT;
	PIMAGE_DOS_HEADER pHeaderDOS = HcPEGetDosHeader(lpModule);
	
	if (!pHeaderDOS)
	{
		return NULL;
	}

	pHeaderNT = (PIMAGE_NT_HEADERS)((LPBYTE) lpModule + pHeaderDOS->e_lfanew);
	if (pHeaderNT->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	return pHeaderNT;
}

HC_EXTERN_API
PIMAGE_EXPORT_DIRECTORY
HCAPI
HcPEGetExportDirectory(HMODULE lpModule)
{
	PIMAGE_EXPORT_DIRECTORY lpExportDirectory;
	PIMAGE_NT_HEADERS pHeaderNT = HcPEGetNtHeader(lpModule);

	if (!pHeaderNT)
	{
		return NULL;
	}

	lpExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
		(pHeaderNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (LPBYTE) lpModule);

	return lpExportDirectory;
}

HC_EXTERN_API
ULONG
HCAPI
HcPEOffsetFromRVA(PIMAGE_NT_HEADERS pImageHeader, PBYTE RVA)
{
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pImageHeader);
	ULONG TruncatedRVA = (ULONG)(ULONG_PTR)RVA;

	/* Search through all sections */
	for (unsigned i = 0, sections = pImageHeader->FileHeader.NumberOfSections; i < sections; i++, sectionHeader++)
	{
		/* Check if the section we hit is the one we need */
		if (sectionHeader->VirtualAddress <= TruncatedRVA)
		{
			if ((sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) > TruncatedRVA)
			{
				/* The section is good, calculate our offset */

				TruncatedRVA -= sectionHeader->VirtualAddress;
				TruncatedRVA += sectionHeader->PointerToRawData;

				return TruncatedRVA;
			}
		}
	}
	return 0;
}
