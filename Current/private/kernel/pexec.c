#include <highcall.h>

DECL_EXTERN_API(BOOLEAN, PEIsValid, HMODULE lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS = HcPEGetDosHeader(lpModule);
	PIMAGE_NT_HEADERS pHeaderNT = HcPEGetNtHeader64(lpModule);

	return (pHeaderDOS != NULL && pHeaderNT != NULL);
}

DECL_EXTERN_API(PIMAGE_DOS_HEADER, PEGetDosHeader, HMODULE lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS = (PIMAGE_DOS_HEADER)lpModule;
	if (pHeaderDOS->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	return pHeaderDOS;
}

DECL_EXTERN_API(PIMAGE_NT_HEADERS64, PEGetNtHeader64, HMODULE lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS = HcPEGetDosHeader(lpModule);
	if (!pHeaderDOS)
	{
		return NULL;
	}

	PIMAGE_NT_HEADERS64 pHeaderNT = (PIMAGE_NT_HEADERS64) ((DWORD64) lpModule + pHeaderDOS->e_lfanew);
	if (pHeaderNT->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	return pHeaderNT;
}

DECL_EXTERN_API(PIMAGE_NT_HEADERS32, PEGetNtHeader32, HMODULE lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS = HcPEGetDosHeader(lpModule);
	if (!pHeaderDOS)
	{
		return NULL;
	}

	PIMAGE_NT_HEADERS32 pHeaderNT = (PIMAGE_NT_HEADERS32) ((DWORD32)lpModule + pHeaderDOS->e_lfanew);
	if (pHeaderNT->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	return pHeaderNT;
}

DECL_EXTERN_API(PIMAGE_EXPORT_DIRECTORY, PEGetExportDirectory32, HMODULE lpModule)
{
	PIMAGE_NT_HEADERS32 pHeaderNT = HcPEGetNtHeader32(lpModule);
	if (!pHeaderNT)
	{
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY lpExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
		(pHeaderNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (DWORD32) lpModule);

	return lpExportDirectory;
}

DECL_EXTERN_API(PIMAGE_EXPORT_DIRECTORY, PEGetExportDirectory64, HMODULE lpModule)
{
	PIMAGE_NT_HEADERS64 pHeaderNT = HcPEGetNtHeader64(lpModule);
	if (!pHeaderNT)
	{
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY lpExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
		(pHeaderNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (DWORD64)lpModule);

	return lpExportDirectory;
}

DECL_EXTERN_API(ULONG, PEOffsetFromRVA32, PIMAGE_NT_HEADERS32 pImageHeader, DWORD RVA)
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

				return RVA;
			}
		}
	}

	return 0;
}


DECL_EXTERN_API(ULONG, PEOffsetFromRVA64, PIMAGE_NT_HEADERS64 pImageHeader, ULONG RVA)
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

				return RVA;
			}
		}
	}
	return 0;
}
