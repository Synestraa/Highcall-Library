#include <highcall.h>

DECL_EXTERN_API(BOOLEAN, ImageIsValid, CONST IN HMODULE lpModule)
{
	return HcImageGetNtHeader(lpModule) != NULL;
}

DECL_EXTERN_API(PIMAGE_DOS_HEADER, ImageGetDosHeader, CONST IN HMODULE lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS = (PIMAGE_DOS_HEADER)lpModule;
	if (pHeaderDOS->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	return pHeaderDOS;
}

DECL_EXTERN_API(PIMAGE_NT_HEADERS, ImageGetNtHeader, CONST IN HMODULE lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS = HcImageGetDosHeader(lpModule);
	if (!pHeaderDOS)
	{
		return NULL;
	}

	PIMAGE_NT_HEADERS pHeaderNT = (PIMAGE_NT_HEADERS)((LPBYTE)lpModule + pHeaderDOS->e_lfanew);
	if (pHeaderNT->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	return pHeaderNT;
}

DECL_EXTERN_API(PIMAGE_NT_HEADERS64, ImageGetNtHeader64, CONST IN ULONG64 hModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS = HcImageGetDosHeader((HMODULE) hModule);
	if (!pHeaderDOS)
	{
		return NULL;
	}

	PIMAGE_NT_HEADERS64 pHeaderNT = (PIMAGE_NT_HEADERS64) (hModule + pHeaderDOS->e_lfanew);
	if (pHeaderNT->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	return pHeaderNT;
}

DECL_EXTERN_API(PIMAGE_NT_HEADERS32, ImageGetNtHeader32, CONST IN ULONG_PTR hModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS = HcImageGetDosHeader((HMODULE)hModule);
	if (!pHeaderDOS)
	{
		return NULL;
	}

	PIMAGE_NT_HEADERS32 pHeaderNT = (PIMAGE_NT_HEADERS32) (hModule + pHeaderDOS->e_lfanew);
	if (pHeaderNT->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	return pHeaderNT;
}

DECL_EXTERN_API(PIMAGE_EXPORT_DIRECTORY, ImageGetExportDirectory, CONST IN HMODULE hModule)
{
	PIMAGE_NT_HEADERS pHeaderNT = HcImageGetNtHeader(hModule);
	if (!pHeaderNT)
	{
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY lpExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
		(pHeaderNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR) hModule);

	return lpExportDirectory;
}

DECL_EXTERN_API(PIMAGE_EXPORT_DIRECTORY, ImageGetExportDirectory32, CONST IN ULONG_PTR hModule)
{
	PIMAGE_NT_HEADERS32 pHeaderNT = HcImageGetNtHeader32(hModule);
	if (!pHeaderNT)
	{
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY lpExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
		(pHeaderNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + hModule);

	return lpExportDirectory;
}

DECL_EXTERN_API(PIMAGE_EXPORT_DIRECTORY, ImageGetExportDirectory64, CONST IN ULONG64 hModule)
{
	PIMAGE_NT_HEADERS64 pHeaderNT = HcImageGetNtHeader64(hModule);
	if (!pHeaderNT)
	{
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY lpExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
		(pHeaderNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + hModule);

	return lpExportDirectory;
}

DECL_EXTERN_API(ULONG, ImageOffsetFromRVA, IN PIMAGE_NT_HEADERS pImageHeader, IN DWORD RVA)
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

DECL_EXTERN_API(ULONG, ImageOffsetFromRVA32, IN PIMAGE_NT_HEADERS32 pImageHeader, IN DWORD RVA)
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


DECL_EXTERN_API(ULONG, ImageOffsetFromRVA64, IN PIMAGE_NT_HEADERS64 pImageHeader, IN DWORD RVA)
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

DECL_EXTERN_API(PIMAGE_SECTION_HEADER, ImageRvaToSection, IN HMODULE hModule, IN ULONG Rva)
{
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_SECTION_HEADER Section;
	ULONG Va;
	ULONG Count;

	NtHeader = HcImageGetNtHeader(hModule);
	if (!NtHeader)
	{
		return NULL;
	}

	Count = SWAPW(NtHeader->FileHeader.NumberOfSections);
	if (!Count)
	{
		return NULL;
	}

	Section = IMAGE_FIRST_SECTION(NtHeader);

	while (Count--)
	{
		Va = SWAPD(Section->VirtualAddress);
		if (Va <= Rva && (Rva < Va + SWAPD(Section->SizeOfRawData)))
		{
			return Section;
		}

		Section++;
	}

	return NULL;
}

DECL_EXTERN_API(LPVOID, ImageRvaToVa, IN HMODULE hModule, IN ULONG Rva)
{
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_SECTION_HEADER Section = NULL;

	NtHeader = HcImageGetNtHeader(hModule);
	if (NtHeader == NULL)
	{
		return NULL;
	}

	if ((Section == NULL) ||
		(Rva < SWAPD(Section->VirtualAddress)) ||
		(Rva >= SWAPD(Section->VirtualAddress) + SWAPD(Section->SizeOfRawData)))
	{
		Section = HcImageRvaToSection(hModule, Rva);
		if (Section == NULL)
		{
			return NULL;
		}
	}

	return (PVOID) ((ULONG_PTR) hModule + Rva +
		(ULONG_PTR) SWAPD(Section->PointerToRawData) -
		(ULONG_PTR) SWAPD(Section->VirtualAddress));
}

DECL_EXTERN_API(ULONG, ImageVaToRva, IN HMODULE hModule, IN LPCVOID lpAddress)
{
	return SUBTRACT_PTR_32(lpAddress, hModule);
}