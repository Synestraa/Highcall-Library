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

DECL_EXTERN_API(BOOLEAN, ImageRemoteSectionByNameA, IN HANDLE hProcess, OUT PIMAGE_SECTION_HEADER Section, IN HMODULE hModule, IN LPSTR lpSection)
{
	IMAGE_DOS_HEADER DosHeader;
	PIMAGE_SECTION_HEADER Sections;
	PIMAGE_SECTION_HEADER CurrentSection;
	PIMAGE_NT_HEADERS NtHeader;
	IMAGE_NT_HEADERS NtCopiedHeader;
	BOOLEAN Success = FALSE;
	DWORD SectionCount = 0;

	ZERO(&NtCopiedHeader);
	ZERO(&DosHeader);

	if (!HcImageRemoteDosHeaderFromModule(hProcess, hModule, &DosHeader))
	{
		goto done;
	}

	NtHeader = (PIMAGE_NT_HEADERS) ((ULONG_PTR) hModule + DosHeader.e_lfanew);

	if (!HcProcessReadMemory(hProcess, NtHeader, &NtCopiedHeader, sizeof(NtCopiedHeader), NULL))
	{
		goto done;
	}

	if (NtCopiedHeader.Signature != IMAGE_NT_SIGNATURE)
	{
		goto done;
	}

	SectionCount = NtCopiedHeader.FileHeader.NumberOfSections;
	if (!SectionCount)
	{
		goto done;
	}

	Sections = HcAlloc(sizeof(IMAGE_SECTION_HEADER) * SectionCount);
	if (!Sections)
	{
		goto done;
	}

	if (!HcProcessReadMemory(hProcess,
		NtHeader + 1,
		Sections,
		sizeof(IMAGE_SECTION_HEADER) * SectionCount,
		NULL))
	{
		goto done;
	}

	CurrentSection = Sections;

	for (DWORD i = 0; i < SectionCount; i++, CurrentSection++)
	{
		if (!HcStringIsBad(CurrentSection->Name) && HcStringEqualA(CurrentSection->Name, lpSection, TRUE))
		{
			HcInternalCopy(Section, CurrentSection, sizeof(IMAGE_SECTION_HEADER));
			Success = TRUE;
			goto done;
		}
	}

	if (Sections != NULL)
	{
		HcFree(Sections);
	}

done:
	return Success;
}

DECL_EXTERN_API(BOOLEAN, ImageSectionByNameA, OUT PIMAGE_SECTION_HEADER Section, IN PIMAGE_NT_HEADERS pImageHeader, IN LPSTR lpSection)
{
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pImageHeader);

	/* Search through all sections */
	for (unsigned i = 0, sections = pImageHeader->FileHeader.NumberOfSections; i < sections; i++, sectionHeader++)
	{
		if (!HcStringIsBad(sectionHeader->Name) && HcStringEqualA(sectionHeader->Name, lpSection, TRUE))
		{
			HcInternalCopy(Section, sectionHeader, sizeof(IMAGE_SECTION_HEADER));
			return TRUE;
		}
	}

	return FALSE;
}

DECL_EXTERN_API(BOOLEAN, ImageSectionByName32A, OUT PIMAGE_SECTION_HEADER Section, IN PIMAGE_NT_HEADERS32 pImageHeader, IN LPSTR lpSection)
{
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pImageHeader);

	/* Search through all sections */
	for (unsigned i = 0, sections = pImageHeader->FileHeader.NumberOfSections; i < sections; i++, sectionHeader++)
	{
		if (!HcStringIsBad(sectionHeader->Name) && HcStringEqualA(sectionHeader->Name, lpSection, TRUE))
		{
			HcInternalCopy(Section, sectionHeader, sizeof(IMAGE_SECTION_HEADER));
			return TRUE;
		}
	}

	return FALSE;
}

DECL_EXTERN_API(BOOLEAN, ImageSectionByName64A, OUT PIMAGE_SECTION_HEADER Section, IN PIMAGE_NT_HEADERS64 pImageHeader, IN LPSTR lpSection)
{
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pImageHeader);

	/* Search through all sections */
	for (unsigned i = 0, sections = pImageHeader->FileHeader.NumberOfSections; i < sections; i++, sectionHeader++)
	{
		if (!HcStringIsBad(sectionHeader->Name) && HcStringEqualA(sectionHeader->Name, lpSection, TRUE))
		{
			HcInternalCopy(Section, sectionHeader, sizeof(IMAGE_SECTION_HEADER));
			return TRUE;
		}
	}

	return FALSE;
}

DECL_EXTERN_API(ULONG, ImageOffset, IN PIMAGE_SECTION_HEADER pSection, IN DWORD RVA)
{
	/* Check if the section we hit is the one we need */
	if (pSection->VirtualAddress <= RVA)
	{
		if ((pSection->VirtualAddress + pSection->Misc.VirtualSize) > RVA)
		{
			RVA -= pSection->VirtualAddress;
			RVA += pSection->PointerToRawData;

			return RVA;
		}
	}

	return 0;
}

DECL_EXTERN_API(ULONG, ImageOffsetFromRVA, IN PIMAGE_NT_HEADERS pImageHeader, IN DWORD RVA)
{
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pImageHeader);
	DWORD Result;

	/* Search through all sections */
	for (unsigned i = 0, sections = pImageHeader->FileHeader.NumberOfSections; i < sections; i++, sectionHeader++)
	{
		Result = HcImageOffset(sectionHeader, RVA);
		if (Result)
		{
			return Result;
		}
	}

	return 0;
}

DECL_EXTERN_API(ULONG, ImageOffsetFromRVA32, IN PIMAGE_NT_HEADERS32 pImageHeader, IN DWORD RVA)
{
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pImageHeader);
	DWORD Result;

	/* Search through all sections */
	for (unsigned i = 0, sections = pImageHeader->FileHeader.NumberOfSections; i < sections; i++, sectionHeader++)
	{
		Result = HcImageOffset(sectionHeader, RVA);
		if (Result)
		{
			return Result;
		}
	}

	return 0;
}


DECL_EXTERN_API(ULONG, ImageOffsetFromRVA64, IN PIMAGE_NT_HEADERS64 pImageHeader, IN DWORD RVA)
{
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pImageHeader);
	DWORD Result;

	/* Search through all sections */
	for (unsigned i = 0, sections = pImageHeader->FileHeader.NumberOfSections; i < sections; i++, sectionHeader++)
	{
		Result = HcImageOffset(sectionHeader, RVA);
		if (Result)
		{
			return Result;
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

DECL_EXTERN_API(BOOLEAN, ImageRemoteDosHeaderFromModule64, IN HANDLE hProcess, IN ULONG64 hModule, IN PIMAGE_DOS_HEADER pDosHeader)
{
	if (!HcProcessReadMemory64(hProcess, (PVOID64) hModule, pDosHeader, sizeof(*pDosHeader), NULL))
	{
		return FALSE;
	}

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ImageRemoteNtHeadersFromModule64, IN HANDLE hProcess, IN ULONG64 hModule, IN PIMAGE_NT_HEADERS64 pNtHeaders)
{
	IMAGE_DOS_HEADER Header;
	ZERO(&Header);

	if (!HcImageRemoteDosHeaderFromModule64(hProcess, hModule, &Header))
	{
		return FALSE;
	}

	if (!HcProcessReadMemory64(hProcess, (PVOID64) (hModule + Header.e_lfanew), pNtHeaders, sizeof(*pNtHeaders), NULL))
	{
		return FALSE;
	}

	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ImageRemoteExportDirectoryFromModule64, IN HANDLE hProcess, IN ULONG64 hModule, IN PIMAGE_EXPORT_DIRECTORY pExportDirectory)
{
	IMAGE_NT_HEADERS64 Header;
	ZERO(&Header);

	if (!HcImageRemoteNtHeadersFromModule64(hProcess, hModule, &Header))
	{
		return FALSE;
	}

	if (!HcProcessReadMemory64(
		hProcess,
		(PVOID64) (hModule + Header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress),
		pExportDirectory,
		sizeof(*pExportDirectory),
		NULL))
	{
		return FALSE;
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ImageRemoteDosHeaderFromModule, IN HANDLE hProcess, IN HMODULE hModule, IN PIMAGE_DOS_HEADER pDosHeader)
{
	if (!HcProcessReadMemory(hProcess, hModule, pDosHeader, sizeof(*pDosHeader), NULL))
	{
		return FALSE;
	}

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ImageRemoteNtHeadersFromModule32, IN HANDLE hProcess, IN HMODULE hModule, IN PIMAGE_NT_HEADERS32 pNtHeaders)
{
	IMAGE_DOS_HEADER Header;
	ZERO(&Header);

	if (!HcImageRemoteDosHeaderFromModule(hProcess, hModule, &Header))
	{
		return FALSE;
	}

	if (!HcProcessReadMemory(hProcess, (PVOID) ((ULONG_PTR) hModule + Header.e_lfanew), pNtHeaders, sizeof(*pNtHeaders), NULL))
	{
		return FALSE;
	}

	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ImageRemoteExportDirectoryFromModule32, IN HANDLE hProcess, IN HMODULE hModule, IN PIMAGE_EXPORT_DIRECTORY pExportDirectory)
{
	IMAGE_NT_HEADERS32 Header;
	ZERO(&Header);

	if (!HcImageRemoteNtHeadersFromModule32(hProcess, hModule, &Header))
	{
		return FALSE;
	}

	if (!HcProcessReadMemory(
		hProcess,
		(LPVOID) ((ULONG_PTR) hModule + Header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress),
		pExportDirectory,
		sizeof(*pExportDirectory),
		NULL))
	{
		return FALSE;
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ImageRemoteNtHeadersFromModule, IN HANDLE hProcess, IN HMODULE hModule, IN PIMAGE_NT_HEADERS pNtHeaders)
{
	IMAGE_DOS_HEADER Header;
	ZERO(&Header);

	if (!HcImageRemoteDosHeaderFromModule(hProcess, hModule, &Header))
	{
		return FALSE;
	}

	if (!HcProcessReadMemory(hProcess, (PVOID) ((ULONG_PTR) hModule + Header.e_lfanew), pNtHeaders, sizeof(*pNtHeaders), NULL))
	{
		return FALSE;
	}

	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, ImageRemoteExportDirectoryFromModule, IN HANDLE hProcess, IN HMODULE hModule, IN PIMAGE_EXPORT_DIRECTORY pExportDirectory)
{
	IMAGE_NT_HEADERS Header;
	ZERO(&Header);

	if (!HcImageRemoteNtHeadersFromModule(hProcess, hModule, &Header))
	{
		return FALSE;
	}

	if (!HcProcessReadMemory(
		hProcess,
		(LPVOID) ((ULONG_PTR) hModule + Header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress),
		pExportDirectory,
		sizeof(*pExportDirectory),
		NULL))
	{
		return FALSE;
	}

	return TRUE;
}