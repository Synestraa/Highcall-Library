#include <highcall.h>
#include "../sys/syscall.h"
#include "../distorm/include/distorm.h"

typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOLEAN(WINAPI *PDLL_MAIN)(HMODULE, SIZE_T, LPVOID);
typedef NTSTATUS(NTAPI *pLdrLoadDll) (PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);
typedef VOID(NTAPI *pRtlInitUnicodeString) (PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI *pLdrGetProcedureAddress) (HMODULE, PANSI_STRING, ULONG, LPVOID*);
typedef VOID(NTAPI *pRtlInitAnsiString) (PANSI_STRING, LPCSTR);

typedef struct _MANUAL_MAP
{
	LPVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
} MANUAL_MAP, *PMANUAL_MAP;

typedef struct _Payload32Initializer
{
	LPVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	pLdrLoadDll fnLdrLoadDll;
	pRtlInitUnicodeString fnRtlInitUnicodeString;
	pLdrGetProcedureAddress fnLdrGetProcedureAddress;
	pRtlInitAnsiString fnRtlInitAnsiString;
	pGetProcAddress fnGetProcAddress;
	pLoadLibraryA fnLoadLibraryA;
} Payload32Initializer, *PPayload32Initializer;

CONST BYTE payload64[] =
{
	0x55,
	0x8B, 0xEC,
	0x83, 0xEC, 0x38,
	0x8B, 0x45, 0x08,
	0x89, 0x45, 0xFC,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x08,
	0x89, 0x55, 0xF8,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x04,
	0x8B, 0x55, 0xFC,
	0x8B, 0x02,
	0x2B, 0x41, 0x34,
	0x89, 0x45, 0xD0,
	0x8B, 0x4D, 0xF8,
	0x83, 0x39, 0x00,
	0x0F, 0x84, 0x87, 0x00, 0x00, 0x00,
	0x8B, 0x55, 0xF8,
	0x83, 0x7A, 0x04, 0x08,
	0x72, 0x6D,
	0x8B, 0x45, 0xF8,
	0x8B, 0x48, 0x04,
	0x83, 0xE9, 0x08,
	0xD1, 0xE9,
	0x89, 0x4D, 0xD4,
	0x8B, 0x55, 0xF8,
	0x83, 0xC2, 0x08,
	0x89, 0x55, 0xDC,
	0xC7, 0x45, 0xEC, 0x00, 0x00, 0x00, 0x00,
	0xEB, 0x09,
	0x8B, 0x45, 0xEC,
	0x83, 0xC0, 0x01,
	0x89, 0x45, 0xEC,
	0x8B, 0x4D, 0xEC,
	0x3B, 0x4D, 0xD4,
	0x73, 0x3C,
	0x8B, 0x55, 0xEC,
	0x8B, 0x45, 0xDC,
	0x0F, 0xB7, 0x0C, 0x50,
	0x85, 0xC9,
	0x74, 0x2C,
	0x8B, 0x55, 0xEC,
	0x8B, 0x45, 0xDC,
	0x0F, 0xB7, 0x0C, 0x50,
	0x81, 0xE1, 0xFF, 0x0F, 0x00, 0x00,
	0x8B, 0x55, 0xF8,
	0x8B, 0x02,
	0x03, 0xC1,
	0x8B, 0x4D, 0xFC,
	0x03, 0x01,
	0x89, 0x45, 0xD8,
	0x8B, 0x55, 0xD8,
	0x8B, 0x02,
	0x03, 0x45, 0xD0,
	0x8B, 0x4D, 0xD8,
	0x89, 0x01,
	0xEB, 0xB3,
	0x8B, 0x55, 0xF8,
	0x8B, 0x45, 0xF8,
	0x03, 0x42, 0x04,
	0x89, 0x45, 0xF8,
	0xE9, 0x6D, 0xFF, 0xFF, 0xFF,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x0C,
	0x89, 0x55, 0xF0,
	0x8B, 0x45, 0xF0,
	0x83, 0x38, 0x00,
	0x0F, 0x84, 0xE4, 0x00, 0x00, 0x00,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF0,
	0x03, 0x10,
	0x89, 0x55, 0xF4,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF0,
	0x03, 0x50, 0x10,
	0x89, 0x55, 0xE4,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF0,
	0x03, 0x50, 0x0C,
	0x52,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x10,
	0xFF, 0xD2,
	0x89, 0x45, 0xE0,
	0x83, 0x7D, 0xE0, 0x00,
	0x75, 0x07,
	0x33, 0xC0,
	0xE9, 0xD9, 0x00, 0x00, 0x00,
	0x8B, 0x45, 0xF4,
	0x83, 0x38, 0x00,
	0x0F, 0x84, 0x8B, 0x00, 0x00, 0x00,
	0x8B, 0x4D, 0xF4,
	0x8B, 0x11,
	0x81, 0xE2, 0x00, 0x00, 0x00, 0x80,
	0x74, 0x32,
	0x8B, 0x45, 0xF4,
	0x8B, 0x08,
	0x81, 0xE1, 0xFF, 0xFF, 0x00, 0x00,
	0x51,
	0x8B, 0x55, 0xE0,
	0x52,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x14,
	0xFF, 0xD1,
	0x89, 0x45, 0xE8,
	0x83, 0x7D, 0xE8, 0x00,
	0x75, 0x07,
	0x33, 0xC0,
	0xE9, 0x98, 0x00, 0x00, 0x00,
	0x8B, 0x55, 0xE4,
	0x8B, 0x45, 0xE8,
	0x89, 0x02,
	0xEB, 0x35,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF4,
	0x03, 0x10,
	0x89, 0x55, 0xCC,
	0x8B, 0x4D, 0xCC,
	0x83, 0xC1, 0x02,
	0x51,
	0x8B, 0x55, 0xE0,
	0x52,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x14,
	0xFF, 0xD1,
	0x89, 0x45, 0xE8,
	0x83, 0x7D, 0xE8, 0x00,
	0x75, 0x04,
	0x33, 0xC0,
	0xEB, 0x61,
	0x8B, 0x55, 0xE4,
	0x8B, 0x45, 0xE8,
	0x89, 0x02,
	0x8B, 0x4D, 0xF4,
	0x83, 0xC1, 0x04,
	0x89, 0x4D, 0xF4,
	0x8B, 0x55, 0xE4,
	0x83, 0xC2, 0x04,
	0x89, 0x55, 0xE4,
	0xE9, 0x69, 0xFF, 0xFF, 0xFF,
	0x8B, 0x45, 0xF0,
	0x83, 0xC0, 0x14,
	0x89, 0x45, 0xF0,
	0xE9, 0x10, 0xFF, 0xFF, 0xFF,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x04,
	0x83, 0x7A, 0x28, 0x00,
	0x74, 0x23,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x04,
	0x8B, 0x55, 0xFC,
	0x8B, 0x02,
	0x03, 0x41, 0x28,
	0x89, 0x45, 0xC8,
	0x6A, 0x00,
	0x6A, 0x01,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x52,
	0xFF, 0x55, 0xC8,
	0x0F, 0xB6, 0xC0,
	0xEB, 0x05,
	0xB8, 0x01, 0x00, 0x00, 0x00,
	0x8B, 0xE5,
	0x5D,
	0xC2, 0x04, 0x00

};

CONST BYTE payload32[] = 
{
	0x55,
	0x8B, 0xEC,
	0x83, 0xEC, 0x38,
	0x8B, 0x45, 0x08,
	0x89, 0x45, 0xFC,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x08,
	0x89, 0x55, 0xF8,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x04,
	0x8B, 0x55, 0xFC,
	0x8B, 0x02,
	0x2B, 0x41, 0x34,
	0x89, 0x45, 0xD0,
	0x8B, 0x4D, 0xF8,
	0x83, 0x39, 0x00,
	0x0F, 0x84, 0x87, 0x00, 0x00, 0x00,
	0x8B, 0x55, 0xF8,
	0x83, 0x7A, 0x04, 0x08,
	0x72, 0x6D,
	0x8B, 0x45, 0xF8,
	0x8B, 0x48, 0x04,
	0x83, 0xE9, 0x08,
	0xD1, 0xE9,
	0x89, 0x4D, 0xD4,
	0x8B, 0x55, 0xF8,
	0x83, 0xC2, 0x08,
	0x89, 0x55, 0xDC,
	0xC7, 0x45, 0xEC, 0x00, 0x00, 0x00, 0x00,
	0xEB, 0x09,
	0x8B, 0x45, 0xEC,
	0x83, 0xC0, 0x01,
	0x89, 0x45, 0xEC,
	0x8B, 0x4D, 0xEC,
	0x3B, 0x4D, 0xD4,
	0x73, 0x3C,
	0x8B, 0x55, 0xEC,
	0x8B, 0x45, 0xDC,
	0x0F, 0xB7, 0x0C, 0x50,
	0x85, 0xC9,
	0x74, 0x2C,
	0x8B, 0x55, 0xEC,
	0x8B, 0x45, 0xDC,
	0x0F, 0xB7, 0x0C, 0x50,
	0x81, 0xE1, 0xFF, 0x0F, 0x00, 0x00,
	0x8B, 0x55, 0xF8,
	0x8B, 0x02,
	0x03, 0xC1,
	0x8B, 0x4D, 0xFC,
	0x03, 0x01,
	0x89, 0x45, 0xD8,
	0x8B, 0x55, 0xD8,
	0x8B, 0x02,
	0x03, 0x45, 0xD0,
	0x8B, 0x4D, 0xD8,
	0x89, 0x01,
	0xEB, 0xB3,
	0x8B, 0x55, 0xF8,
	0x8B, 0x45, 0xF8,
	0x03, 0x42, 0x04,
	0x89, 0x45, 0xF8,
	0xE9, 0x6D, 0xFF, 0xFF, 0xFF,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x0C,
	0x89, 0x55, 0xF0,
	0x8B, 0x45, 0xF0,
	0x83, 0x38, 0x00,
	0x0F, 0x84, 0xE4, 0x00, 0x00, 0x00,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF0,
	0x03, 0x10,
	0x89, 0x55, 0xF4,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF0,
	0x03, 0x50, 0x10,
	0x89, 0x55, 0xE4,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF0,
	0x03, 0x50, 0x0C,
	0x52,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x10,
	0xFF, 0xD2,
	0x89, 0x45, 0xE0,
	0x83, 0x7D, 0xE0, 0x00,
	0x75, 0x07,
	0x33, 0xC0,
	0xE9, 0xD9, 0x00, 0x00, 0x00,
	0x8B, 0x45, 0xF4,
	0x83, 0x38, 0x00,
	0x0F, 0x84, 0x8B, 0x00, 0x00, 0x00,
	0x8B, 0x4D, 0xF4,
	0x8B, 0x11,
	0x81, 0xE2, 0x00, 0x00, 0x00, 0x80,
	0x74, 0x32,
	0x8B, 0x45, 0xF4,
	0x8B, 0x08,
	0x81, 0xE1, 0xFF, 0xFF, 0x00, 0x00,
	0x51,
	0x8B, 0x55, 0xE0,
	0x52,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x14,
	0xFF, 0xD1,
	0x89, 0x45, 0xE8,
	0x83, 0x7D, 0xE8, 0x00,
	0x75, 0x07,
	0x33, 0xC0,
	0xE9, 0x98, 0x00, 0x00, 0x00,
	0x8B, 0x55, 0xE4,
	0x8B, 0x45, 0xE8,
	0x89, 0x02,
	0xEB, 0x35,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF4,
	0x03, 0x10,
	0x89, 0x55, 0xCC,
	0x8B, 0x4D, 0xCC,
	0x83, 0xC1, 0x02,
	0x51,
	0x8B, 0x55, 0xE0,
	0x52,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x14,
	0xFF, 0xD1,
	0x89, 0x45, 0xE8,
	0x83, 0x7D, 0xE8, 0x00,
	0x75, 0x04,
	0x33, 0xC0,
	0xEB, 0x61,
	0x8B, 0x55, 0xE4,
	0x8B, 0x45, 0xE8,
	0x89, 0x02,
	0x8B, 0x4D, 0xF4,
	0x83, 0xC1, 0x04,
	0x89, 0x4D, 0xF4,
	0x8B, 0x55, 0xE4,
	0x83, 0xC2, 0x04,
	0x89, 0x55, 0xE4,
	0xE9, 0x69, 0xFF, 0xFF, 0xFF,
	0x8B, 0x45, 0xF0,
	0x83, 0xC0, 0x14,
	0x89, 0x45, 0xF0,
	0xE9, 0x10, 0xFF, 0xFF, 0xFF,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x04,
	0x83, 0x7A, 0x28, 0x00,
	0x74, 0x23,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x04,
	0x8B, 0x55, 0xFC,
	0x8B, 0x02,
	0x03, 0x41, 0x28,
	0x89, 0x45, 0xC8,
	0x6A, 0x00,
	0x6A, 0x01,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x52,
	0xFF, 0x55, 0xC8,
	0x0F, 0xB6, 0xC0,
	0xEB, 0x05,
	0xB8, 0x01, 0x00, 0x00, 0x00,
	0x8B, 0xE5,
	0x5D,
	0xC2, 0x04, 0x00
};

#pragma region Internal Manual Map Code

// turn off incremental linking -- should force this to *not* use a jump table
#pragma comment(linker, "/incremental:no")

// turn off optimizations
//#pragma optimize( "", off )

// turn off pesky runtime checks that add an extra call to _RTC_CheckEsp to the end of our function
#pragma runtime_checks( "", off)

// put both functions in the same section.  as long as there are only two, they should be in order
#pragma code_seg( ".text$A" )

__declspec(noinline)
static
SIZE_T HCAPI MmInternalResolve(PVOID lParam)
{
	PMANUAL_MAP ManualInject = (PMANUAL_MAP)lParam;
	HMODULE hModule;
	ULONG_PTR Index, Function, Count, Delta;
	PULONG_PTR FunctionPointer;
	PDWORD ImportList;
	PIMAGE_BASE_RELOCATION pIBR;
	PIMAGE_IMPORT_DESCRIPTOR pIID;
	PIMAGE_IMPORT_BY_NAME pIBN;
	PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;
	PDLL_MAIN EntryPoint;

	pIBR = ManualInject->BaseRelocation;
	Delta = (ULONG_PTR) ((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase);

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			Count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(DWORD);
			ImportList = (PDWORD)(pIBR + 1);

			for (Index = 0; Index < Count; Index++)
			{
				if (ImportList[Index])
				{
					FunctionPointer = (PULONG_PTR) ((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (ImportList[Index] & 0xFFFF)));
					*FunctionPointer += Delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	pIID = ManualInject->ImportDirectory;

	/* Manually load all the library imports */
	while (pIID->Characteristics)
	{
		OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);


		hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);
		if (!hModule)
		{
			return FALSE;
		}

		/* Import each */
		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				/* By ordinal */
				Function = (SIZE_T)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			else
			{
				/* By name */
				pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
				Function = (SIZE_T)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			OrigFirstThunk++;
			FirstThunk++;
		}

		pIID++;
	}

	if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
	}

	return TRUE;
}

static void __stdcall MmInternalResolve_End()
{

}

#pragma code_seg()
#pragma runtime_checks ("", restore)
//#pragma optimize ("", restore)

#pragma endregion

static
BOOLEAN
HCAPI
HcParameterVerifyInjectModuleManual(PVOID Buffer)
{
	PIMAGE_NT_HEADERS pHeaderNt = HcImageGetNtHeader(Buffer);

	return pHeaderNt && (pHeaderNt->FileHeader.Characteristics & IMAGE_FILE_DLL);
}

static
DECL_EXTERN_API(DWORD, AssertFunctionSize, LPVOID lpBaseAddress)
{
	DWORD Size = 0;
	_CodeInfo Info;
	_DInst* Instructions = NULL;
	DWORD InstructionIndex = 0;
	DWORD InstructionCount = 0;
	PBYTE lpStream = (PBYTE)lpBaseAddress;

	HcInternalSet(&Info, 0, sizeof(Info));

	Info.code = (unsigned char*)lpBaseAddress;
	Info.codeLen = 0x100 * 10;
	Info.codeOffset = 0;
	Info.features = DF_NONE;
	Info.dt = DISASM_TYPE;

	/* Assume that each instruction is 10 bytes at least */
	Instructions = HcAlloc(sizeof(_DecodedInst) * 0x100);
	if (!Instructions)
	{
		return 0;
	}

	/* Decode the instructions */
	if (distorm_decompose(&Info, Instructions, 0x100, &InstructionCount) == DECRES_INPUTERR
		|| InstructionCount == 0)
	{
		HcFree(Instructions);
		return 0;
	}

	/* Loop through all the instructions. */
	for (InstructionIndex = 0; InstructionIndex < InstructionCount; InstructionIndex++)
	{
		_DInst instr = Instructions[InstructionIndex];
		if (*(lpStream + instr.addr) != 0xcc)
		{
			Size += instr.size;
		}
		else if (instr.size == 1)
		{
			break;
		}
	}

	HcFree(Instructions);
	return Size;
}

DECL_EXTERN_API(BOOLEAN, InjectManualMap32W, CONST IN HANDLE hProcess, IN LPCWSTR szcPath)
{
	MANUAL_MAP ManualInject;
	PIMAGE_DOS_HEADER pHeaderDos;
	PIMAGE_NT_HEADERS pHeaderNt;
	PIMAGE_SECTION_HEADER pHeaderSection;
	HANDLE hThread = NULL, hFile;
	PVOID ImageBuffer, LoaderBuffer = NULL, FileBuffer = NULL;
	DWORD ExitCode = 0, SectionIndex;
	SIZE_T BytesWritten = 0;
	DWORD dwFileSize;
	BOOLEAN bSuspended = FALSE;
	BOOLEAN bReturnValue = FALSE;
	ULONG_PTR hKernel32;
	ULONG_PTR hRemoteKernel32;
	ULONG_PTR dwRvaLoadLibraryA;
	ULONG_PTR dwRvaGetProcAddress;

	ZERO(&ManualInject);

	/* Check if we attempted to inject too early. */
	if (!HcProcessReadyEx(hProcess))
	{
		return FALSE;
	}

	if (hProcess != NtCurrentProcess)
	{
		if (HcProcessSuspendEx(hProcess))
		{
			bSuspended = TRUE;
		}
	}

	/* Read the file */
	hFile = HcFileOpenW(szcPath, OPEN_EXISTING, GENERIC_READ);
	if (hFile == INVALID_HANDLE)
	{
		goto done;
	}

	dwFileSize = HcFileSize(hFile);
	if (!dwFileSize)
	{
		goto done;
	}

	/* Allocate for the file information */
	FileBuffer = HcAlloc(dwFileSize);
	if (!FileBuffer)
	{
		goto done;
	}

	if (HcFileRead(hFile, FileBuffer, dwFileSize) != dwFileSize)
	{
		HcClose(hFile);
		goto done;
	}

	HcObjectClose(&hFile);

	if (!HcParameterVerifyInjectModuleManual(FileBuffer))
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
		goto done;
	}

	pHeaderDos = HcImageGetDosHeader(FileBuffer);
	pHeaderNt = HcImageGetNtHeader(FileBuffer);

	/* Allocate for the code/data of the dll */
	ImageBuffer = HcVirtualAllocEx(hProcess,
		NULL,
		pHeaderNt->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!ImageBuffer)
	{
		goto done;
	}

	/* Write the code/data to the target executable */
	if (!HcProcessWriteMemory(hProcess,
		ImageBuffer,
		FileBuffer,
		pHeaderNt->OptionalHeader.SizeOfHeaders,
		&BytesWritten))
	{
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);
		goto done;
	}

	pHeaderSection = (PIMAGE_SECTION_HEADER)(pHeaderNt + 1);

	/* Write sections of the dll to the process, not guaranteed to succeed, so no check. */
	for (SectionIndex = 0; SectionIndex < pHeaderNt->FileHeader.NumberOfSections; SectionIndex++)
	{
		/* This writes to relative locations of our loaded executable.

		ImageBuffer points to the base of the library.
		.VirtualAddress points to the relative offset from the base of the library to the section.

		FileBuffer points to the base of the file.
		.PointerToRawData points to the relative offset from the file to the section.
		*/

		HcProcessWriteMemory(hProcess,
			(PVOID)((LPBYTE)ImageBuffer + pHeaderSection[SectionIndex].VirtualAddress),
			(PVOID)((LPBYTE)FileBuffer + pHeaderSection[SectionIndex].PointerToRawData),
			pHeaderSection[SectionIndex].SizeOfRawData,
			&BytesWritten);
	}

	/* Allocate code for our function */
	LoaderBuffer = HcVirtualAllocEx(hProcess,
		NULL,
		4096,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!LoaderBuffer)
	{
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);
		goto done;
	}

	hKernel32 = (ULONG_PTR) HcModuleHandleW(L"kernel32.dll");
	hRemoteKernel32 = (ULONG_PTR) HcModuleHandleAdvancedExW(hProcess, L"kernel32.dll", FALSE);
	if (!hRemoteKernel32)
	{
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);
		goto done;
	}

	dwRvaLoadLibraryA = (ULONG_PTR) HcModuleProcedureW((HMODULE)hKernel32, L"LoadLibraryA") - hRemoteKernel32;
	dwRvaGetProcAddress = (ULONG_PTR) HcModuleProcedureW((HMODULE)hKernel32, L"GetProcAddress") - hRemoteKernel32;

	ManualInject.ImageBase = ImageBuffer;
	ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ImageBuffer + pHeaderDos->e_lfanew);
	ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)ImageBuffer + pHeaderNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ImageBuffer + pHeaderNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	ManualInject.fnLoadLibraryA = (pLoadLibraryA) ((ULONG_PTR) hRemoteKernel32 + dwRvaLoadLibraryA);
	ManualInject.fnGetProcAddress = (pGetProcAddress) ((ULONG_PTR)hRemoteKernel32 + dwRvaGetProcAddress);

	/* Set the manual map information */
	if (!HcProcessWriteMemory(hProcess,
		LoaderBuffer,
		&ManualInject,
		sizeof(MANUAL_MAP),
		&BytesWritten))
	{
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);
		goto done;
	}

	/* Set the code which will resolve imports, relocations  */
	if (!HcProcessWriteMemory(hProcess,
		(PVOID)((PMANUAL_MAP)LoaderBuffer + 1),
		payload32,
		sizeof(payload32),
		&BytesWritten))
	{
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);

		HcErrorSetNtStatus(STATUS_ACCESS_VIOLATION);
		goto done;
	}

	/* Execute the code in a new thread */
	hThread = HcProcessCreateThread(hProcess,
		(LPTHREAD_START_ROUTINE)((PMANUAL_MAP)LoaderBuffer + 1),
		LoaderBuffer,
		0);

	if (!hThread)
	{
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);
		goto done;
	}

	HcThreadResume(hThread);

	/* Wait for the thread to finish */
	HcObjectWait(hThread, INFINITE);

	/* Did the thread exit? */
	HcThreadExitCode(hThread, &ExitCode);
	if (!ExitCode)
	{
		/* We're out, something went wrong. */
		HcErrorSetDosError(ExitCode);

		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);

		goto done;
	}

	bReturnValue = TRUE;

done:
	if (bSuspended)
	{
		HcProcessResumeEx(hProcess);
	}

	if (hThread != NULL && hThread != INVALID_HANDLE)
	{
		HcObjectClose(&hThread);
	}

	if (LoaderBuffer)
	{
		HcVirtualFreeEx(hProcess, LoaderBuffer, 0, MEM_RELEASE);
	}

	if (FileBuffer)
	{
		HcFree(FileBuffer);
	}

	return bReturnValue;
}

DECL_EXTERN_API(BOOLEAN, InjectRemoteThreadW, CONST IN HANDLE hProcess, IN LPCWSTR szcPath)
{
	LPVOID PathToDll;
	SIZE_T PathSize;
	LPVOID lpToLoadLibrary;
	LPWSTR szFullPath;
	HANDLE hThread;
	DWORD ExitCode = 0;
	HANDLE hFile;

	if (HcStringIsBad(szcPath))
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
		return FALSE;
	}

	lpToLoadLibrary = (LPVOID)HcModuleProcedureA(HcModuleLoadW(L"kernel32.dll"), "LoadLibraryW");
	if (!lpToLoadLibrary)
	{
		HcErrorSetNtStatus(STATUS_INVALID_ADDRESS);
		return FALSE;
	}

	//szFullPath = HcStringAllocW(MAX_PATH);
	/*
	if (!szFullPath)
	{
		//
		// return NO_MEMORY;
		//
		HcErrorSetNtStatus(STATUS_NO_MEMORY);
		return FALSE;
	}
	*/

	/*
	// @defineme
	if (!GetFullPathNameW(szcPath, MAX_PATH, szFullPath, NULL))
	{
		//
		// return INVALID_FILE;
		//
		HcFree(szFullPath);
		return FALSE;
	}
	*/

	szFullPath = (LPWSTR) szcPath;

	hFile = HcFileOpenW(szcPath, OPEN_EXISTING, GENERIC_READ);
	if (hFile == INVALID_HANDLE)
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);

		return FALSE;
	}

	HcObjectClose(&hFile);

	PathSize = HcStringSizeW(szFullPath);
	if (!PathSize)
	{
		return FALSE;
	}

	PathToDll = HcVirtualAllocEx(hProcess,
		NULL,
		PathSize + sizeof(WCHAR), 
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (!PathToDll)
	{
		//
		// SetLastError from the api should handle it.
		//
		HcFree(szFullPath);
		return FALSE;
	}

	if (!HcProcessWriteMemory(hProcess,
		PathToDll,
		szFullPath,
		PathSize + sizeof(WCHAR),
		NULL))
	{
		//
		// SetLastError from the api should handle it.
		//
		HcVirtualFreeEx(hProcess, lpToLoadLibrary, 0, MEM_RELEASE);
		HcFree(szFullPath);
		return FALSE;
	}

	//
	// Load the dll with a new thread in the process.
	//
	hThread = HcProcessCreateThread(hProcess, (LPTHREAD_START_ROUTINE)lpToLoadLibrary, (LPVOID)PathToDll, 0);
	if (hThread == INVALID_HANDLE)
	{
		//
		// Failed creating the thread
		//
		HcVirtualFreeEx(hProcess, lpToLoadLibrary, 0, MEM_RELEASE);
		return FALSE;
	}


	/* Wait for the thread to finish */
	HcObjectWait(hThread, INFINITE);

	/* Did the thread exit? */
	// @defineme GetExitCodeThread(hThread, &ExitCode);

	if (!ExitCode)
	{
		/* We're out, something went wrong. */
		//HcErrorSetDosError(ExitCode);

		//HcVirtualFreeEx(hProcess, lpToLoadLibrary, 0, MEM_RELEASE);

		//HcClose(hThread);
		//return FALSE;
	}

	/* Done.*/
	HcClose(hThread);

	HcVirtualFreeEx(hProcess, lpToLoadLibrary, 0, MEM_RELEASE);
	return TRUE;
}