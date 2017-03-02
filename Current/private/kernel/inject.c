#include <highcall.h>
#include "../sys/syscall.h"
#include "../distorm/include/distorm.h"


typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOLEAN(WINAPI *PDLL_MAIN)(HMODULE, SIZE_T, LPVOID);

typedef struct _MANUAL_MAP
{
	LPVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
} MANUAL_MAP, *PMANUAL_MAP;

#pragma region Internal Manual Map Code

#pragma optimize("", on)  
__declspec(noinline)
static
SIZE_T HCAPI MmInternalResolve(PVOID lParam)
{
	PMANUAL_MAP ManualInject = (PMANUAL_MAP)lParam;
	HMODULE hModule;
	ULONG_PTR Index, Function, Count, Delta;
	PULONG_PTR FunctionPointer;
	PWORD ImportList;
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
			Count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			ImportList = (PWORD)(pIBR + 1);

			for (Index = 0; Index < Count; Index++)
			{
				if (ImportList[Index])
				{
					FunctionPointer = (PULONG_PTR) ((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (ImportList[Index] & 0xFFF)));
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
#pragma optimize("", off)  

#pragma endregion

static
BOOLEAN
HCAPI
HcParameterVerifyInjectModuleManual(PVOID Buffer)
{
	PIMAGE_NT_HEADERS pHeaderNt = HcPEGetNtHeader(Buffer);

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

DECL_EXTERN_API(BOOLEAN, InjectManualMapW, CONST IN HANDLE hProcess, IN LPCWSTR szcPath)
{
	MANUAL_MAP ManualInject;
	PIMAGE_DOS_HEADER pHeaderDos;
	PIMAGE_NT_HEADERS pHeaderNt;
	PIMAGE_SECTION_HEADER pHeaderSection;
	HANDLE hThread, hFile;
	PVOID ImageBuffer, LoaderBuffer, FileBuffer;
	DWORD ExitCode = 0, SectionIndex;
	SIZE_T BytesWritten = 0;
	DWORD dwFileSize;

	ZERO(&ManualInject);

	/* Check if we attempted to inject too early. */
	if (!HcProcessReadyEx(hProcess))
	{
		return FALSE;
	}

	if (!HcProcessSuspendEx(hProcess))
	{
		return FALSE;
	}

	/* Read the file */
	hFile = HcFileOpenW(szcPath, OPEN_EXISTING, GENERIC_READ);
	if (hFile == INVALID_HANDLE)
	{
		HcProcessResumeEx(hProcess);
		return FALSE;
	}

	dwFileSize = HcFileSize(hFile);
	if (!dwFileSize)
	{
		HcProcessResumeEx(hProcess);
		return FALSE;
	}

	/* Allocate for the file information */
	FileBuffer = HcAlloc(dwFileSize);
	if (!FileBuffer)
	{
		HcProcessResumeEx(hProcess);
		return FALSE;
	}

	if (HcFileRead(hFile, FileBuffer, dwFileSize) != dwFileSize)
	{
		HcFree(FileBuffer);
		HcClose(hFile);

		HcProcessResumeEx(hProcess);
		return FALSE;
	}

	HcObjectClose(&hFile);

	/* Verify this is a PE DLL */
	if (!HcParameterVerifyInjectModuleManual(FileBuffer))
	{
		HcFree(FileBuffer);
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);

		HcProcessResumeEx(hProcess);
		return FALSE;
	}

	pHeaderDos = HcPEGetDosHeader(FileBuffer);
	pHeaderNt = HcPEGetNtHeader(FileBuffer);

	/* Allocate for the code/data of the dll */
	ImageBuffer = HcVirtualAllocEx(hProcess,
		NULL,
		pHeaderNt->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!ImageBuffer)
	{
		HcFree(FileBuffer);
		HcProcessResumeEx(hProcess);
		return FALSE;
	}

	/* Write the code/data to the target executable */
	if (!HcProcessWriteMemory(hProcess,
		ImageBuffer,
		FileBuffer,
		pHeaderNt->OptionalHeader.SizeOfHeaders,
		&BytesWritten))
	{
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);
		HcFree(FileBuffer);
		HcProcessResumeEx(hProcess);
		return FALSE;
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
		HcFree(FileBuffer);
		HcProcessResumeEx(hProcess);

		return FALSE;
	}

	/*
	 * MANUAL_MAP struct
	 * 
	 * ImageBase = allocated image location.
	 * NtHeaders = allocated image location, added with relative address pointing Nt header.
	 * BaseRelocation = allocated image buffer + relative address of relocation.
	 * ImportDirectory = allocated image buffer + relative import directory
	 * 
	 * LoadLibraryA - this needs to be reworked.
	 * right now, this function is located by looking into our own address.
	 * this will not work for when the executable does not match the target executable architecture. (cross dll injection)
	 * 
	 * GetProcAddress, same as above.
	 */

	ManualInject.ImageBase = ImageBuffer;
	ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ImageBuffer + pHeaderDos->e_lfanew);
	ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)ImageBuffer + pHeaderNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ImageBuffer + pHeaderNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	ManualInject.fnLoadLibraryA = (pLoadLibraryA)HcModuleProcedureW(HcModuleHandleW(L"kernel32.dll"), L"LoadLibraryA");
	ManualInject.fnGetProcAddress = (pGetProcAddress)HcModuleProcedureW(HcModuleHandleW(L"kernel32.dll"), L"GetProcAddress");

	/* Set the manual map information */
	if (!HcProcessWriteMemory(hProcess,
		LoaderBuffer,
		&ManualInject,
		sizeof(MANUAL_MAP),
		&BytesWritten))
	{
		HcProcessResumeEx(hProcess);
		HcFree(FileBuffer);
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);
		return FALSE;
	}

	SIZE_T testSize = HcAssertFunctionSize(MmInternalResolve);

	/* Set the code which will resolve imports, relocations */
	if (!HcProcessWriteMemory(hProcess,
		(PVOID)((PMANUAL_MAP)LoaderBuffer + 1),
		MmInternalResolve,
		testSize,
		&BytesWritten))
	{
		HcProcessResumeEx(hProcess);
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);
		HcFree(FileBuffer);

		HcErrorSetNtStatus(STATUS_ACCESS_VIOLATION);
		return FALSE;
	}

	HcProcessResumeEx(hProcess);

	/* Execute the code in a new thread */
	hThread = HcProcessCreateThread(hProcess,
		(LPTHREAD_START_ROUTINE)((PMANUAL_MAP)LoaderBuffer + 1),
		LoaderBuffer,
		0);

	if (!hThread)
	{
		HcVirtualFreeEx(hProcess, LoaderBuffer, 0, MEM_RELEASE);
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);

		HcFree(FileBuffer);
		return FALSE;
	}

	/* Wait for the thread to finish */
	HcObjectWait(hThread, INFINITE);

	/* Did the thread exit? */
	// @defineme GetExitCodeThread(hThread, &ExitCode);

	/*
	if (!ExitCode)
	{
		/* We're out, something went wrong. 
		HcErrorSetDosError(ExitCode);

		HcVirtualFreeEx(hProcess, LoaderBuffer, 0, MEM_RELEASE);
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);

		HcClose(hThread);

		HcFree(FileBuffer);
		return FALSE;
	}
	*/

	/* Done.*/
	HcClose(hThread);
	HcVirtualFreeEx(hProcess, LoaderBuffer, 0, MEM_RELEASE);

	HcFree(FileBuffer);
	return TRUE;
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