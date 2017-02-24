#include "../public/hcinject.h"

//
// For HcObjectWait
//
#include "../public/hcobject.h"

#pragma comment(lib, "user32.lib")

//
// For files
//
#include "../public/hcfile.h"

//
// For process interaction
//
#include "../public/hcprocess.h"

//
// For image file parsing
//
#include "../public/hcpe.h"

//
// For HcModuleProcedureAddress()
//
#include "../public/hcmodule.h"

//
// For HcGlobal
//
#include "../public/hcglobal.h"

//
// For HcVirtualAllocEx
//
#include "../public/hcvirtual.h"

//
// For string stuff
// 
#include "../public/hcstring.h"

//
// For HcClose
//
#include "sys/hcsyscall.h"

//
// For errors
//
#include "../public/hcerror.h"

//
// Typedef for LoadLibraryA, used in obsolete struct HC_MANUAL_MAP
//
typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);

//
// Typedef for GetProcAddress, used in obsolete struct HC_MANUAL_MAP
//
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);

//
// Typedef for DLL_MAIN, used in obsolete struct HC_MANUAL_MAP
//
typedef BOOLEAN(WINAPI *PDLL_MAIN)(HMODULE, SIZE_T, LPVOID);

//
// This is an obsolete and likely removed struct, which contains information used internally
// by HcProcessInjectModuleManual.
//
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

static
SIZE_T
HCAPI MmInternalResolve(PVOID lParam)
{
	PMANUAL_MAP ManualInject = NULL;
	HMODULE hModule = NULL;
	SIZE_T Index = 0, Function = 0, Count = 0, Delta = 0;
	PSIZE_T FunctionPointer = NULL;
	PWORD ImportList = NULL;

	PIMAGE_BASE_RELOCATION pIBR = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pIID = NULL;
	PIMAGE_IMPORT_BY_NAME pIBN = NULL;
	PIMAGE_THUNK_DATA FirstThunk = NULL, OrigFirstThunk = NULL;

	PDLL_MAIN EntryPoint = NULL;

	ManualInject = (PMANUAL_MAP)lParam;

	pIBR = ManualInject->BaseRelocation;
	Delta = (SIZE_T)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase);

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			Count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			ImportList = (PWORD)(pIBR + 1);

			for (Index = 0; Index<Count; Index++)
			{
				if (ImportList[Index])
				{
					FunctionPointer = (PSIZE_T)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (ImportList[Index] & 0xFFF)));
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

#pragma optimize( "", off )  
SIZE_T HCAPI MmInternalResolved()
{
	return 0;
}
#pragma optimize("", on)

#pragma endregion

static
BOOLEAN
HCAPI
HcParameterVerifyInjectModuleManual(PVOID Buffer)
{
	PIMAGE_NT_HEADERS pHeaderNt =HcPEGetNtHeader(Buffer);

	return pHeaderNt && (pHeaderNt->FileHeader.Characteristics & IMAGE_FILE_DLL);
}

//
// @inprogress
//
// Inserts a dynamic library's code inside of a process, without the use of any windows library linking code.
// This ensure that any code trying to locate a dll will not succeed, as there is no record of library loading happening.
//
// The code currently only supports 32bit to 32bit.
//
// For 64bit to 32bit, the internal resolving code will need to be in either shellcode, or an assembly file.
// For 32bit to 64bit, same story.
//
// RETURN
//		- A boolean indicating success
//
// HcErrorGetDosError() for a diagnosis.
//
HC_EXTERN_API
BOOLEAN
HCAPI
HcInjectManualMapW(HANDLE hProcess, LPCWSTR szcPath)
{
	HC_FILE_INFORMATIONW fileInformation;
	MANUAL_MAP ManualInject;
	PIMAGE_DOS_HEADER pHeaderDos = NULL;
	PIMAGE_NT_HEADERS pHeaderNt = NULL;
	PIMAGE_SECTION_HEADER pHeaderSection = NULL;
	HANDLE hThread = NULL, hFile = NULL;
	PVOID ImageBuffer = NULL, LoaderBuffer = NULL, FileBuffer = NULL;
	DWORD ExitCode = 0, SectionIndex = 0, BytesRead = 0;
	SIZE_T BytesWritten = 0;

	HcInternalSet(&fileInformation, 0, sizeof(fileInformation));
	HcInternalSet(&ManualInject, 0, sizeof(ManualInject));

	/* Check if we attempted to inject too early. */
	if (!HcProcessReadyEx(hProcess))
	{
		return FALSE;
	}

	if (!HcProcessSuspendEx(hProcess))
	{
		return FALSE;
	}

	/* Get the basic information about the file */
	if (!HcFileQueryInformationW(szcPath, &fileInformation))
	{
		HcProcessResumeEx(hProcess);
		return FALSE;
	}

	/* Allocate for the file information */
	FileBuffer = HcAlloc(fileInformation.Size);
	if (!FileBuffer)
	{
		HcProcessResumeEx(hProcess);
		return FALSE;
	}

	/* Read the file */
	hFile = HcFileOpenW(szcPath, OPEN_EXISTING, GENERIC_READ);
	if (hFile == INVALID_HANDLE)
	{
		HcProcessResumeEx(hProcess);
		HcFree(FileBuffer);
		return FALSE;
	}

	if (HcFileRead(hFile,
		FileBuffer,
		fileInformation.Size) != fileInformation.Size)
	{
		HcFree(FileBuffer);
		HcClose(hFile);

		HcProcessResumeEx(hProcess);
		return FALSE;
	}

	HcObjectClose(hFile);

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

	HcInternalSet(&ManualInject, 0, sizeof(MANUAL_MAP));

	/*
	MANUAL_MAP struct

	ImageBase = allocated image location.
	NtHeaders = allocated image location, added with relative address pointing Nt header.
	BaseRelocation = allocated image buffer + relative address of relocation.
	ImportDirectory = allocated image buffer + relative import directory

	LoadLibraryA - this needs to be reworked.
	right now, this function is located by looking into our own address.
	this will not work for when the executable does not match the target executable architecture. (cross dll injection)

	GetProcAddress, same as above.
	*/

	ManualInject.ImageBase = ImageBuffer;
	ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ImageBuffer + pHeaderDos->e_lfanew);
	ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)ImageBuffer + pHeaderNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ImageBuffer + pHeaderNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	ManualInject.fnLoadLibraryA = (pLoadLibraryA) HcModuleProcedureAddressW(HcModuleHandleW(L"kernel32.dll"), L"LoadLibraryA");
	ManualInject.fnGetProcAddress = (pGetProcAddress) HcModuleProcedureAddressW(HcModuleHandleW(L"kernel32.dll"), L"GetProcAddress");

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

	/* Set the code which will resolve imports, relocations */
	if (!HcProcessWriteMemory(hProcess,
		(PVOID)((PMANUAL_MAP)LoaderBuffer + 1),
		MmInternalResolve,
		(SIZE_T)MmInternalResolved - (SIZE_T)MmInternalResolve,
		&BytesWritten))
	{
		HcProcessResumeEx(hProcess);

		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);

		HcFree(FileBuffer);
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

	if (!ExitCode)
	{
		/* We're out, something went wrong. */
		HcErrorSetDosError(ExitCode);

		HcVirtualFreeEx(hProcess, LoaderBuffer, 0, MEM_RELEASE);
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);

		HcClose(hThread);

		HcFree(FileBuffer);
		return FALSE;
	}

	/* Done.*/
	HcClose(hThread);
	HcVirtualFreeEx(hProcess, LoaderBuffer, 0, MEM_RELEASE);

	HcFree(FileBuffer);
	return TRUE;
}

//
// Currently supports only same architecture injection due to the location of LoadLibraryW.
//
HC_EXTERN_API
BOOLEAN 
HCAPI 
HcInjectRemoteThreadW(HANDLE hProcess, LPCWSTR szcPath)
{
	LPVOID PathToDll = NULL;
	SIZE_T PathSize = 0;
	LPVOID lpToLoadLibrary = NULL;
	LPWSTR szFullPath = NULL;
	HANDLE hThread = NULL;
	DWORD ExitCode = 0;
	HANDLE hFile = NULL;

	if (HcStringIsBad(szcPath))
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
		return FALSE;
	}

	lpToLoadLibrary = (LPVOID)HcModuleProcedureAddressA(HcGlobal.HandleKernel32, "LoadLibraryW");
	if (!lpToLoadLibrary)
	{
		//
		// return FUNCTION_NOT_FOUND;
		//
		return FALSE;
	}

	szFullPath = HcStringAllocW(MAX_PATH);
	if (!szFullPath)
	{
		//
		// return NO_MEMORY;
		//
		HcErrorSetNtStatus(STATUS_NO_MEMORY);
		return FALSE;
	}

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

		HcFree(szFullPath);
		return FALSE;
	}

	HcObjectClose(hFile);

	PathSize = HcStringSizeW(szFullPath);
	if (!PathSize)
	{
		HcFree(szFullPath);
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
		HcFree(szFullPath);
		return FALSE;
	}


	/* Wait for the thread to finish */
	HcObjectWait(hThread, INFINITE);

	/* Did the thread exit? */
	// @defineme GetExitCodeThread(hThread, &ExitCode);

	if (!ExitCode)
	{
		/* We're out, something went wrong. */
		HcErrorSetDosError(ExitCode);

		HcVirtualFreeEx(hProcess, lpToLoadLibrary, 0, MEM_RELEASE);
		HcFree(szFullPath);

		HcClose(hThread);

		return FALSE;
	}

	/* Done.*/
	HcClose(hThread);

	HcVirtualFreeEx(hProcess, lpToLoadLibrary, 0, MEM_RELEASE);
	HcFree(szFullPath);
	return TRUE;
}