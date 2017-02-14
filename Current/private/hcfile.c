/*++

Module Name:

hcfile.c

Abstract:

This module implements custom file handling functions as we as reimplementations of kernel32.dll.

Author:

Synestra 9/11/2016, information was gathered from various sources.

Revision History:

--*/

//
// @TODO: Replace the functions from the <windows.h> include with reimplementations using highcall.
//

#include <windows.h>

#include "sys/hcsyscall.h"

#include "../public/hcfile.h"
#include "../public/hcmodule.h"
#include "../public/hcpe.h"
#include "../public/hcobject.h"
#include "../public/hcerror.h"
#include "../public/hcvirtual.h"
#include "../public/imports.h"
#include "../public/hcstring.h"

//
// Unimplemented.
//

DWORD HCAPI HcGetFileAttributesA(LPCSTR lpFile)
{
	return 0;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcFileExistsA(LPCSTR lpFilePath)
//
// Retrieves attributes of a file path, determines whether the file is present.
//
// Parameters:
//
//	1. lpFilePath -> Ansi string representing the file path.
//
// Returns:
//	Success.
//
{
	return (GetFileAttributesA(lpFilePath) != 0xFFFFFFFF);
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcFileExistsW(LPCWSTR lpFilePath)
//
// Unicode implementation of HcFileExists.
//
// Parameters:
//
//	1. lpFilePath -> Unicode string representing the file path.
//
// Returns:
//	Success.
//
{
	return (GetFileAttributesW(lpFilePath) != 0xFFFFFFFF);
}

HC_EXTERN_API
SIZE_T
HCAPI
HcFileSize(LPCSTR lpPath)
//
// Retrieves the size of a file.
// @TODO: Implement unicode version, rename to ...A/...W
//
// Parameters:
//
//	1. lpPath -> Ansi string representing the file path.
//
// Returns:
//	The size of the file in a size_t type.
//
{
	SIZE_T FileSize = 0;
	HANDLE hFile = CreateFileA(lpPath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);

	if (!hFile)
	{
		return 0;
	}

	FileSize = GetFileSize(hFile, NULL);

	/* Close handle and return */
	HcClose(hFile);
	return FileSize;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcFileQueryInformationW(LPCWSTR lpPath, PHC_FILE_INFORMATIONW fileInformation)
//
// Retrieves a HC_FILE_INFORMATION struct (defined in hcfile.h) from a file.
//
// Parameters:
//
//	1. lpPath -> Unicode string representing the file path.
//  2. fileInformation -> Pointer to a HC_FILE_INFORMATIONA struct.
//
// Returns:
//	Success.
//
{
	HANDLE hFile = CreateFileW(lpPath,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	fileInformation->Size = GetFileSize(hFile, NULL);

	HcClose(hFile);

	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcFileQueryInformationA(LPCSTR lpPath, PHC_FILE_INFORMATIONA fileInformation)
//
// Ansi implementation of HcFileQueryInformation.
//
// Parameters:
//
//	1. lpPath -> Ansi string representing the file path.
//  2. fileInformation -> Pointer to a HC_FILE_INFORMATIONA struct.
//
// Returns:
//	Success.
//
{
	HANDLE hFile = CreateFileA(lpPath,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	fileInformation->Size = GetFileSize(hFile, NULL);

	HcClose(hFile);
	return TRUE;
}

HC_EXTERN_API
DWORD
HCAPI
HcFileOffsetByExportNameA(HMODULE hModule, LPCSTR lpExportName)
//
// Retrieves the offset in bytes to the start of a function exported by a dll.
//
// Parameters:
//
//	1. hModule -> The handle of the targetted module.
//  2. lpExportName -> Ansi string representing the functions name.
//
// Returns:
//	An offset inside of a file, in bytes, to the start of a function export located.
//
{
	PIMAGE_NT_HEADERS pHeaderNT = NULL;
	SIZE_T szExportRVA = 0;
	SIZE_T szExportVA = 0;
	SIZE_T szModule = 0;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	szModule = (SIZE_T)hModule;
	pHeaderNT = HcPEGetNtHeader(hModule);

	if (!pHeaderNT)
	{
		return 0;
	}

	//
	// Get the absolute address of requested export, subtract the module's base,
	// pass to the PE handler function.
	//
	szExportVA = (SIZE_T)HcModuleProcedureAddressA(hModule, lpExportName);
	if (szExportVA)
	{
		/* Calculate the relative offset */
		szExportRVA = szExportVA - szModule;

		return HcPEGetRawFromRva(pHeaderNT, szExportRVA);
	}

	return 0;
}

HC_EXTERN_API
DWORD
HCAPI
HcFileOffsetByExportNameW(HMODULE hModule, LPCWSTR lpExportName)
//
// Unicode implementation of HcFileOffsetByExportNameW
// 
// Parameters:
//
//	1. hModule -> The handle of the targetted module.
//  2. lpExportName -> Unicode string representing the functions name.
//
// Returns:
//	An offset inside of a file, in bytes, to the start of a function export located.
//
{
	PIMAGE_NT_HEADERS pHeaderNT = NULL;
	SIZE_T dwExportRVA = 0;
	SIZE_T dwExportVA = 0;
	SIZE_T dwModule = 0;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	dwModule = (SIZE_T)hModule;

	pHeaderNT = HcPEGetNtHeader(hModule);
	if (!pHeaderNT)
	{
		return 0;
	}

	//
	// Get the absolute address of requested export, subtract the module's base,
	// pass to the PE handler function.
	//
	dwExportVA = (SIZE_T)HcModuleProcedureAddressW(hModule, lpExportName);
	if (dwExportVA)
	{
		/* Calculate the relative offset */
		dwExportRVA = dwExportVA - dwModule;

		return HcPEGetRawFromRva(pHeaderNT, dwExportRVA);
	}

	return 0;
}

HC_EXTERN_API
SIZE_T
HCAPI
HcFileReadModuleA(HMODULE hModule, LPCSTR lpExportName, PBYTE lpBuffer, DWORD dwCount)
//
// Translates a loaded module's virtual address into a file offset, reads the data inside of lpBuffer.
//
// Parameters:
//
//	1. hModule -> The handle of the targetted module.
//  2. lpExportName -> Ansi string representing the functions name.
//	3. lpBuffer -> Pointer to a block of memory to write the file data to.
//  4. dwCount -> The max amount of bytes to read.
//
// Returns:
//	The amount of bytes successfully read from the file.
//
{
	DWORD dwFileOffse = 0;
	HANDLE hFile = NULL;
	DWORD BytesRead = 0;
	LPSTR lpModulePath = HcStringAllocA(MAX_PATH);
	DWORD dwFileOffset = HcFileOffsetByExportNameA(hModule, lpExportName);

	if (!dwFileOffset || !lpModulePath)
	{
		return 0;
	}

	/* Acquire path of targetted module. */
	GetModuleFileNameA(hModule, lpModulePath, MAX_PATH);

	/* Open it up */
	if (!(hFile = CreateFileA(lpModulePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL)))
	{
		HcFree(lpModulePath);
		return 0;
	}

	/* Run to the offset */
	if (!(SetFilePointer(hFile, dwFileOffset, 0, FILE_BEGIN)))
	{
		HcFree(lpModulePath);
		HcObjectClose(hFile);
		return 0;
	}

	/* Snatch the data */
	if (!ReadFile(hFile, lpBuffer, dwCount, &BytesRead, NULL))
	{
		HcFree(lpModulePath);
		HcObjectClose(hFile);
		return 0;
	}

	/* Fuck off */
	HcFree(lpModulePath);
	HcObjectClose(hFile);
	return BytesRead;
}

HC_EXTERN_API
SIZE_T
HCAPI
HcFileReadModuleW(HMODULE hModule, LPCWSTR lpExportName, PBYTE lpBuffer, DWORD dwCount)
//
// Unicode implementation of HcFileReadModule.
//
// Parameters:
//
//	1. hModule -> The handle of the targetted module.
//  2. lpExportName -> Ansi string representing the functions name.
//	3. lpBuffer -> Pointer to a block of memory to write the file data to.
//  4. dwCount -> The max amount of bytes to read.
//
// Returns:
//	The amount of bytes successfully read from the file.
//
{
	HANDLE hFile = NULL;
	DWORD BytesRead = 0;
	LPWSTR lpModulePath = lpModulePath = HcStringAllocW(MAX_PATH);
	DWORD dwFileOffset = HcFileOffsetByExportNameW(hModule, lpExportName);

	if (!dwFileOffset || !lpModulePath)
	{
		return 0;
	}

	/* Acquire path of targetted module. */
	GetModuleFileNameW(hModule, lpModulePath, MAX_PATH);

	/* Open it up */
	if (!(hFile = CreateFileW(lpModulePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL)))
	{
		HcFree(lpModulePath);
		return 0;
	}

	/* Run to the offset */
	if (!(SetFilePointer(hFile, dwFileOffset, 0, FILE_BEGIN)))
	{
		HcFree(lpModulePath);
		HcObjectClose(hFile);
		return 0;
	}

	/* Snatch the data */
	if (!ReadFile(hFile, lpBuffer, dwCount, &BytesRead, NULL))
	{
		HcFree(lpModulePath);
		HcObjectClose(hFile);
		return 0;
	}

	/* Fuck off */
	HcFree(lpModulePath);
	HcObjectClose(hFile);
	return BytesRead;
}

HC_EXTERN_API
DWORD
HCAPI
HcFileOffsetByVirtualAddress(LPCVOID lpAddress)
//
// Similar to HcFileOffsetByExportName, it retrieves an offset to the module.
// This function retrieves the offset of an address instead of an export.
//
// Parameters:
//
//	1. lpddress -> The address to locate.
//
// Returns:
//	The offset to the file in bytes.
//
{
	PIMAGE_NT_HEADERS pHeaderNT = NULL;
	SIZE_T szRva = 0;
	SIZE_T szModule = 0;
	MEMORY_BASIC_INFORMATION memInfo = { 0 };
	HMODULE hModule = NULL;

	/* Find the module that allocated the address */
	if (!HcVirtualQuery(lpAddress,
		&memInfo,
		sizeof(memInfo)))
	{
		return 0;
	}

	/* Take the module */
	hModule = (HMODULE)memInfo.AllocationBase;
	if (!hModule)
	{
		return 0;
	}

	szModule = (SIZE_T)hModule;

	pHeaderNT = HcPEGetNtHeader(hModule);
	if (!pHeaderNT)
	{
		return 0;
	}

	/* Calculate the relative offset */
	szRva = ((SIZE_T)lpAddress) - szModule;

	return HcPEGetRawFromRva(pHeaderNT, szRva);
}

HC_EXTERN_API
SIZE_T
HCAPI
HcFileReadAddress(LPCVOID lpBaseAddress, PBYTE lpBufferOut, DWORD dwCountToRead)
//
// Similar to HcFileReadModule, it reads a module from it's file path.
// The difference is that this read any arbitrary address located inside of the disk and not just the RAM.
//
// Parameters:
//
//	1. lpAddress -> The address to read from.
//  2. lpBufferOut -> The buffer to write the data from the file to.
//  3. dwCountToRead -> The amount of bytes to read from the file.
//
// Returns:
//	The amount of bytes successfully read.
//
{
	DWORD dwFileOffset = 0;
	LPWSTR lpModulePath = NULL;
	HANDLE hFile = NULL;
	DWORD BytesRead = 0;
	HMODULE hModule = NULL;
	MEMORY_BASIC_INFORMATION memInfo = { 0 };

	/* Find the module that allocated the address */
	if (!HcVirtualQuery(lpBaseAddress,
		&memInfo,
		sizeof(memInfo)))
	{
		return 0;
	}

	/* Take the module */
	hModule = (HMODULE)memInfo.AllocationBase;
	if (!hModule)
	{
		return 0;
	}

	/* Get the file offset */
	dwFileOffset = HcFileOffsetByVirtualAddress(lpBaseAddress);
	if (!dwFileOffset)
	{
		return 0;
	}

	/* Allocate for the path of the module */
	lpModulePath = HcStringAllocW(MAX_PATH);

	if (!lpModulePath)
	{
		HcErrorSetDosError(STATUS_INSUFFICIENT_RESOURCES);
		return 0;
	}

	/* Acquire path of targetted module. */
	if (!GetModuleFileNameW(hModule, lpModulePath, MAX_PATH))
	{
		HcFree(lpModulePath);
		return 0;
	}

	/* Open the file */
	if (!(hFile = CreateFileW(lpModulePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL)))
	{
		HcFree(lpModulePath);
		return 0;
	}

	/* Go to the offset */
	if (!(SetFilePointer(hFile, dwFileOffset, 0, FILE_BEGIN)))
	{
		HcFree(lpModulePath);
		HcClose(hFile);
		return 0;
	}

	/* Read it */
	if (!ReadFile(hFile, lpBufferOut, dwCountToRead, &BytesRead, NULL))
	{
		HcFree(lpModulePath);
		HcClose(hFile);
		return 0;
	}

	HcFree(lpModulePath);
	HcClose(hFile);
	return BytesRead;
}

NTSTATUS WINAPI HcFileGetCurrentDirectoryW(ULONG buflen, LPWSTR buf)
{
	UNICODE_STRING* us = NULL;
	ULONG len = 0;

	RtlAcquirePebLock();

	us = &NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath;
	len = us->Length / sizeof(WCHAR);

	if (us->Buffer[len - 1] == '\\' && us->Buffer[len - 2] != ':')
	{
		len--;
	}
	
	if (buflen / sizeof(WCHAR) > len)
	{
		memcpy(buf, us->Buffer, len * sizeof(WCHAR));
		buf[len] = '\0';
	}
	else
	{
		len++;
	}

	RtlReleasePebLock();

	return len * sizeof(WCHAR);
}