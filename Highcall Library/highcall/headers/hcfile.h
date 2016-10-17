/*++

Module Name:

hcfile.h

Abstract:

This module declares custom file handling functions, as well as
reimplementations of kernel32.dll functions.

Author:

Synestra 10/10/2016, information was gathered from various sources.

Revision History:

--*/

#ifndef HC_FILE_H
#define HC_FILE_H

//
// Standard highcall definition file.
//

#include "hcdef.h"

//
// Contains out information about a file.
// Used by HcFileQueryInformation.
//

//
// Ansi
//

typedef struct _HC_FILE_INFORMATIONA
{
	DWORD Size;
} HC_FILE_INFORMATIONA, *PHC_FILE_INFORMATIONA;

//
// Unicode
//

typedef struct _HC_FILE_INFORMATIONW
{
	DWORD Size;
} HC_FILE_INFORMATIONW, *PHC_FILE_INFORMATIONW;

#if defined (__cplusplus)
extern "C" {
#endif

	//
	// Implemented in hcfile.c
	//

	BOOLEAN HCAPI HcFileExistsA(LPCSTR lpFilePath);
	BOOLEAN HCAPI HcFileExistsW(LPCWSTR lpFilePath);

	SIZE_T HCAPI HcFileSize(LPCSTR lpPath);

	BOOLEAN HCAPI HcFileQueryInformationW(LPCWSTR lpPath, PHC_FILE_INFORMATIONW fileInformation);
	BOOLEAN HCAPI HcFileQueryInformationA(LPCSTR lpPath, PHC_FILE_INFORMATIONA fileInformation);

	DWORD HCAPI HcFileOffsetByExportNameA(HMODULE hModule, LPCSTR lpExportName);
	DWORD HCAPI HcFileOffsetByExportNameW(HMODULE hModule, LPCWSTR lpExportName);

	DWORD HCAPI HcFileOffsetByVirtualAddress(LPCVOID lpAddress);

	SIZE_T HCAPI HcFileReadModuleA(HMODULE hModule, LPCSTR lpExportName, PBYTE lpBuffer, DWORD dwCount);
	SIZE_T HCAPI HcFileReadModuleW(HMODULE hModule, LPCWSTR lpExportName, PBYTE lpBuffer, DWORD dwCount);

	SIZE_T HCAPI HcFileReadAddress(LPCVOID lpAddress, PBYTE lpBufferOut, DWORD dwCountToRead);

#endif

#if defined (__cplusplus)
}
#endif