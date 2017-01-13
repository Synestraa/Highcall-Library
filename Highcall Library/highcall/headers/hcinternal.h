/*++

Module Name:

hcinternal.h

Abstract:

This module defines internal memory handling functions. i.e. memcpy, memmove, memset... as well as helpers for defined functions.

Author:

Synestra 9/11/2016

Revision History:

Synestra 10/15/2016

--*/

#ifndef HC_INTERNAL_H
#define HC_INTERNAL_H

//
// Main definition file
//
#include "hcdef.h"

//
// For HcProcessQueryInformationModule
// 
#include "hcprocess.h"

//
// Outputs the main module's MODULE_INFORMATION struct.
//
#define HcInternalMainModule(pmi) (HcProcessQueryInformationModule(NtCurrentProcess, NULL, pmi)) 

//
// Offsetted pointer validation.
//
#define HcInternalValidateEx(lpcAddress, ptOffsets, tCount) (HcInternalValidate(HcInternalLocatePointer(lpcAddress, ptOffsets, tCount)))

//
// Reads an int from a multi offset pointer.
//
#define HcInternalReadInt32(lpcAddress) ((INT)(HcInternalValidate(lpcAddress) ? (*(DWORD*)(lpcAddress)) : 0))
#define HcInternalReadInt64(lpcAddress) ((INT64)(HcInternalValidate(lpcAddress) ? (*(DWORD64*)lpcAddress) : 0))

//
// Reads a string from a multi offset pointer.
//
#define HcInternalReadStringExA(lpcAddress, ptOffsets, tCount) ((LPSTR)HcInternalLocatePointer(lpcAddress, ptOffsets, tCount))
#define HcInternalReadStringExW(lpcAddress, ptOffsets, tCount) ((LPWSTR)HcInternalLocatePointer(lpcAddress, ptOffsets, tCount))

#if defined (__cplusplus)
extern "C" {
#endif

	//
	// Implemented in hcinternal.c
	//

	HC_EXTERN_API BOOLEAN HCAPI HcInternalCompare(PBYTE pbFirst, PBYTE pbSecond, SIZE_T tLength);

	HC_EXTERN_API PVOID HCAPI HcInternalCopy(PVOID pDst, PVOID pSrc, SIZE_T tCount);

	HC_EXTERN_API PVOID HCAPI HcInternalMove(PVOID pDst, PVOID pSrc, SIZE_T tCount);

	HC_EXTERN_API PVOID HCAPI HcInternalSet(PVOID pDst, BYTE bVal, SIZE_T tCount);

	HC_EXTERN_API BOOLEAN HCAPI HcInternalValidate(LPCVOID lpcAddress);

	HC_EXTERN_API LPVOID HCAPI HcInternalLocatePointer(LPCVOID lpcAddress, PSIZE_T ptOffsets, SIZE_T tCount);

	HC_EXTERN_API INT HCAPI HcInternalReadIntEx32(LPCVOID lpcAddress, PSIZE_T ptOffsets, SIZE_T tCount);
	HC_EXTERN_API INT64 HCAPI HcInternalReadIntEx64(LPCVOID lpcAddress, PSIZE_T ptOffsets, SIZE_T tCount);

	HC_EXTERN_API BOOLEAN HCAPI HcInternalMemoryWrite(LPVOID lpAddress, SIZE_T tLength, PBYTE pbNew);

	HC_EXTERN_API BOOLEAN HCAPI HcInternalMemoryNopInstruction(PVOID pAddress);

	HC_EXTERN_API SIZE_T HCAPI HcInternalPatternFind(LPCSTR szcPattern, LPCSTR szcMask, PHC_MODULE_INFORMATIONW pmInfo);


#if defined (__cplusplus)
}
#endif

#endif