/*++

Module Name:

hcstring.h

Abstract:

Defines the structure of various string helpers, as well as implements macro string helpers.

Author:

Synestra 10/14/2016

Revision History:

--*/

#ifndef HC_STRING_H
#define HC_STRING_H

#include "hcdef.h"

//
// HcInternalValidate, HcInternalCopy
//
#include "../public/hcinternal.h"

#define HcStringAnsiLengthToUnicode(size) (size * sizeof(WCHAR))
#define HcStringUnicodeLengthToAnsi(size) (size / sizeof(WCHAR))

#define HcStringTerminateA(lpStr, size) (lpStr[size] = ANSI_NULL)
#define HcStringTerminateW(lpStr, size) (lpStr[size] = UNICODE_NULL)

//
// Determines whether the pointer is invalid.
//
#define HcStringIsBad(lpcStr) (!HcInternalValidate((LPVOID)lpcStr))

//
// Determines whether the pointer to a string is invalid or empty. i.e. "" 
//
#define HcStringIsNullOrEmpty(lpcStr) (HcStringIsBad(lpcStr) || lpcStr[0] == 0)

#if defined (__cplusplus)
extern "C" {
#endif

	HC_EXTERN_API LPSTR HCAPI HcStringAllocA(DWORD tSize);
	HC_EXTERN_API LPWSTR HCAPI HcStringAllocW(DWORD tSize);

	HC_EXTERN_API BOOLEAN HCAPI HcStringSplitA(LPSTR lpStr, const CHAR cDelimiter, LPSTR lpStrArrayOut[], PDWORD pdwCount);
	HC_EXTERN_API BOOLEAN HCAPI HcStringSplitW(LPWSTR lpStr, const WCHAR cDelimiter, LPWSTR lpStrArrayOut[], PDWORD pdwCount);

	HC_EXTERN_API BOOLEAN HCAPI HcStringSubtractA(LPCSTR lpStr, LPSTR lpOutStr, DWORD szStartIndex, DWORD szEndIndex);
	HC_EXTERN_API BOOLEAN HCAPI HcStringSubtractW(LPCWSTR lpStr, LPWSTR lpOutStr, DWORD szStartIndex, DWORD szEndIndex);

	HC_EXTERN_API DWORD HCAPI HcStringIndexOfA(LPCSTR lpStr, LPCSTR lpDelimiter, BOOLEAN CaseInsensitive);
	HC_EXTERN_API DWORD HCAPI HcStringIndexOfW(LPCWSTR lpStr, LPCWSTR lpDelimiter, BOOLEAN CaseInsensitive);

	HC_EXTERN_API DWORD HCAPI HcStringEndOfA(LPCSTR lpStr, LPCSTR lpDelimiter, BOOLEAN CaseInsensitive);
	HC_EXTERN_API DWORD HCAPI HcStringEndOfW(LPCWSTR lpStr, LPCWSTR lpDelimiter, BOOLEAN CaseInsensitive);

	HC_EXTERN_API DWORD HCAPI HcStringLenA(LPCSTR lpString);
	HC_EXTERN_API DWORD HCAPI HcStringLenW(LPCWSTR lpString);

	HC_EXTERN_API DWORD HCAPI HcStringSizeA(LPCSTR lpString);
	HC_EXTERN_API DWORD HCAPI HcStringSizeW(LPCWSTR lpString);

	HC_EXTERN_API BOOLEAN HCAPI HcStringToLowerA(LPSTR lpStr);
	HC_EXTERN_API BOOLEAN HCAPI HcStringToLowerW(LPWSTR lpStr);

	HC_EXTERN_API BOOLEAN HCAPI HcStringToUpperA(LPSTR lpStr);
	HC_EXTERN_API BOOLEAN HCAPI HcStringToUpperW(LPWSTR lpStr);

	HC_EXTERN_API BOOLEAN HCAPI HcStringCompareContentA(LPCSTR lpStr1, LPCSTR lpStr2);
	HC_EXTERN_API BOOLEAN HCAPI HcStringCompareContentW(LPCWSTR lpStr1, LPCWSTR lpStr2);

	HC_EXTERN_API BOOLEAN HCAPI HcStringEqualA(LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive);
	HC_EXTERN_API BOOLEAN HCAPI HcStringEqualW(LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInSensitive);

	HC_EXTERN_API LPSTR HCAPI HcStringWithinStringA(LPCSTR szStr, LPCSTR szToFind, BOOLEAN CaseInsensitive);
	HC_EXTERN_API LPWSTR HCAPI HcStringWithinStringW(LPCWSTR szStr, LPCWSTR szToFind, BOOLEAN CaseInsensitive);

	HC_EXTERN_API BOOLEAN HCAPI HcStringContainsA(LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive);
	HC_EXTERN_API BOOLEAN HCAPI HcStringContainsW(LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInSensitive);

	HC_EXTERN_API BOOLEAN HCAPI HcStringCopyConvertAtoW(LPCSTR lpStringToConvert, LPWSTR lpStringOut, DWORD Size);
	HC_EXTERN_API BOOLEAN HCAPI HcStringCopyConvertWtoA(LPCWSTR lpStringToConvert, LPSTR lpStringOut, DWORD Size);
	
	HC_EXTERN_API LPWSTR HCAPI HcStringConvertAtoW(IN LPCSTR lpStringConvert);
	HC_EXTERN_API LPSTR HCAPI HcStringConvertWtoA(IN LPCWSTR lpStringConvert);

	HC_EXTERN_API BOOLEAN HCAPI HcStringCopyA(IN LPSTR szOut, LPCSTR szcIn, DWORD tSize);
	HC_EXTERN_API BOOLEAN HCAPI HcStringCopyW(IN LPWSTR szOut, LPCWSTR szcIn, DWORD tSize);

#if defined (__cplusplus)
}
#endif

#endif HC_STRING_H // HC_STRING_H