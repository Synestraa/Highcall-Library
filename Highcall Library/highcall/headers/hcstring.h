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
#include "../headers/hcinternal.h"

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

	//
	// Implemented in hcstring.c
	//

	BOOLEAN HCAPI HcStringSplitA(LPSTR lpStr, const char cDelimiter, LPSTR lpStrArrayOut[], PSIZE_T pdwCount);
	BOOLEAN HCAPI HcStringSplitW(LPWSTR lpStr, const wchar_t cDelimiter, LPWSTR lpStrArrayOut[], PSIZE_T pdwCount);

	BOOLEAN HCAPI HcStringSubtractA(LPCSTR lpStr, LPSTR lpOutStr, SIZE_T szStartIndex, SIZE_T szEndIndex);
	BOOLEAN HCAPI HcStringSubtractW(LPCWSTR lpStr, LPWSTR lpOutStr, SIZE_T szStartIndex, SIZE_T szEndIndex);

	SIZE_T HCAPI HcStringIndexOfA(LPCSTR lpStr, LPCSTR lpDelimiter);
	SIZE_T HCAPI HcStringIndexOfW(LPCWSTR lpStr, LPCWSTR lpDelimiter);

	DWORD HCAPI HcStringSecureLengthA(LPCSTR lpString);
	DWORD HCAPI HcStringSecureLengthW(LPCWSTR lpString);

	DWORD HCAPI HcStringLengthA(LPCSTR lpString);
	DWORD HCAPI HcStringLengthW(LPCWSTR lpString);

	BOOLEAN HCAPI HcStringToLowerA(LPSTR lpStr);
	BOOLEAN HCAPI HcStringToLowerW(LPWSTR lpStr);

	BOOLEAN HCAPI HcStringToUpperA(LPSTR lpStr);

	BOOLEAN HCAPI HcStringEqualA(LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive);
	BOOLEAN HCAPI HcStringEqualW(LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInSensitive);

	BOOLEAN HCAPI HcStringContainsA(LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive);
	BOOLEAN HCAPI HcStringContainsW(LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInSensitive);

	BOOLEAN HCAPI HcStringCopyConvertAtoW(LPCSTR lpStringToConvert, LPWSTR lpStringOut, SIZE_T Size);
	BOOLEAN HCAPI HcStringCopyConvertWtoA(LPCWSTR lpStringToConvert, LPSTR lpStringOut, SIZE_T Size); 
	
	LPWSTR HCAPI HcStringConvertAtoW(IN LPCSTR lpStringConvert);
	LPSTR HCAPI HcStringConvertWtoA(IN LPCWSTR lpStringConvert);

	BOOLEAN HCAPI HcStringCopyA(IN LPSTR szOut, LPCSTR szcIn, SIZE_T tSize);
	BOOLEAN HCAPI HcStringCopyW(IN LPWSTR szOut, LPCWSTR szcIn, SIZE_T tSize);

#if defined (__cplusplus)
}
#endif

#endif HC_STRING_H // HC_STRING_H