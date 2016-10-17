/*++

Module Name:

hcstring.c

Abstract:

Implements various string helper functions from hcstring.h module. Support should be kept for both Unicode (W affix) and Ansi (A affix)

Author:

Synestra 10/14/2016

Revision History:

--*/

//
// For strtok, wcstok
//
#define _CRT_SECURE_NO_WARNINGS

//
// For ERROR_INVALID_PARAMETER, CP_UTF8, WideCharToMultiByte(), MultiByteToWideChar()
//
#include <windows.h>

//
// For structure definitions
//
#include "../headers/hcstring.h"

//
// For HcFree and HcAlloc
//
#include "../headers/hcvirtual.h"

BOOLEAN
HCAPI
HcStringSplitA(LPSTR lpStr, const char cDelimiter, LPSTR lpStrArrayOut[], PSIZE_T pdwCount)
{
	LPSTR lpToken;
	CHAR lpTerminatedDelim[] = { cDelimiter, ANSI_NULL };

	*pdwCount = 0;

	if (HcStringSecureLengthA(lpStr) == 0)
	{
		return FALSE;
	}

	/* Get the first token. */
	lpToken = strtok(lpStr, lpTerminatedDelim);

	/* Loop over the splits. */
	while (lpToken)
	{
		/* Duplicate the string and insert into return array. */
		lpStrArrayOut[*pdwCount] = _strdup(lpToken);

		/* Acquire next token. */
		lpToken = strtok(0, lpTerminatedDelim);
		*pdwCount += 1;
	}

	/* Null terminate final string. */
	lpStrArrayOut[*pdwCount] = '\0';

	return TRUE;
}


BOOLEAN
HCAPI
HcStringSplitW(LPWSTR lpStr, const wchar_t cDelimiter, LPWSTR lpStrArrayOut[], PSIZE_T pdwCount)
{
	LPWSTR lpToken;
	LPWSTR Buffer;
	const WCHAR lpTerminatedDelim[] = { cDelimiter, UNICODE_NULL };

	*pdwCount = 0;

	if (HcStringSecureLengthW(lpStr) == 0)
	{
		return FALSE;
	}

	/* Get the first token. */
	lpToken = wcstok(lpStr, lpTerminatedDelim, &Buffer);

	/* Loop over the splits. */
	while (lpToken)
	{
		/* Duplicate the string and insert into return array. */
		lpStrArrayOut[*pdwCount] = _wcsdup(lpToken);

		/* Acquire next token. */
		lpToken = wcstok(0, lpTerminatedDelim, &Buffer);
		*pdwCount += 1;
	}

	/* Null terminate final string. */
	lpStrArrayOut[*pdwCount] = UNICODE_NULL;

	return TRUE;
}


BOOLEAN
HCAPI
HcStringSubtractA(LPCSTR lpStr, LPSTR lpOutStr, SIZE_T szStartIndex, SIZE_T szEndIndex)
{
	if (HcStringIsBad(lpStr))
	{
		return FALSE;
	}

	/* Create the null terminated sub string. */
	if (HcStringCopyA(lpOutStr, lpStr + szStartIndex, szEndIndex - szStartIndex))
	{
		lpOutStr[szEndIndex - szStartIndex] = ANSI_NULL;
		return TRUE;
	}

	return FALSE;
}


BOOLEAN
HCAPI
HcStringSubtractW(LPCWSTR lpStr, LPWSTR lpOutStr, SIZE_T szStartIndex, SIZE_T szEndIndex)
{
	if (HcStringIsBad(lpStr))
	{
		return FALSE;
	}

	/* Create the null terminated sub string. */
	if (HcStringCopyW(lpOutStr, lpStr + szStartIndex, szEndIndex - szStartIndex))
	{
		lpOutStr[szEndIndex - szStartIndex] = UNICODE_NULL;
		return TRUE;
	}

	return FALSE;
}


SIZE_T
HCAPI
HcStringIndexOfA(LPCSTR lpStr, LPCSTR lpDelimiter)
{
	if (!HcStringSecureLengthA(lpStr))
	{
		return -1;
	}

	LPCSTR Buffer = strstr(lpStr, lpDelimiter);
	return Buffer ? Buffer - lpStr : -1;
}


SIZE_T
HCAPI
HcStringIndexOfW(LPCWSTR lpStr, LPCWSTR lpDelimiter)
{
	if (!HcStringSecureLengthW(lpStr))
	{
		return -1;
	}

	LPCWSTR Buffer = wcsstr(lpStr, lpDelimiter);
	return Buffer ? Buffer - lpStr : -1;
}

DWORD
HCAPI
HcStringSecureLengthA(LPCSTR lpString)
{
	DWORD Length = 0;

	if (HcStringIsBad(lpString))
	{
		return 0;
	}

	for (; *lpString; *lpString++)
		Length++;

	return Length * sizeof(CHAR);
}

DWORD
HCAPI
HcStringSecureLengthW(LPCWSTR lpString)
{
	DWORD Length = 0;

	if (HcStringIsBad(lpString))
	{
		return 0;
	}

	for (; *lpString; *lpString++)
		Length++;

	return Length * sizeof(WCHAR);
}

DWORD
HCAPI
HcStringLengthA(LPCSTR lpString)
{
	DWORD Length = 0;

	for (; *lpString; *lpString++)
		Length++;

	return Length * sizeof(CHAR);
}

DWORD
HCAPI
HcStringLengthW(LPCWSTR lpString)
{
	DWORD Length = 0;

	for (; *lpString; *lpString++)
		Length++;

	return Length * sizeof(WCHAR);
}


BOOLEAN
HCAPI
HcStringToLowerA(LPSTR lpStr)
{
	if (HcStringIsBad(lpStr))
	{
		return FALSE;
	}

	for (; *lpStr; *lpStr++)
		*lpStr = tolower(*lpStr);

	return TRUE;
}


BOOLEAN
HCAPI
HcStringToLowerW(LPWSTR lpStr)
{
	if (HcStringIsBad(lpStr))
	{
		return FALSE;
	}

	for (; *lpStr; *lpStr++)
		*lpStr = towlower(*lpStr);

	return TRUE;
}


BOOLEAN
HCAPI
HcStringToUpperA(LPSTR lpStr)
{
	if (HcStringIsBad(lpStr))
	{
		return FALSE;
	}

	for (; *lpStr; *lpStr++)
		*lpStr = toupper(*lpStr);

	return TRUE;
}


BOOLEAN
HCAPI
HcStringToUpperW(LPWSTR lpStr)
{
	if (HcStringIsBad(lpStr))
	{
		return FALSE;
	}

	for (; *lpStr; *lpStr++)
		*lpStr = towupper(*lpStr);

	return TRUE;
}

BOOLEAN
HCAPI
HcStringEqualA(LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive)
{
	BOOLEAN Return;
	SIZE_T Size1, Size2;
	BOOLEAN bString1, bString2;

	bString1 = HcStringIsBad(lpString1);
	bString2 = HcStringIsBad(lpString2);

	if (bString1 && bString2)
		return TRUE;

	if (!bString1 && bString2)
		return FALSE;

	if (bString1 && !bString2)
		return FALSE;

	Size1 = HcStringLengthA(lpString1);
	Size2 = HcStringLengthA(lpString2);

	if (Size1 != Size2)
		return FALSE;

	if (CaseInSensitive)
	{
		LPSTR lpCopy1, lpCopy2;

		lpCopy1 = (LPSTR)HcAlloc(Size1 + sizeof(CHAR));

		HcStringCopyA(lpCopy1, lpString1, Size1);
		HcStringToLowerA(lpCopy1);

		lpCopy2 = (LPSTR)HcAlloc(Size2 + sizeof(CHAR));

		HcStringCopyA(lpCopy2, lpString2, Size2);
		HcStringToLowerA(lpCopy2);

		Return = strcmp(lpCopy1, lpCopy2) == 0 ? TRUE : FALSE;

		HcFree(lpCopy1);
		HcFree(lpCopy2);

		return Return;
	}

	return !strcmp(lpString1, lpString2);
}


BOOLEAN
HCAPI
HcStringEqualW(LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInSensitive)
{
	BOOLEAN Return;
	SIZE_T Size1, Size2;
	BOOLEAN bString1, bString2;

	bString1 = HcStringIsBad(lpString1);
	bString2 = HcStringIsBad(lpString2);

	if (bString1 && bString2)
		return TRUE;

	if (!bString1 && bString2)
		return FALSE;

	if (bString1 && !bString2)
		return FALSE;

	Size1 = HcStringLengthW(lpString1);
	Size2 = HcStringLengthW(lpString2);

	if (Size1 != Size2)
		return FALSE;

	if (CaseInSensitive)
	{
		LPWSTR lpCopy1, lpCopy2;

		lpCopy1 = (LPWSTR)HcAlloc(Size1 + sizeof(WCHAR));

		HcStringCopyW(lpCopy1, lpString1, Size1);
		HcStringToLowerW(lpCopy1);

		lpCopy2 = (LPWSTR)HcAlloc(Size2 + sizeof(WCHAR));

		HcStringCopyW(lpCopy2, lpString2, Size2);
		HcStringToLowerW(lpCopy2);

		Return = wcscmp(lpCopy1, lpCopy2) == 0 ? TRUE : FALSE;

		HcFree(lpCopy1);
		HcFree(lpCopy2);

		return Return;
	}

	return !wcscmp(lpString1, lpString2);
}



BOOLEAN
HCAPI
HcStringContainsA(LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive)
{
	BOOLEAN Return;
	BOOLEAN bString1, bString2;

	bString1 = HcStringIsBad(lpString1);
	bString2 = HcStringIsBad(lpString2);

	if (bString1 && bString2)
		return TRUE;

	if (!bString1 && bString2)
		return FALSE;

	if (bString1 && !bString2)
		return FALSE;

	if (CaseInSensitive)
	{
		LPSTR lpCopy1, lpCopy2;
		SIZE_T Size1, Size2;

		Size1 = HcStringLengthA(lpString1);
		Size2 = HcStringLengthA(lpString2);

		lpCopy1 = (LPSTR)HcAlloc(Size1 + sizeof(CHAR));

		HcStringCopyA(lpCopy1, lpString1, Size1);
		HcStringToLowerA(lpCopy1);

		lpCopy2 = (LPSTR)HcAlloc(Size2 + sizeof(CHAR));

		HcStringCopyA(lpCopy2, lpString2, Size2);
		HcStringToLowerA(lpCopy2);

		Return = strstr(lpCopy1, lpCopy2) > 0;

		HcFree(lpCopy1);
		HcFree(lpCopy2);

		return Return;
	}

	return strstr(lpString1, lpString2) > 0;
}


BOOLEAN
HCAPI
HcStringContainsW(LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInSensitive)
{
	BOOLEAN Return;
	BOOLEAN bString1, bString2;

	bString1 = HcStringIsBad(lpString1);
	bString2 = HcStringIsBad(lpString2);

	if (bString1 && bString2)
		return TRUE;

	if (!bString1 && bString2)
		return FALSE;

	if (bString1 && !bString2)
		return FALSE;

	if (CaseInSensitive)
	{
		LPWSTR lpCopy1, lpCopy2;
		SIZE_T Size1, Size2;

		Size1 = HcStringLengthW(lpString1);
		Size2 = HcStringLengthW(lpString2);

		lpCopy1 = (LPWSTR)HcAlloc(Size1 + sizeof(WCHAR));

		HcStringCopyW(lpCopy1, lpString1, Size1);
		HcStringToLowerW(lpCopy1);

		lpCopy2 = (LPWSTR)HcAlloc(Size2 + sizeof(WCHAR));

		HcStringCopyW(lpCopy2, lpString2, Size2);
		HcStringToLowerW(lpCopy2);

		Return = wcsstr(lpCopy1, lpCopy2) > 0;

		HcFree(lpCopy1);
		HcFree(lpCopy2);

		return Return;
	}

	return wcsstr(lpString1, lpString2) > 0;
}

//
// When using this function, take care for UNICODE and ANSI type size difference.
//
BOOLEAN
HCAPI
HcStringCopyConvertAtoW(LPCSTR lpStringToConvert,
	LPWSTR lpStringOut,
	SIZE_T Size)
{
	if (!MultiByteToWideChar(CP_UTF8,
		0,
		lpStringToConvert,
		(DWORD)Size,
		lpStringOut, 
		(DWORD)Size))
	{
		return FALSE;
	}

	lpStringOut[Size / sizeof(WCHAR)] = UNICODE_NULL;

	return TRUE;
}

//
// When using this function, take care for UNICODE and ANSI type size difference.
//
BOOLEAN
HCAPI
HcStringCopyConvertWtoA(LPCWSTR lpStringToConvert,
	LPSTR lpStringOut,
	SIZE_T Size)
{
	/* Do the convert. */
	if (!WideCharToMultiByte(CP_UTF8,
		0,
		lpStringToConvert,
		-1,
		lpStringOut,
		(DWORD)Size,
		NULL,
		NULL))
	{
		return FALSE;
	}

	lpStringOut[Size / sizeof(CHAR)] = ANSI_NULL;

	return TRUE;
}

//
// Allocates and converts using HcStringCopyConvert function.
// Deallocate using HcFree()
//
LPWSTR
HCAPI
HcStringConvertAtoW(IN LPCSTR lpStringConvert)
{
	LPWSTR convertedOut;
	SIZE_T sizeOfString;
	
	sizeOfString = HcStringSecureLengthA(lpStringConvert);
	if (!sizeOfString)
	{
		return NULL;
	}

	//
	// Conversion from UNICODE to ANSI required a size reduction.
	// 1 char ANSI = 1 byte
	// 1 char UNICODE = 2 bytes
	//

	sizeOfString *= 2;

	convertedOut = (LPWSTR) HcAlloc(sizeOfString + sizeof(WCHAR));
	if (!convertedOut)
	{
		return NULL;
	}

	if (!HcStringCopyConvertAtoW(lpStringConvert, convertedOut, sizeOfString))
	{
		return NULL;
	}

	return convertedOut;
}

//
// Allocates and converts using HcStringCopyConvert function.
// Deallocate using HcFree()
//
LPSTR
HCAPI
HcStringConvertWtoA(IN LPCWSTR lpStringConvert)
{
	LPSTR convertedOut;
	SIZE_T sizeOfString;

	sizeOfString = HcStringSecureLengthW(lpStringConvert);
	if (!sizeOfString)
	{
		return NULL;
	}

	//
	// Conversion from UNICODE to ANSI required a size reduction.
	// 1 char ANSI = 1 byte
	// 1 char UNICODE = 2 bytes
	//

	sizeOfString /= 2;

	convertedOut = (LPSTR)HcAlloc(sizeOfString + sizeof(CHAR));
	if (!convertedOut)
	{
		return NULL;
	}

	if (!HcStringCopyConvertWtoA(lpStringConvert, convertedOut, sizeOfString))
	{
		return NULL;
	}

	return convertedOut;
}

BOOLEAN HCAPI HcStringCopyA(IN LPSTR szOut, LPCSTR szcIn, SIZE_T tSize)
{
	SIZE_T Size = tSize;
	if (!Size)
	{
		Size = HcStringSecureLengthA(szOut);
		if (!Size)
		{
			//
			// Invalid pointer.
			//
			return FALSE;
		}
	}

	//
	// Do the copy.
	//
	HcInternalCopy(szOut, (PVOID)szcIn, Size);

	//
	// Terminate the string.
	//
	szOut[Size] = ANSI_NULL;

	return TRUE;
}

BOOLEAN HCAPI HcStringCopyW(IN LPWSTR szOut, LPCWSTR szcIn, SIZE_T tSize)
{
	SIZE_T Size = tSize;
	if (!Size)
	{
		Size = HcStringSecureLengthW(szOut);
		if (!Size)
		{
			//
			// Invalid pointer.
			//
			return FALSE;
		}
	}

	//
	// Do the copy.
	//
	HcInternalCopy(szOut, (PVOID)szcIn, Size);

	//
	// Terminate the string.
	//
	szOut[Size] = UNICODE_NULL;

	return TRUE;
}