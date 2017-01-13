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

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringSplitA(LPSTR lpStr, const CHAR cDelimiter, LPSTR lpStrArrayOut[], PSIZE_T pdwCount)
{
	SIZE_T strSize = HcStringSecureLengthA(lpStr);
	if (strSize == 0)
	{
		return FALSE;
	}

	LPSTR lpCopy = (LPSTR)HcAlloc(strSize + 1);
	HcInternalCopy(lpCopy, lpStr, strSize);

	LPSTR lpToken;
	CHAR lpTerminatedDelim[] = { cDelimiter, ANSI_NULL };

	*pdwCount = 0;

	/* Get the first token. */
	lpToken = strtok(lpCopy, lpTerminatedDelim);

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
	
	HcFree(lpCopy);
	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringSplitW(LPWSTR lpStr, const WCHAR cDelimiter, LPWSTR lpStrArrayOut[], PSIZE_T pdwCount)
{
	SIZE_T strSize = HcStringSecureLengthW(lpStr);
	if (!strSize)
	{
		return FALSE;
	}

	LPWSTR lpCopy = (LPWSTR)HcAlloc(strSize + sizeof(WCHAR));
	LPWSTR lpToken;
	LPWSTR Buffer = NULL;
	const WCHAR lpTerminatedDelim[] = { cDelimiter, UNICODE_NULL };

	*pdwCount = 0;

	/* Get the first token. */
	lpToken = wcstok(lpCopy, lpTerminatedDelim, &Buffer);

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

	HcFree(lpCopy);
	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringSubtractA(LPCSTR lpStr, LPSTR lpOutStr, SIZE_T szStartIndex, SIZE_T szEndIndex)
{
	if (HcStringIsBad(lpStr))
		return FALSE;

	if (szEndIndex == -1)
	{
		szEndIndex = HcStringSecureLengthA(lpStr) - 1;
	}

	/* Create the null terminated sub string. */
	if (HcStringCopyA(lpOutStr, lpStr + szStartIndex, szEndIndex - szStartIndex))
	{
		lpOutStr[szEndIndex - szStartIndex] = ANSI_NULL;
		return TRUE;
	}

	return FALSE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringSubtractW(LPCWSTR lpStr, LPWSTR lpOutStr, SIZE_T szStartIndex, SIZE_T szEndIndex)
{
	if (HcStringIsBad(lpStr))
		return FALSE;

	if (szEndIndex == -1)
	{
		szEndIndex = HcStringSecureLengthW(lpStr) - 1;
	}

	/* Create the null terminated sub string. */
	if (HcStringCopyW(lpOutStr, lpStr + szStartIndex, szEndIndex - szStartIndex))
	{
		lpOutStr[szEndIndex - szStartIndex] = UNICODE_NULL;
		return TRUE;
	}

	return FALSE;
}

HC_EXTERN_API
SIZE_T
HCAPI
HcStringIndexOfA(LPCSTR lpStr, LPCSTR lpDelimiter, BOOLEAN CaseInsensitive)
{
	if (!HcStringSecureLengthA(lpStr))
	{
		return -1;
	}

	LPCSTR Buffer = HcStringWithinStringA(lpStr, lpDelimiter, CaseInsensitive);
	return Buffer ? Buffer - lpStr : -1;
}

HC_EXTERN_API
SIZE_T
HCAPI
HcStringIndexOfW(LPCWSTR lpStr, LPCWSTR lpDelimiter, BOOLEAN CaseInsensitive)
{
	if (!HcStringSecureLengthW(lpStr))
	{
		return -1;
	}

	LPCWSTR Buffer = HcStringWithinStringW(lpStr, lpDelimiter, CaseInsensitive);
	return Buffer ? Buffer - lpStr : -1;
}

HC_EXTERN_API
SIZE_T
HCAPI
HcStringEndOfA(LPCSTR lpStr, LPCSTR lpDelimiter, BOOLEAN CaseInsensitive)
{
	SIZE_T tDelimSize = HcStringSecureLengthA(lpDelimiter);
	if (!HcStringSecureLengthA(lpStr) || !tDelimSize)
		return -1;

	LPCSTR Buffer = HcStringWithinStringA(lpStr, lpDelimiter, CaseInsensitive);
	return Buffer ? (Buffer - lpStr) + tDelimSize : -1;
}

HC_EXTERN_API
SIZE_T
HCAPI
HcStringEndOfW(LPCWSTR lpStr, LPCWSTR lpDelimiter, BOOLEAN CaseInsensitive)
{
	SIZE_T tDelimSize = HcStringSecureLengthW(lpDelimiter);
	if (!HcStringSecureLengthW(lpStr) || !tDelimSize)
	{
		return -1;
	}

	LPCWSTR Buffer = HcStringWithinStringW(lpStr, lpDelimiter, CaseInsensitive);
	return Buffer ? (Buffer - lpStr) + tDelimSize : -1;
}

HC_EXTERN_API
SIZE_T
HCAPI
HcStringSecureLengthA(LPCSTR lpString)
{
	if (HcStringIsBad(lpString))
		return 0;

	return HcStringSizeA(lpString) / sizeof(CHAR);
}

HC_EXTERN_API
SIZE_T
HCAPI
HcStringSecureLengthW(LPCWSTR lpString)
{
	if (HcStringIsBad(lpString))
		return 0;

	return HcStringSizeW(lpString) / sizeof(WCHAR);
}

HC_EXTERN_API
SIZE_T
HCAPI
HcStringSizeA(LPCSTR szcString)
{
	CONST CHAR *p = szcString;

	while (*p)
		p++;

	return (p - szcString) * sizeof(CHAR);
}

HC_EXTERN_API
SIZE_T
HCAPI
HcStringSizeW(LPCWSTR szcString)
{
	CONST WCHAR *p = szcString;

	while (*p)
		p++;

	return (p - szcString) * sizeof(WCHAR);
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringToLowerA(LPSTR lpStr)
{
	if (HcStringIsBad(lpStr))
		return FALSE;

	LPSTR p = lpStr;
	for (; *p; ++p) 
		*p = tolower(*p);

	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringToLowerW(LPWSTR lpStr)
{
	if (HcStringIsBad(lpStr))
		return FALSE;

	LPWSTR p = lpStr;
	for (; *p; ++p)
		*p = tolower(*p);

	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringToUpperA(LPSTR lpStr)
{
	if (HcStringIsBad(lpStr))
		return FALSE;

	for (; *lpStr; *lpStr++)
		*lpStr = toupper(*lpStr);

	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringToUpperW(LPWSTR lpStr)
{
	if (HcStringIsBad(lpStr))
		return FALSE;

	for (; *lpStr; *lpStr++)
		*lpStr = towupper(*lpStr);

	return TRUE;
}

HC_EXTERN_API
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

	Size1 = HcStringSizeA(lpString1);
	Size2 = HcStringSizeA(lpString2);

	if (Size1 != Size2)
		return FALSE;

	if (CaseInSensitive)
	{
		LPSTR lpCopy1;
		LPSTR lpCopy2;

		lpCopy1 = (LPSTR)HcAlloc(Size1 + sizeof(CHAR));

		HcStringCopyA(lpCopy1, lpString1, Size1);
		HcStringToLowerA(lpCopy1);

		lpCopy2 = (LPSTR)HcAlloc(Size2 + sizeof(CHAR));

		HcStringCopyA(lpCopy2, lpString2, Size2);
		HcStringToLowerA(lpCopy2);

		Return = HcInternalCompare((PBYTE)lpCopy1, (PBYTE)lpCopy2, Size1);

		HcFree(lpCopy1);
		HcFree(lpCopy2);

		return Return;
	}

	return HcInternalCompare((PBYTE)lpString1, (PBYTE)lpString2, Size1);
}

HC_EXTERN_API
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

	Size1 = HcStringSizeW(lpString1);
	Size2 = HcStringSizeW(lpString2);

	if (Size1 != Size2)
		return FALSE;

	if (CaseInSensitive)
	{
		LPWSTR lpCopy1;
		LPWSTR lpCopy2;

		lpCopy1 = (LPWSTR)HcAlloc(Size1 + sizeof(WCHAR));

		HcStringCopyW(lpCopy1, lpString1, Size1);
		HcStringToLowerW(lpCopy1);

		lpCopy2 = (LPWSTR)HcAlloc(Size2 + sizeof(WCHAR));

		HcStringCopyW(lpCopy2, lpString2, Size2);
		HcStringToLowerW(lpCopy2);

		Return = HcInternalCompare((PBYTE)lpCopy1, (PBYTE)lpCopy2, Size1);

		HcFree(lpCopy1);
		HcFree(lpCopy2);

		return Return;
	}

	return HcInternalCompare((PBYTE)lpString1, (PBYTE)lpString2, Size1);
}

HC_EXTERN_API
LPSTR
HCAPI
HcStringWithinStringA(LPCSTR szStr, LPCSTR szToFind, BOOLEAN CaseInsensitive)
{
	SIZE_T tIndex = 0;
	SIZE_T tLen;
	LPSTR lpStr1 = (LPSTR)szStr, lpStr2 = (LPSTR)szToFind;
	SIZE_T tSize1, tSize2;

	if (HcStringIsBad(lpStr1) || HcStringIsBad(lpStr2))
		return NULL;

	if (CaseInsensitive)
	{
		tSize1 = HcStringSizeA(lpStr1);
		tSize2 = HcStringSizeA(lpStr2);

		lpStr1 = (LPSTR)HcAlloc(tSize1 + sizeof(CHAR));

		HcStringCopyA(lpStr1, szStr, tSize1);
		HcStringToLowerA(lpStr1);

		lpStr2 = (LPSTR)HcAlloc(tSize2 + sizeof(CHAR));

		HcStringCopyA(lpStr2, szToFind, tSize2);
		HcStringToLowerA(lpStr2);
	}

	for (tLen = HcStringSizeA(lpStr2);
		*(CHAR*)(lpStr1 + tIndex) != UNICODE_NULL && !HcInternalCompare((PBYTE)(lpStr1 + tIndex), (PBYTE)lpStr2, tLen);
		tIndex++);

	if (*(CHAR*)(lpStr1 + tIndex) == UNICODE_NULL)
		return NULL;

	if (CaseInsensitive)
	{
		HcFree(lpStr1);
		HcFree(lpStr2);
	}

	return (LPSTR)(szStr + tIndex);
}

HC_EXTERN_API
LPWSTR
HCAPI
HcStringWithinStringW(LPCWSTR szStr, LPCWSTR szToFind, BOOLEAN CaseInsensitive)
{
	SIZE_T tIndex = 0;
	SIZE_T tLen;
	LPWSTR lpStr1 = (LPWSTR)szStr, lpStr2 = (LPWSTR)szToFind;
	SIZE_T tSize1, tSize2;

	if (HcStringIsBad(lpStr1) || HcStringIsBad(lpStr2))
		return NULL;

	if (CaseInsensitive)
	{
		tSize1 = HcStringSizeW(lpStr1);
		tSize2 = HcStringSizeW(lpStr2);

		lpStr1 = (LPWSTR)HcAlloc(tSize1 + sizeof(WCHAR));

		HcStringCopyW(lpStr1, szStr, tSize1);
		HcStringToLowerW(lpStr1);

		lpStr2 = (LPWSTR)HcAlloc(tSize2 + sizeof(WCHAR));

		HcStringCopyW(lpStr2, szToFind, tSize2);
		HcStringToLowerW(lpStr2);
	}

	for (tLen = HcStringSizeW(lpStr2);
		*(WCHAR*)(lpStr1 + tIndex) != UNICODE_NULL && !HcInternalCompare((PBYTE)(lpStr1 + tIndex), (PBYTE)lpStr2, tLen);
		tIndex++);

	if (*(WCHAR*)(lpStr1 + tIndex) == UNICODE_NULL)
		return NULL;

	if (CaseInsensitive)
	{
		HcFree(lpStr1);
		HcFree(lpStr2);
	}

	return ((LPWSTR)(szStr + tIndex));
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringContainsA(LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive)
{
	return HcStringWithinStringA(lpString1, lpString2, CaseInSensitive) > 0;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringContainsW(LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInsensitive)
{
	return HcStringWithinStringW(lpString1, lpString2, CaseInsensitive) > 0;
}

//
// When using this function, take care for UNICODE and ANSI type size difference.
//
HC_EXTERN_API
BOOLEAN
HCAPI
HcStringCopyConvertAtoW(LPCSTR lpStringToConvert,
	LPWSTR lpStringOut,
	SIZE_T Size)
{
	if (!MultiByteToWideChar(CP_UTF8,
		0,
		lpStringToConvert,
		-1,
		lpStringOut, 
		(DWORD)(Size / sizeof(WCHAR) + 1)))
	{
		return FALSE;
	}

	lpStringOut[Size / sizeof(WCHAR)] = UNICODE_NULL;

	return TRUE;
}

//
// When using this function, take care for UNICODE and ANSI type size difference.
//
HC_EXTERN_API
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
HC_EXTERN_API
LPWSTR
HCAPI
HcStringConvertAtoW(IN LPCSTR lpStringConvert)
{
	LPWSTR convertedOut;
	SIZE_T sizeOfString = 0;
	
	sizeOfString = HcStringSizeA(lpStringConvert);
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
HC_EXTERN_API
LPSTR
HCAPI
HcStringConvertWtoA(IN LPCWSTR lpStringConvert)
{
	LPSTR convertedOut;
	SIZE_T sizeOfString = 0;

	sizeOfString = HcStringSizeW(lpStringConvert);
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

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringCopyA(IN LPSTR szOut, LPCSTR szcIn, SIZE_T tSize)
{
	SIZE_T Size = tSize;
	if (!Size)
	{
		Size = HcStringSizeA(szOut);
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
	szOut[Size / sizeof(CHAR)] = ANSI_NULL;

	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringCopyW(IN LPWSTR szOut, LPCWSTR szcIn, SIZE_T tSize)
{
	SIZE_T Size = tSize;
	if (!Size)
	{
		Size = HcStringSizeW(szOut);
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
	szOut[Size / sizeof(WCHAR)] = UNICODE_NULL;

	return TRUE;
}