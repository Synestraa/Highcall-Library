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
// For ERROR_INVALID_PARAMETER, CP_UTF8, WideCharToMultiByte(), MultiByteToWideChar()
//
#include <windows.h>

//
// For structure definitions
//
#include "../public/hcstring.h"

//
// For HcFree and HcAlloc
//
#include "../public/hcvirtual.h"

HC_EXTERN_API LPSTR HCAPI HcStringAllocA(DWORD tSize)
{
	return (LPSTR) HcAlloc(tSize * sizeof(CHAR) + sizeof(ANSI_NULL));
}

HC_EXTERN_API LPWSTR HCAPI HcStringAllocW(DWORD tSize)
{
	return (LPWSTR) HcAlloc(tSize * sizeof(WCHAR) + sizeof(UNICODE_NULL));
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringSplitA(LPSTR lpStr, const CHAR cDelimiter, LPSTR lpStrArrayOut[], PDWORD pdwCount)
{
	DWORD strSize = HcStringLenA(lpStr);
	if (strSize == 0)
	{
		return FALSE;
	}

	LPSTR lpCopy = HcStringAllocA(strSize);
	HcInternalCopy(lpCopy, lpStr, strSize);

	LPSTR lpToken;
	CHAR lpTerminatedDelim[] = { cDelimiter, ANSI_NULL };

	*pdwCount = 0;

	/* Get the first token. */
	lpToken = strtok_s(lpCopy, lpTerminatedDelim, &lpToken);

	/* Loop over the splits. */
	while (lpToken)
	{
		/* Duplicate the string and insert into return array. */
		lpStrArrayOut[*pdwCount] = _strdup(strtok_s(NULL, lpTerminatedDelim, &lpToken));

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
HcStringSplitW(LPWSTR lpStr, const WCHAR cDelimiter, LPWSTR lpStrArrayOut[], PDWORD pdwCount)
{
	DWORD tlpStrSize = HcStringLenW(lpStr);
	if (!tlpStrSize)
	{
		return FALSE;
	}

	LPWSTR lpCopy = HcStringAllocW(tlpStrSize);
	LPWSTR lpToken = NULL;
	const WCHAR lpTerminatedDelim[] = { cDelimiter, UNICODE_NULL };

	*pdwCount = 0;

	/* Get the first token. */
	lpToken = wcstok_s(lpCopy, lpTerminatedDelim, &lpToken);

	/* Loop over the splits. */
	while (lpToken)
	{
		/* Duplicate the string and insert into return array. */
		lpStrArrayOut[*pdwCount] = _wcsdup(wcstok_s(0, lpTerminatedDelim, &lpToken));

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
HcStringSubtractA(LPCSTR lpStr, LPSTR lpOutStr, DWORD szStartIndex, DWORD szEndIndex)
{
	if (HcStringIsBad(lpStr))
		return FALSE;

	if (szEndIndex == -1)
	{
		szEndIndex = HcStringLenA(lpStr) - 1;
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
HcStringSubtractW(LPCWSTR lpStr, LPWSTR lpOutStr, DWORD szStartIndex, DWORD szEndIndex)
{
	if (HcStringIsBad(lpStr))
		return FALSE;

	if (szEndIndex == -1)
	{
		szEndIndex = HcStringLenW(lpStr) - 1;
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
DWORD
HCAPI
HcStringIndexOfA(LPCSTR lpStr, LPCSTR lpDelimiter, BOOLEAN CaseInsensitive)
{
	if (!HcStringLenA(lpStr))
	{
		return -1;
	}

	LPCSTR Buffer = HcStringWithinStringA(lpStr, lpDelimiter, CaseInsensitive);
	return Buffer ? (DWORD) (Buffer - lpStr) : -1;
}

HC_EXTERN_API
DWORD
HCAPI
HcStringIndexOfW(LPCWSTR lpStr, LPCWSTR lpDelimiter, BOOLEAN CaseInsensitive)
{
	if (!HcStringLenW(lpStr))
	{
		return -1;
	}

	LPCWSTR Buffer = HcStringWithinStringW(lpStr, lpDelimiter, CaseInsensitive);
	return Buffer ? (DWORD) (Buffer - lpStr) : -1;
}

HC_EXTERN_API
DWORD
HCAPI
HcStringEndOfA(LPCSTR lpStr, LPCSTR lpDelimiter, BOOLEAN CaseInsensitive)
{
	DWORD tDelimSize = HcStringLenA(lpDelimiter);
	if (!HcStringLenA(lpStr) || !tDelimSize)
	{
		return -1;
	}

	LPCSTR Buffer = HcStringWithinStringA(lpStr, lpDelimiter, CaseInsensitive);
	return Buffer ? (DWORD) (Buffer - lpStr) + tDelimSize : -1;
}

HC_EXTERN_API
DWORD
HCAPI
HcStringEndOfW(LPCWSTR lpStr, LPCWSTR lpDelimiter, BOOLEAN CaseInsensitive)
{
	DWORD tDelimSize = HcStringLenW(lpDelimiter);
	if (!HcStringLenW(lpStr) || !tDelimSize)
	{
		return -1;
	}

	LPCWSTR Buffer = HcStringWithinStringW(lpStr, lpDelimiter, CaseInsensitive);
	return Buffer ? (DWORD) (Buffer - lpStr) + tDelimSize : -1;
}

HC_EXTERN_API
DWORD
HCAPI
HcStringLenA(LPCSTR lpString)
{
	if (HcStringIsBad(lpString))
	{
		return 0;
	}

	return HcStringSizeA(lpString) / sizeof(CHAR);
}

HC_EXTERN_API
DWORD
HCAPI
HcStringLenW(LPCWSTR lpString)
{
	if (HcStringIsBad(lpString))
	{
		return 0;
	}

	return HcStringSizeW(lpString) / sizeof(WCHAR);
}

HC_EXTERN_API
DWORD
HCAPI
HcStringSizeA(LPCSTR szcString)
{
	LPCSTR p = szcString;

	while (*p)
	{
		p++;
	}

	return (DWORD) (p - szcString) * sizeof(CHAR);
}

HC_EXTERN_API
DWORD
HCAPI
HcStringSizeW(LPCWSTR szcString)
{
	LPCWSTR p = szcString;

	while (*p)
	{
		p++;
	}

	return (DWORD) (p - szcString) * sizeof(WCHAR);
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringToLowerA(LPSTR lpStr)
{
	if (HcStringIsBad(lpStr))
	{
		return FALSE;
	}

	LPSTR p = lpStr;
	for (; *p; ++p)
	{
		*p = tolower(*p);
	}

	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringToLowerW(LPWSTR lpStr)
{
	if (HcStringIsBad(lpStr))
	{
		return FALSE;
	}

	LPWSTR p = lpStr;
	for (; *p; ++p)
	{
		*p = tolower(*p);
	}

	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringToUpperA(LPSTR lpStr)
{
	if (HcStringIsBad(lpStr))
	{
		return FALSE;
	}

	for (; *lpStr; *lpStr++)
	{
		*lpStr = toupper(*lpStr);
	}

	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringToUpperW(LPWSTR lpStr)
{
	if (HcStringIsBad(lpStr))
	{
		return FALSE;
	}

	for (; *lpStr; *lpStr++)
	{
		*lpStr = towupper(*lpStr);
	}

	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringEqualA(LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive)
{
	BOOLEAN Return;
	DWORD Size1, Size2;
	BOOLEAN bString1, bString2;

	bString1 = HcStringIsBad(lpString1);
	bString2 = HcStringIsBad(lpString2);

	if (bString1 && bString2)
	{
		return TRUE;
	}

	if (!bString1 && bString2)
	{
		return FALSE;
	}

	if (bString1 && !bString2)
	{
		return FALSE;
	}

	Size1 = HcStringSizeA(lpString1);
	Size2 = HcStringSizeA(lpString2);

	if (Size1 != Size2)
	{
		return FALSE;
	}

	if (CaseInSensitive)
	{
		LPSTR lpCopy1;
		LPSTR lpCopy2;

		lpCopy1 = HcStringAllocA(Size1);

		HcStringCopyA(lpCopy1, lpString1, Size1);
		HcStringToLowerA(lpCopy1);

		lpCopy2 = HcStringAllocA(Size2);

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
	DWORD Size1, Size2;
	BOOLEAN bString1, bString2;

	bString1 = HcStringIsBad(lpString1);
	bString2 = HcStringIsBad(lpString2);

	if (bString1 && bString2)
	{
		return TRUE;
	}

	if (!bString1 && bString2)
	{
		return FALSE;
	}

	if (bString1 && !bString2)
	{
		return FALSE;
	}

	Size1 = HcStringSizeW(lpString1);
	Size2 = HcStringSizeW(lpString2);

	if (Size1 != Size2)
	{
		return FALSE;
	}

	if (CaseInSensitive)
	{
		LPWSTR lpCopy1;
		LPWSTR lpCopy2;

		lpCopy1 = HcStringAllocW(Size1);

		HcStringCopyW(lpCopy1, lpString1, Size1);
		HcStringToLowerW(lpCopy1);

		lpCopy2 = HcStringAllocW(Size2);

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
	DWORD tIndex = 0;
	DWORD tLen;
	LPSTR lpStr1 = (LPSTR)szStr, lpStr2 = (LPSTR)szToFind;
	DWORD tSize1, tSize2;

	if (HcStringIsBad(lpStr1) || HcStringIsBad(lpStr2))
	{
		return NULL;
	}

	if (CaseInsensitive)
	{
		tSize1 = HcStringSizeA(lpStr1);
		tSize2 = HcStringSizeA(lpStr2);

		lpStr1 = HcStringAllocA(tSize1);

		HcStringCopyA(lpStr1, szStr, tSize1);
		HcStringToLowerA(lpStr1);

		lpStr2 = HcStringAllocA(tSize2);

		HcStringCopyA(lpStr2, szToFind, tSize2);
		HcStringToLowerA(lpStr2);
	}

	for (tLen = HcStringSizeA(lpStr2);
		*(lpStr1 + tIndex) != UNICODE_NULL && !HcInternalCompare((PBYTE)(lpStr1 + tIndex), (PBYTE)lpStr2, tLen);
		tIndex++);

	if (*(lpStr1 + tIndex) == UNICODE_NULL)
	{
		return NULL;
	}

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
	DWORD tIndex = 0;
	DWORD tLen;
	LPWSTR lpStr1 = (LPWSTR)szStr, lpStr2 = (LPWSTR)szToFind;
	DWORD tSize1, tSize2;

	if (HcStringIsBad(lpStr1) || HcStringIsBad(lpStr2))
	{
		return NULL;
	}

	if (CaseInsensitive)
	{
		tSize1 = HcStringSizeW(lpStr1);
		tSize2 = HcStringSizeW(lpStr2);

		lpStr1 = HcStringAllocW(tSize1);

		HcStringCopyW(lpStr1, szStr, tSize1);
		HcStringToLowerW(lpStr1);

		lpStr2 = HcStringAllocW(tSize2);

		HcStringCopyW(lpStr2, szToFind, tSize2);
		HcStringToLowerW(lpStr2);
	}

	for (tLen = HcStringSizeW(lpStr2);
		*(lpStr1 + tIndex) != UNICODE_NULL && !HcInternalCompare((PBYTE)(lpStr1 + tIndex), (PBYTE)lpStr2, tLen);
		tIndex++);

	if (*(lpStr1 + tIndex) == UNICODE_NULL)
	{
		return NULL;
	}

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
	return HcStringWithinStringA(lpString1, lpString2, CaseInSensitive) != NULL;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringContainsW(LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInsensitive)
{
	return HcStringWithinStringW(lpString1, lpString2, CaseInsensitive) != NULL;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringCopyConvertAtoW(LPCSTR lpStringToConvert,
	LPWSTR lpStringOut,
	DWORD Size)
{
	if (!MultiByteToWideChar(CP_UTF8,
		0,
		lpStringToConvert,
		-1,
		lpStringOut, 
		Size + sizeof(UNICODE_NULL)))
	{
		return FALSE;
	}

	HcStringTerminateW(lpStringOut, Size);
	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringCopyConvertWtoA(LPCWSTR lpStringToConvert,
	LPSTR lpStringOut,
	DWORD Size)
{
	/* Do the convert. */
	if (!WideCharToMultiByte(CP_UTF8,
		0,
		lpStringToConvert,
		-1,
		lpStringOut,
		Size + sizeof(ANSI_NULL),
		NULL,
		NULL))
	{
		return FALSE;
	}

	HcStringTerminateA(lpStringOut, Size);
	return TRUE;
}

HC_EXTERN_API
LPWSTR
HCAPI
HcStringConvertAtoW(IN LPCSTR lpStringConvert)
{
	LPWSTR convertedOut;
	DWORD sizeOfString;
	
	sizeOfString = (DWORD) HcStringLenA(lpStringConvert);
	if (!sizeOfString)
	{
		return NULL;
	}

	convertedOut = HcStringAllocW(sizeOfString);
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
	DWORD sizeOfString;

	sizeOfString = (DWORD) HcStringLenW(lpStringConvert);
	if (!sizeOfString)
	{
		return NULL;
	}

	convertedOut = HcStringAllocA(sizeOfString);
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
HcStringCopyA(IN LPSTR szOut, LPCSTR szcIn, DWORD dwSize)
{
	DWORD Size = dwSize;
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

	HcStringTerminateA(szOut, Size);
	return TRUE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcStringCopyW(IN LPWSTR szOut, LPCWSTR szcIn, DWORD tSize)
{
	DWORD Size = tSize;
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
	HcStringTerminateW(szOut, Size);

	return TRUE;
}