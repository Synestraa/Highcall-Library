#include <highcall.h>

DECL_EXTERN_API(LPSTR, StringAllocA, DWORD tSize)
{
	return (LPSTR) HcAlloc(tSize * sizeof(CHAR) + sizeof(ANSI_NULL));
}

DECL_EXTERN_API(LPWSTR, StringAllocW, DWORD tSize)
{
	return (LPWSTR) HcAlloc(tSize * sizeof(WCHAR) + sizeof(UNICODE_NULL));
}

DECL_EXTERN_API(BOOLEAN, StringSplitA, LPSTR lpStr, const CHAR cDelimiter, LPSTR lpStrArrayOut[], PDWORD pdwCount)
{
	return FALSE;

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
	//lpToken = strtok_s(lpCopy, lpTerminatedDelim, &lpToken);

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

DECL_EXTERN_API(BOOLEAN, StringSplitW, LPWSTR lpStr, const WCHAR cDelimiter, LPWSTR lpStrArrayOut[], PDWORD pdwCount)
{
	return FALSE;

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
	//lpToken = wcstok_s(lpCopy, lpTerminatedDelim, &lpToken);

	/* Loop over the splits. */
	while (lpToken)
	{
		/* Duplicate the string and insert into return array. */
		//lpStrArrayOut[*pdwCount] = _wcsdup(wcstok_s(0, lpTerminatedDelim, &lpToken));

		*pdwCount += 1;
	}

	/* Null terminate final string. */
	lpStrArrayOut[*pdwCount] = UNICODE_NULL;

	HcFree(lpCopy);
	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, StringSubtractA, LPCSTR lpStr, LPSTR lpOutStr, DWORD szStartIndex, DWORD szEndIndex)
{
	if (szEndIndex == -1)
	{
		szEndIndex = HcStringLenA(lpStr);
	}

	/* Create the null terminated sub string. */
	if (HcStringCopyA(lpOutStr, &lpStr[szStartIndex], szEndIndex - szStartIndex))
	{
		lpOutStr[szEndIndex - szStartIndex] = ANSI_NULL;
		return TRUE;
	}

	return FALSE;
}

DECL_EXTERN_API(BOOLEAN, StringSubtractW, LPCWSTR lpStr, LPWSTR lpOutStr, DWORD szStartIndex, DWORD szEndIndex)
{
	if (szEndIndex == -1)
	{
		szEndIndex = HcStringLenW(lpStr);
	}

	/* Create the null terminated sub string. */
	if (HcStringCopyW(lpOutStr, &lpStr[szStartIndex], szEndIndex - szStartIndex))
	{
		lpOutStr[szEndIndex - szStartIndex] = UNICODE_NULL;
		return TRUE;
	}

	return FALSE;
}

DECL_EXTERN_API(DWORD, StringIndexOf, LPCSTR lpStr, LPCSTR lpDelimiter, BOOLEAN CaseInsensitive)
{
	if (!HcStringLenA(lpStr))
	{
		return -1;
	}

	LPCSTR Buffer = HcStringWithinStringA(lpStr, lpDelimiter, CaseInsensitive);
	return Buffer ? (DWORD) (Buffer - lpStr) + 1: -1;
}

DECL_EXTERN_API(DWORD, StringLastIndexOf, LPCSTR lpStr, LPCSTR lpDelimiter, BOOLEAN CaseInsensitive)
{
	if (!HcStringLenA(lpStr))
	{
		return -1;
	}

	LPCSTR Buffer = HcStringWithinStringLastA(lpStr, lpDelimiter, CaseInsensitive);
	return Buffer ? (DWORD)(Buffer - lpStr) + 1: -1;
}


DECL_EXTERN_API(DWORD, StringIndexOfW, LPCWSTR lpStr, LPCWSTR lpDelimiter, BOOLEAN CaseInsensitive)
{
	if (!HcStringLenW(lpStr))
	{
		return -1;
	}

	LPCWSTR Buffer = HcStringWithinStringW(lpStr, lpDelimiter, CaseInsensitive);
	return Buffer ? (DWORD) (Buffer - lpStr) + 1 : -1;
}

DECL_EXTERN_API(DWORD, StringLastIndexOfW, LPCWSTR lpStr, LPCWSTR lpDelimiter, BOOLEAN CaseInsensitive)
{
	if (!HcStringLenW(lpStr))
	{
		return -1;
	}

	LPCWSTR Buffer = HcStringWithinStringLastW(lpStr, lpDelimiter, CaseInsensitive);
	return Buffer ? (DWORD)(Buffer - lpStr) + 1 : -1;
}


DECL_EXTERN_API(DWORD, StringEndOfA, LPCSTR lpStr, LPCSTR lpDelimiter, BOOLEAN CaseInsensitive)
{
	DWORD tDelimSize = HcStringLenA(lpDelimiter);
	if (!HcStringLenA(lpStr) || !tDelimSize)
	{
		return -1;
	}

	LPCSTR Buffer = HcStringWithinStringA(lpStr, lpDelimiter, CaseInsensitive);
	return Buffer ? (DWORD) (Buffer - lpStr) + tDelimSize : -1;
}

DECL_EXTERN_API(DWORD, StringEndOfW, LPCWSTR lpStr, LPCWSTR lpDelimiter, BOOLEAN CaseInsensitive)
{
	DWORD tDelimSize = HcStringLenW(lpDelimiter);
	if (!HcStringLenW(lpStr) || !tDelimSize)
	{
		return -1;
	}

	LPCWSTR Buffer = HcStringWithinStringW(lpStr, lpDelimiter, CaseInsensitive);
	return Buffer ? (DWORD) (Buffer - lpStr) + tDelimSize : -1;
}

DECL_EXTERN_API(DWORD, StringLenA, LPCSTR lpString)
{
	return HcStringSizeA(lpString) / sizeof(CHAR);
}

DECL_EXTERN_API(DWORD, StringLenW, LPCWSTR lpString)
{
	return HcStringSizeW(lpString) / sizeof(WCHAR);
}

DECL_EXTERN_API(DWORD, StringSizeA, LPCSTR szcString)
{
	LPCSTR p = szcString;

	while (*p)
	{
		p++;
	}

	return (DWORD) (p - szcString) * sizeof(CHAR);
}

DECL_EXTERN_API(DWORD, StringSizeW, LPCWSTR szcString)
{
	LPCWSTR p = szcString;

	while (*p)
	{
		p++;
	}

	return (DWORD) (p - szcString) * sizeof(WCHAR);
}

static int __tolower(int c)
{
	if (c <= 'Z' && c >= 'A')
	{
		return c + 32;
	}

	return c;
}

static int __islower(int c)
{
	return c >= 'a' && c <= 'z';
}

static int __toupper(int c)
{
	return __islower(c) ? c - 'a' + 'A' : c;
}

DECL_EXTERN_API(BOOLEAN, StringToLowerA, LPSTR lpStr)
{
	LPSTR p = lpStr;
	for (; *p; ++p)
	{
		*p = __tolower(*p);
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, StringToLowerW, LPWSTR lpStr)
{
	LPWSTR p = lpStr;
	for (; *p; ++p)
	{
		*p = __tolower(*p);
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, StringToUpperA, LPSTR lpStr)
{
	for (; *lpStr; *lpStr++)
	{
		*lpStr = __toupper(*lpStr);
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, StringToUpperW, LPWSTR lpStr)
{
	for (; *lpStr; *lpStr++)
	{
		*lpStr = __toupper(*lpStr);
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, StringCompareContentA, LPCSTR lpStr1, LPCSTR lpStr2)
{
	DWORD Size1, Size2;

	if (lpStr1 == NULL && lpStr2 == NULL)
	{
		return TRUE;
	}

	if (lpStr1 != NULL && lpStr2 == NULL)
	{
		return FALSE;
	}

	if (lpStr2 != NULL && lpStr1 == NULL)
	{
		return FALSE;
	}

	Size1 = HcStringSizeA(lpStr1);
	Size2 = HcStringSizeA(lpStr2);

	if (Size1 != Size2)
	{
		return FALSE;
	}

	return HcInternalCompare((PBYTE)lpStr1, (PBYTE)lpStr2, Size1);
}

DECL_EXTERN_API(BOOLEAN, StringCompareContentW, LPCWSTR lpStr1, LPCWSTR lpStr2)
{
	DWORD Size1, Size2;

	if (lpStr1 == NULL && lpStr2 == NULL)
	{
		return TRUE;
	}

	if (lpStr1 != NULL && lpStr2 == NULL)
	{
		return FALSE;
	}

	if (lpStr2 != NULL && lpStr1 == NULL)
	{
		return FALSE;
	}

	Size1 = HcStringSizeW(lpStr1);
	Size2 = HcStringSizeW(lpStr2);

	if (Size1 != Size2)
	{
		return FALSE;
	}

	return HcInternalCompare((PBYTE)lpStr1, (PBYTE)lpStr2, Size1);
}

DECL_EXTERN_API(BOOLEAN, StringEqualA, LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive)
{
	BOOLEAN Return;
	DWORD dwLen1, dwLen2;
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

	dwLen1 = HcStringLenA(lpString1);
	dwLen2 = HcStringLenA(lpString2);

	if (dwLen1 != dwLen2)
	{
		return FALSE;
	}

	if (CaseInSensitive)
	{
		LPSTR lpCopy1;
		LPSTR lpCopy2;

		lpCopy1 = HcStringAllocA(dwLen1);

		HcStringCopyA(lpCopy1, lpString1, dwLen1);
		HcStringToLowerA(lpCopy1);

		lpCopy2 = HcStringAllocA(dwLen2);

		HcStringCopyA(lpCopy2, lpString2, dwLen2);
		HcStringToLowerA(lpCopy2);

		Return = HcStringCompareContentA(lpCopy1, lpCopy2);

		HcFree(lpCopy1);
		HcFree(lpCopy2);

		return Return;
	}

	return HcInternalCompare((PBYTE)lpString1, (PBYTE)lpString2, dwLen1);
}

DECL_EXTERN_API(BOOLEAN, StringEqualW, LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInSensitive)
{
	BOOLEAN Return;
	DWORD Length1, Length2;
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

	Length1 = HcStringLenW(lpString1);
	Length2 = HcStringLenW(lpString2);

	if (Length1 != Length2)
	{
		return FALSE;
	}

	if (CaseInSensitive)
	{
		LPWSTR lpCopy1;
		LPWSTR lpCopy2;

		lpCopy1 = HcStringAllocW(Length1);

		HcStringCopyW(lpCopy1, lpString1, Length1);
		HcStringToLowerW(lpCopy1);

		lpCopy2 = HcStringAllocW(Length2);

		HcStringCopyW(lpCopy2, lpString2, Length2);
		HcStringToLowerW(lpCopy2);

		Return = HcStringCompareContentW(lpCopy1, lpCopy2);

		HcFree(lpCopy1);
		HcFree(lpCopy2);

		return Return;
	}

	return HcInternalCompare((PBYTE)lpString1, (PBYTE)lpString2, Length1);
}

DECL_EXTERN_API(LPSTR, StringWithinStringA, LPCSTR szStr, LPCSTR szToFind, BOOLEAN CaseInsensitive)
{
	DWORD lastOccuredIndex = -1;
	DWORD dwSizeInBytes;
	LPSTR lpStr1 = (LPSTR)szStr, lpStr2 = (LPSTR)szToFind;
	DWORD tSize1, tSize2;

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

	dwSizeInBytes = HcStringSizeA(lpStr2);
	if (dwSizeInBytes > 0)
	{
		for (; *lpStr1 != ANSI_NULL; lpStr1++)
		{
			if (HcInternalCompare((PBYTE)lpStr1, (PBYTE)lpStr2, dwSizeInBytes))
			{
				lastOccuredIndex = (DWORD) (lpStr1 - szStr);
			}
		}
	};

	if (CaseInsensitive)
	{
		HcFree(lpStr1);
		HcFree(lpStr2);
	}

	if (lastOccuredIndex == -1)
	{
		return NULL;
	}

	return lpStr1;
}

DECL_EXTERN_API(LPSTR, StringWithinStringLastA, LPCSTR szStr, LPCSTR szToFind, BOOLEAN CaseInsensitive)
{
	DWORD lastOccuredIndex = -1;
	DWORD dwSizeInBytes;
	LPSTR lpStr1 = (LPSTR)szStr, lpStr2 = (LPSTR)szToFind;
	DWORD tSize1, tSize2;

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

	dwSizeInBytes = HcStringSizeA(lpStr2);
	if (dwSizeInBytes > 0)
	{
		for (; *lpStr1 != ANSI_NULL; lpStr1++)
		{
			if (HcInternalCompare((PBYTE)lpStr1, (PBYTE)lpStr2, dwSizeInBytes))
			{
				lastOccuredIndex = (DWORD)(lpStr1 - szStr);
				break;
			}
		}
	};

	if (CaseInsensitive)
	{
		HcFree(lpStr1);
		HcFree(lpStr2);
	}

	if (lastOccuredIndex == -1)
	{
		return NULL;
	}

	return (LPSTR) szStr + lastOccuredIndex;
}

// TODO refine to EX
DECL_EXTERN_API(LPWSTR, StringWithinStringLastW, LPCWSTR szStr, LPCWSTR szToFind, BOOLEAN CaseInsensitive)
{
	DWORD dwSizeInBytes;
	LPWSTR lpStr1 = (LPWSTR)szStr, lpStr2 = (LPWSTR)szToFind;
	DWORD dwLen1, dwLen2;;
	DWORD lastOccuredIndex = -1;

	if (CaseInsensitive)
	{
		dwLen1 = HcStringLenW(lpStr1);
		dwLen2 = HcStringLenW(lpStr2);

		lpStr1 = HcStringAllocW(dwLen1);

		HcStringCopyW(lpStr1, szStr, dwLen1);
		HcStringToLowerW(lpStr1);

		lpStr2 = HcStringAllocW(dwLen2);

		HcStringCopyW(lpStr2, szToFind, dwLen2);
		HcStringToLowerW(lpStr2);
	}

	dwSizeInBytes = HcStringSizeW(lpStr2);
	if (dwSizeInBytes > 0)
	{
		for (; *lpStr1 != UNICODE_NULL; lpStr1++)
		{
			if (HcInternalCompare((PBYTE)lpStr1, (PBYTE)lpStr2, dwSizeInBytes))
			{
				lastOccuredIndex = (DWORD) (lpStr1 - szStr);
			}
		}
	}

	if (CaseInsensitive)
	{
		HcFree(lpStr1);
		HcFree(lpStr2);
	}

	if (lastOccuredIndex == -1)
	{
		return NULL;
	}

	return (LPWSTR) szStr + lastOccuredIndex;
}

DECL_EXTERN_API(LPWSTR, StringWithinStringW, LPCWSTR szStr, LPCWSTR szToFind, BOOLEAN CaseInsensitive)
{
	DWORD tLen;
	LPWSTR lpStr1 = (LPWSTR)szStr, lpStr2 = (LPWSTR)szToFind;
	DWORD dwLen1, dwLen2;;
	DWORD lastOccuredIndex = -1;

	if (CaseInsensitive)
	{
		dwLen1 = HcStringLenW(lpStr1);
		dwLen2 = HcStringLenW(lpStr2);

		lpStr1 = HcStringAllocW(dwLen1);

		HcStringCopyW(lpStr1, szStr, dwLen1);
		HcStringToLowerW(lpStr1);

		lpStr2 = HcStringAllocW(dwLen2);

		HcStringCopyW(lpStr2, szToFind, dwLen2);
		HcStringToLowerW(lpStr2);
	}

	tLen = HcStringSizeW(lpStr2);
	if (tLen > 0)
	{
		for (; *lpStr1 != UNICODE_NULL; lpStr1++)
		{
			if (HcInternalCompare((PBYTE)lpStr1, (PBYTE)lpStr2, tLen))
			{
				lastOccuredIndex = (DWORD)(lpStr1 - szStr);
				break;
			}
		}
	}

	if (CaseInsensitive)
	{
		HcFree(lpStr1);
		HcFree(lpStr2);
	}

	if (lastOccuredIndex == -1)
	{
		return NULL;
	}

	return lpStr1;
}

DECL_EXTERN_API(BOOLEAN, StringContainsA, LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive)
{
	return HcStringWithinStringA(lpString1, lpString2, CaseInSensitive) != NULL;
}

DECL_EXTERN_API(BOOLEAN, StringContainsW, LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInsensitive)
{
	return HcStringWithinStringW(lpString1, lpString2, CaseInsensitive) != NULL;
}

#define MB_LEN_MAX 4

static
size_t
__mbstowcs(register wchar_t *pwcs, register const char *s, int n)
{
	register int i = n;
	
	while (--i >= 0) 
	{
		if (!(*pwcs++ = *s++))
		{
			return n - i - 1;
		}
	}
    return n - i;
}

DECL_EXTERN_API(BOOLEAN, StringCopyConvertAtoW, LPCSTR lpStringToConvert,
	LPWSTR lpStringOut,
	DWORD dwStringCount)
{
	size_t retn = __mbstowcs(lpStringOut, lpStringToConvert, dwStringCount);
	TERMINATE_W(lpStringOut, dwStringCount);
	return TRUE;
}

static
size_t
__wcstombs(register char *s, register const wchar_t *pwcs, int n)
{
	register int i = n;
	
	while (--i >= 0) 
	{
		if (!(*s++ = (CHAR) *pwcs++))
		{
			break;
		}
	}
	return n - i - 1;
}

DECL_EXTERN_API(BOOLEAN, StringCopyConvertWtoA, LPCWSTR lpStringToConvert,
	LPSTR lpStringOut,
	DWORD dwStringCount)
{
	size_t retn = __wcstombs(lpStringOut, lpStringToConvert, dwStringCount);
	TERMINATE_A(lpStringOut, dwStringCount);
	return retn > 0;
}

DECL_EXTERN_API(LPWSTR, StringConvertAtoW, IN LPCSTR lpStringConvert)
{
	LPWSTR convertedOut;
	DWORD dwCount;
	
	dwCount = HcStringLenA(lpStringConvert);
	if (!dwCount)
	{
		return NULL;
	}

	convertedOut = HcStringAllocW(dwCount);
	if (!convertedOut)
	{
		return NULL;
	}

	if (!HcStringCopyConvertAtoW(lpStringConvert, convertedOut, dwCount))
	{
		return NULL;
	}

	return convertedOut;
}

DECL_EXTERN_API(LPSTR, StringConvertWtoA, IN LPCWSTR lpStringConvert)
{
	LPSTR convertedOut;
	DWORD dwCount;

	dwCount = HcStringLenW(lpStringConvert);
	if (!dwCount)
	{
		return NULL;
	}

	convertedOut = HcStringAllocA(dwCount);
	if (!convertedOut)
	{
		return NULL;
	}

	if (!HcStringCopyConvertWtoA(lpStringConvert, convertedOut, dwCount))
	{
		return NULL;
	}

	return convertedOut;
}

DECL_EXTERN_API(BOOLEAN, StringCopyA, IN LPSTR szOut, LPCSTR szcIn, DWORD dwLen)
{
	DWORD Length = dwLen;
	if (!Length)
	{
		Length = HcStringLenA(szOut);
		if (!Length)
		{
			return FALSE;
		}
	}

	HcInternalCopy(szOut, (PVOID)szcIn, Length);
	TERMINATE_A(szOut, Length);

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, StringCopyW, IN LPWSTR szOut, LPCWSTR szcIn, DWORD dwLen)
{
	DWORD Length = dwLen;
	if (!Length)
	{
		Length = HcStringLenW(szOut);
		if (!Length)
		{
			return FALSE;
		}
	}

	HcInternalCopy(szOut, (PVOID)szcIn, Length * sizeof(WCHAR));
	TERMINATE_W(szOut, Length);

	return TRUE;
}