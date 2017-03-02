#include <highcall.h>

DECL_EXTERN_API(LPSTR, StringAllocA, CONST IN DWORD tSize)
{
	return (LPSTR) HcAlloc(tSize * sizeof(CHAR) + sizeof(ANSI_NULL));
}

DECL_EXTERN_API(LPWSTR, StringAllocW, CONST IN DWORD tSize)
{
	return (LPWSTR) HcAlloc(tSize * sizeof(WCHAR) + sizeof(UNICODE_NULL));
}

/* @unimplemented */
DECL_EXTERN_API(BOOLEAN, StringSplitA, VOID)
{
	return FALSE;
}

/* @unimplemented */
DECL_EXTERN_API(BOOLEAN, StringSplitW, VOID)
{
	return FALSE;
}

DECL_EXTERN_API(BOOLEAN, StringSubtractA, IN LPCSTR lpStr, OUT LPSTR lpOutStr, CONST IN DWORD szStartIndex, IN DWORD szEndIndex OPTIONAL)
{
	/* Optional param value */
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

DECL_EXTERN_API(BOOLEAN, StringSubtractW, IN LPCWSTR lpStr, OUT LPWSTR lpOutStr, CONST IN DWORD szStartIndex, IN DWORD szEndIndex OPTIONAL)
{
	/* Optional param value */
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

DECL_EXTERN_API(DWORD, StringIndexOfA, IN LPCSTR lpStr, IN LPCSTR lpDelimiter, CONST IN BOOLEAN CaseInsensitive)
{
	LPCSTR Buffer = HcStringWithinStringA(lpStr, lpDelimiter, TRUE, CaseInsensitive);
	return Buffer ? (DWORD) (Buffer - lpStr) + 1 : -1;
}

DECL_EXTERN_API(DWORD, StringLastIndexOfA, IN LPCSTR lpStr, IN LPCSTR lpDelimiter, CONST IN BOOLEAN CaseInsensitive)
{
	LPCSTR Buffer = HcStringWithinStringA(lpStr, lpDelimiter, FALSE, CaseInsensitive);
	return Buffer ? (DWORD)(Buffer - lpStr) + 1 : -1;
}

DECL_EXTERN_API(DWORD, StringIndexOfW, IN LPCWSTR lpStr, IN LPCWSTR lpDelimiter, CONST IN BOOLEAN CaseInsensitive)
{
	LPCWSTR Buffer = HcStringWithinStringW(lpStr, lpDelimiter, TRUE, CaseInsensitive);
	return Buffer ? (DWORD) (Buffer - lpStr) + 1 : -1;
}

DECL_EXTERN_API(DWORD, StringLastIndexOfW, IN LPCWSTR lpStr, IN LPCWSTR lpDelimiter, CONST IN BOOLEAN CaseInsensitive)
{
	LPCWSTR Buffer = HcStringWithinStringW(lpStr, lpDelimiter, FALSE, CaseInsensitive);
	return Buffer ? (DWORD)(Buffer - lpStr) + 1 : -1;
}

DECL_EXTERN_API(DWORD, StringLenA, IN LPCSTR lpString)
{
	return HcStringSizeA(lpString) / sizeof(CHAR);
}

DECL_EXTERN_API(DWORD, StringLenW, IN LPCWSTR lpString)
{
	return HcStringSizeW(lpString) / sizeof(WCHAR);
}

DECL_EXTERN_API(DWORD, StringSizeA, IN LPCSTR szcString)
{
	LPSTR p = (LPSTR) szcString;

	while (*p)
	{
		p++;
	}

	return (DWORD) (p - szcString) * sizeof(CHAR);
}

DECL_EXTERN_API(DWORD, StringSizeW, IN LPCWSTR szcString)
{
	LPWSTR p = (LPWSTR) szcString;

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

DECL_EXTERN_API(BOOLEAN, StringToLowerA, IN OUT LPSTR lpStr)
{
	LPSTR p = lpStr;
	for (; *p; ++p)
	{
		*p = __tolower(*p);
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, StringToLowerW, IN OUT LPWSTR lpStr)
{
	LPWSTR p = lpStr;
	for (; *p; ++p)
	{
		*p = __tolower(*p);
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, StringToUpperA, IN OUT LPSTR lpStr)
{
	for (; *lpStr; *lpStr++)
	{
		*lpStr = __toupper(*lpStr);
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, StringToUpperW, IN OUT LPWSTR lpStr)
{
	for (; *lpStr; *lpStr++)
	{
		*lpStr = __toupper(*lpStr);
	}

	return TRUE;
}

DECL_EXTERN_API(BOOLEAN, StringCompareContent, IN LPCVOID lpStr1, IN LPCVOID lpStr2, CONST IN DWORD dwLen)
{
	return HcInternalCompare((PBYTE)lpStr1, (PBYTE)lpStr2, dwLen);
}

DECL_EXTERN_API(BOOLEAN, StringCompareA, IN LPCSTR lpStr1, IN LPCSTR lpStr2)
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

	return HcStringCompareContent(lpStr1, lpStr2, Size1);
}

DECL_EXTERN_API(BOOLEAN, StringCompareW, IN LPCWSTR lpStr1, IN LPCWSTR lpStr2)
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

	return HcStringCompareContent(lpStr1, lpStr2, Size1);
}

DECL_EXTERN_API(BOOLEAN, StringEqualA, IN LPCSTR lpString1, IN LPCSTR lpString2, CONST IN BOOLEAN CaseInSensitive)
{
	BOOLEAN Return;
	DWORD dwLen1, dwLen2;
	BOOLEAN bString1, bString2;

	bString1 = HcStringIsNullOrEmpty(lpString1);
	bString2 = HcStringIsNullOrEmpty(lpString2);

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

		Return = HcStringCompareContent(lpCopy1, lpCopy2, dwLen1 * sizeof(CHAR));

		HcFree(lpCopy1);
		HcFree(lpCopy2);

		return Return;
	}

	return HcStringCompareContent(lpString1, lpString2, dwLen1 * sizeof(CHAR));
}

DECL_EXTERN_API(BOOLEAN, StringEqualW, IN LPCWSTR lpString1, IN LPCWSTR lpString2, CONST IN BOOLEAN CaseInSensitive)
{
	BOOLEAN Return;
	DWORD Length1, Length2;
	BOOLEAN bString1, bString2;

	bString1 = HcStringIsNullOrEmpty(lpString1);
	bString2 = HcStringIsNullOrEmpty(lpString2);

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

		Return = HcStringCompareContent(lpCopy1, lpCopy2, Length1 * sizeof(WCHAR));

		HcFree(lpCopy1);
		HcFree(lpCopy2);

		return Return;
	}

	return HcStringCompareContent(lpString1, lpString2, Length1 * sizeof(WCHAR));
}

DECL_EXTERN_API(LPSTR, StringWithinStringA, IN LPCSTR szStr, IN LPCSTR szToFind, CONST IN BOOLEAN bStopFirst, CONST IN BOOLEAN CaseInsensitive)
{
	DWORD lastOccuredIndex = -1;
	LPSTR lpStr1 = (LPSTR)szStr, lpStr2 = (LPSTR)szToFind;
	LPSTR lpSave1, lpSave2;
	DWORD dwLen1, dwLen2;
	DWORD dwSize1, dwSize2;

	if (CaseInsensitive)
	{
		dwLen1 = HcStringSizeA(lpStr1);
		dwLen2 = HcStringSizeA(lpStr2);

		lpStr1 = HcStringAllocA(dwLen1);

		HcStringCopyA(lpStr1, szStr, dwLen1);
		HcStringToLowerA(lpStr1);

		lpStr2 = HcStringAllocA(dwLen2);

		HcStringCopyA(lpStr2, szToFind, dwLen2);
		HcStringToLowerA(lpStr2);
	}

	lpSave1 = lpStr1;
	lpSave2 = lpStr2;

	for (; *lpStr1 != ANSI_NULL; lpStr1++)
	{
		dwSize1 = HcStringSizeA(lpStr1);
		dwSize2 = HcStringSizeA(lpStr2);

		if (dwSize1 < dwSize2)
		{
			break;
		}

		if (HcStringCompareContent(lpStr1, lpStr2, dwSize2))
		{
			lastOccuredIndex = (DWORD)(lpStr1 - szStr);

			if (bStopFirst)
			{
				break;
			}
		}
	}

	if (CaseInsensitive)
	{
		HcFree(lpSave1);
		HcFree(lpSave2);
	}

	if (lastOccuredIndex == -1)
	{
		return NULL;
	}

	return lpStr1;
}

DECL_EXTERN_API(LPWSTR, StringWithinStringW, IN LPCWSTR szStr, IN LPCWSTR szToFind, CONST IN BOOLEAN bStopFirst, CONST IN BOOLEAN CaseInsensitive)
{
	LPWSTR lpStr1 = (LPWSTR)szStr, lpStr2 = (LPWSTR)szToFind;
	LPWSTR lpSave1, lpSave2;
	DWORD dwLen1, dwLen2;
	DWORD dwSize1, dwSize2;
	DWORD lastOccuredIndex = -1;

	if (CaseInsensitive)
	{
		dwLen1 = HcStringLenW(lpStr1);
		dwLen2 = HcStringLenW(lpStr2);

		if (dwLen1 < dwLen2)
		{
			return NULL;
		}

		lpStr1 = HcStringAllocW(dwLen1);

		HcStringCopyW(lpStr1, szStr, dwLen1);
		HcStringToLowerW(lpStr1);

		lpStr2 = HcStringAllocW(dwLen2);

		HcStringCopyW(lpStr2, szToFind, dwLen2);
		HcStringToLowerW(lpStr2);
	}

	lpSave1 = lpStr1;
	lpSave2 = lpStr2;

	for (; *lpStr1 != UNICODE_NULL; lpStr1++)
	{
		dwSize1 = HcStringSizeW(lpStr1);
		dwSize2 = HcStringSizeW(lpStr2);

		if (dwSize1 < dwSize2)
		{
			break;
		}

		if (HcStringCompareContent(lpStr1, lpStr2, dwSize2))
		{
			lastOccuredIndex = (DWORD)(lpStr1 - szStr);

			if (bStopFirst)
			{
				break;
			}
		}
	}

	if (CaseInsensitive)
	{
		HcFree(lpSave1);
		HcFree(lpSave2);
	}

	if (lastOccuredIndex == -1)
	{
		return NULL;
	}

	return lpStr1;
}

DECL_EXTERN_API(BOOLEAN, StringContainsA, IN LPCSTR lpString1, IN LPCSTR lpString2, CONST IN BOOLEAN CaseInSensitive)
{
	return HcStringWithinStringA(lpString1, lpString2, TRUE, CaseInSensitive) != NULL;
}

DECL_EXTERN_API(BOOLEAN, StringContainsW, IN LPCWSTR lpString1, IN LPCWSTR lpString2, CONST IN BOOLEAN CaseInsensitive)
{
	return HcStringWithinStringW(lpString1, lpString2, TRUE, CaseInsensitive) != NULL;
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

DECL_EXTERN_API(BOOLEAN, StringCopyConvertAtoW, IN LPCSTR lpStringToConvert, OUT LPWSTR lpStringOut, CONST IN DWORD dwStringCount)
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

DECL_EXTERN_API(BOOLEAN, StringCopyConvertWtoA, IN LPCWSTR lpStringToConvert, OUT LPSTR lpStringOut, CONST IN DWORD dwStringCount)
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

DECL_EXTERN_API(BOOLEAN, StringCopyA, OUT LPSTR szOut, IN LPCSTR szcIn, CONST IN DWORD dwLen OPTIONAL)
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

DECL_EXTERN_API(BOOLEAN, StringCopyW, OUT LPWSTR szOut, IN LPCWSTR szcIn, CONST IN DWORD dwLen OPTIONAL)
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