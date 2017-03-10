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
	return Buffer ? (DWORD) (Buffer - lpStr) + 1 : -1;
}

DECL_EXTERN_API(DWORD, StringIndexOfW, IN LPCWSTR lpStr, IN LPCWSTR lpDelimiter, CONST IN BOOLEAN CaseInsensitive)
{
	LPCWSTR Buffer = HcStringWithinStringW(lpStr, lpDelimiter, TRUE, CaseInsensitive);
	return Buffer ? (DWORD) (Buffer - lpStr) + 1 : -1;
}

DECL_EXTERN_API(DWORD, StringLastIndexOfW, IN LPCWSTR lpStr, IN LPCWSTR lpDelimiter, CONST IN BOOLEAN CaseInsensitive)
{
	LPCWSTR Buffer = HcStringWithinStringW(lpStr, lpDelimiter, FALSE, CaseInsensitive);
	return Buffer ? (DWORD) (Buffer - lpStr) + 1 : -1;
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
	return HcInternalCompare((PBYTE) lpStr1, (PBYTE) lpStr2, dwLen);
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
	LPSTR lpStr1 = (LPSTR) szStr, lpStr2 = (LPSTR) szToFind;
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
			lastOccuredIndex = (DWORD) (lpStr1 - szStr);

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

	return (LPSTR) szStr + lastOccuredIndex;
}

DECL_EXTERN_API(LPWSTR, StringWithinStringW, IN LPCWSTR szStr, IN LPCWSTR szToFind, CONST IN BOOLEAN bStopFirst, CONST IN BOOLEAN CaseInsensitive)
{
	LPWSTR lpStr1 = (LPWSTR) szStr, lpStr2 = (LPWSTR) szToFind;
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
			lastOccuredIndex = (DWORD) (lpStr1 - szStr);

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

	return (LPWSTR) szStr + lastOccuredIndex;
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
__mbstowcs(register wchar_t *pwcs, register CONST char *s, int n)
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
__wcstombs(register char *s, register CONST wchar_t *pwcs, int n)
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

	HcInternalCopy(szOut, (PVOID) szcIn, Length);
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

	HcInternalCopy(szOut, (PVOID) szcIn, Length * sizeof(WCHAR));
	TERMINATE_W(szOut, Length);

	return TRUE;
}

DECL_EXTERN_API(ULONG_PTR, StringConvertIntPtrA, IN LPSTR lpString)
{
	ULONG_PTR res = 0; // Initialize result
	int sgn = 1;

	if (*lpString == '-')
	{
		sgn = -1;
		++lpString;
	}
	else if (*lpString == '+')
	{
		++lpString;
	}

	// Iterate through all characters of input string and update result
	for (; *lpString != 0; ++lpString)
	{
		unsigned d = (unsigned) *lpString - '0';
		if (d > 9)
		{
			return sgn * res;
		}
		res = res * 10 + d;
	}

	// return result.
	return sgn * res;
}

DECL_EXTERN_API(ULONG_PTR, StringConvertIntPtrW, IN LPWSTR lpString)
{
	ULONG_PTR res = 0; // Initialize result
	int sgn = 1;

	if (*lpString == L'-')
	{
		sgn = -1;
		++lpString;
	}
	else if (*lpString == L'+')
	{
		++lpString;
	}

	// Iterate through all characters of input string and update result
	for (; *lpString != 0; ++lpString)
	{
		unsigned d = (unsigned) *lpString - L'0';
		if (d > 9)
		{
			return sgn * res;
		}
		res = res * 10 + d;
	}

	// return result.
	return sgn * res;
}

CONST CHAR gDigitsANSI[200] =
{
	'0','0','0','1','0','2','0','3','0','4','0','5','0','6','0','7','0','8','0','9',
	'1','0','1','1','1','2','1','3','1','4','1','5','1','6','1','7','1','8','1','9',
	'2','0','2','1','2','2','2','3','2','4','2','5','2','6','2','7','2','8','2','9',
	'3','0','3','1','3','2','3','3','3','4','3','5','3','6','3','7','3','8','3','9',
	'4','0','4','1','4','2','4','3','4','4','4','5','4','6','4','7','4','8','4','9',
	'5','0','5','1','5','2','5','3','5','4','5','5','5','6','5','7','5','8','5','9',
	'6','0','6','1','6','2','6','3','6','4','6','5','6','6','6','7','6','8','6','9',
	'7','0','7','1','7','2','7','3','7','4','7','5','7','6','7','7','7','8','7','9',
	'8','0','8','1','8','2','8','3','8','4','8','5','8','6','8','7','8','8','8','9',
	'9','0','9','1','9','2','9','3','9','4','9','5','9','6','9','7','9','8','9','9'
};

DECL_EXTERN_API(VOID, StringUInt32ToStringA, ULONG value, LPSTR buffer)
{
	if (value < 10000)
	{
		CONST ULONG d1 = (value / 100) << 1;
		CONST ULONG d2 = (value % 100) << 1;

		if (value >= 1000)
		{
			*buffer++ = gDigitsANSI[d1];
		}

		if (value >= 100)
		{
			*buffer++ = gDigitsANSI[d1 + 1];
		}

		if (value >= 10)
		{
			*buffer++ = gDigitsANSI[d2];
		}

		*buffer++ = gDigitsANSI[d2 + 1];
	}
	else if (value < 100000000)
	{
		// value = bbbbcccc
		CONST ULONG b = value / 10000;
		CONST ULONG c = value % 10000;

		CONST ULONG d1 = (b / 100) << 1;
		CONST ULONG d2 = (b % 100) << 1;

		CONST ULONG d3 = (c / 100) << 1;
		CONST ULONG d4 = (c % 100) << 1;

		if (value >= 10000000)
		{
			*buffer++ = gDigitsANSI[d1];
		}

		if (value >= 1000000)
		{
			*buffer++ = gDigitsANSI[d1 + 1];
		}

		if (value >= 100000)
		{
			*buffer++ = gDigitsANSI[d2];
		}

		*buffer++ = gDigitsANSI[d2 + 1];

		*buffer++ = gDigitsANSI[d3];
		*buffer++ = gDigitsANSI[d3 + 1];
		*buffer++ = gDigitsANSI[d4];
		*buffer++ = gDigitsANSI[d4 + 1];
	}
	else
	{
		// value = aabbbbcccc in decimal

		CONST ULONG a = value / 100000000; // 1 to 42
		value %= 100000000;

		if (a >= 10)
		{
			CONST unsigned i = a << 1;
			*buffer++ = gDigitsANSI[i];
			*buffer++ = gDigitsANSI[i + 1];
		}
		else
		{
			*buffer++ = '0' + (char) a;
		}

		CONST ULONG b = value / 10000; // 0 to 9999
		CONST ULONG c = value % 10000; // 0 to 9999

		CONST ULONG d1 = (b / 100) << 1;
		CONST ULONG d2 = (b % 100) << 1;

		CONST ULONG d3 = (c / 100) << 1;
		CONST ULONG d4 = (c % 100) << 1;

		*buffer++ = gDigitsANSI[d1];
		*buffer++ = gDigitsANSI[d1 + 1];
		*buffer++ = gDigitsANSI[d2];
		*buffer++ = gDigitsANSI[d2 + 1];
		*buffer++ = gDigitsANSI[d3];
		*buffer++ = gDigitsANSI[d3 + 1];
		*buffer++ = gDigitsANSI[d4];
		*buffer++ = gDigitsANSI[d4 + 1];
	}
	*buffer++ = '\0';
}

DECL_EXTERN_API(VOID, StringInt32ToStringA, LONG value, LPSTR buffer)
{
	ULONG u = (ULONG) value;
	if (value < 0)
	{
		*buffer++ = '-';
		u = ~u + 1;
	}

	HcStringUInt32ToStringA(u, buffer);
}

DECL_EXTERN_API(VOID, StringUInt64ToStringA, ULONG64 value, LPSTR buffer)
{
	if (value < 100000000)
	{
		ULONG v = (ULONG) (value);
		if (v < 10000)
		{
			CONST ULONG d1 = (v / 100) << 1;
			CONST ULONG d2 = (v % 100) << 1;

			if (v >= 1000)
			{
				*buffer++ = gDigitsANSI[d1];
			}

			if (v >= 100)
			{
				*buffer++ = gDigitsANSI[d1 + 1];
			}

			if (v >= 10)
			{
				*buffer++ = gDigitsANSI[d2];
			}

			*buffer++ = gDigitsANSI[d2 + 1];
		}
		else
		{
			// value = bbbbcccc
			CONST ULONG b = v / 10000;
			CONST ULONG c = v % 10000;

			CONST ULONG d1 = (b / 100) << 1;
			CONST ULONG d2 = (b % 100) << 1;

			CONST ULONG d3 = (c / 100) << 1;
			CONST ULONG d4 = (c % 100) << 1;

			if (value >= 10000000)
				*buffer++ = gDigitsANSI[d1];
			if (value >= 1000000)
				*buffer++ = gDigitsANSI[d1 + 1];
			if (value >= 100000)
				*buffer++ = gDigitsANSI[d2];
			*buffer++ = gDigitsANSI[d2 + 1];

			*buffer++ = gDigitsANSI[d3];
			*buffer++ = gDigitsANSI[d3 + 1];
			*buffer++ = gDigitsANSI[d4];
			*buffer++ = gDigitsANSI[d4 + 1];
		}
	}
	else if (value < 10000000000000000)
	{
		CONST ULONG v0 = (ULONG) (value / 100000000);
		CONST ULONG v1 = (ULONG) (value % 100000000);

		CONST ULONG b0 = v0 / 10000;
		CONST ULONG c0 = v0 % 10000;

		CONST ULONG d1 = (b0 / 100) << 1;
		CONST ULONG d2 = (b0 % 100) << 1;

		CONST ULONG d3 = (c0 / 100) << 1;
		CONST ULONG d4 = (c0 % 100) << 1;

		CONST ULONG b1 = v1 / 10000;
		CONST ULONG c1 = v1 % 10000;

		CONST ULONG d5 = (b1 / 100) << 1;
		CONST ULONG d6 = (b1 % 100) << 1;

		CONST ULONG d7 = (c1 / 100) << 1;
		CONST ULONG d8 = (c1 % 100) << 1;

		if (value >= 1000000000000000)
		{
			*buffer++ = gDigitsANSI[d1];
		}

		if (value >= 100000000000000)
		{
			*buffer++ = gDigitsANSI[d1 + 1];
		}

		if (value >= 10000000000000)
		{
			*buffer++ = gDigitsANSI[d2];
		}

		if (value >= 1000000000000)
		{
			*buffer++ = gDigitsANSI[d2 + 1];
		}

		if (value >= 100000000000)
		{
			*buffer++ = gDigitsANSI[d3];
		}

		if (value >= 10000000000)
		{
			*buffer++ = gDigitsANSI[d3 + 1];
		}

		if (value >= 1000000000)
		{
			*buffer++ = gDigitsANSI[d4];
		}

		if (value >= 100000000)
		{
			*buffer++ = gDigitsANSI[d4 + 1];
		}

		*buffer++ = gDigitsANSI[d5];
		*buffer++ = gDigitsANSI[d5 + 1];
		*buffer++ = gDigitsANSI[d6];
		*buffer++ = gDigitsANSI[d6 + 1];
		*buffer++ = gDigitsANSI[d7];
		*buffer++ = gDigitsANSI[d7 + 1];
		*buffer++ = gDigitsANSI[d8];
		*buffer++ = gDigitsANSI[d8 + 1];
	}
	else
	{
		CONST ULONG a = (ULONG) (value / 10000000000000000); // 1 to 1844
		value %= 10000000000000000;

		if (a < 10)
			*buffer++ = '0' + (char) (a);
		else if (a < 100)
		{
			CONST ULONG i = a << 1;
			*buffer++ = gDigitsANSI[i];
			*buffer++ = gDigitsANSI[i + 1];
		}
		else if (a < 1000)
		{
			*buffer++ = '0' + (char) (a / 100);

			CONST ULONG i = (a % 100) << 1;
			*buffer++ = gDigitsANSI[i];
			*buffer++ = gDigitsANSI[i + 1];
		}
		else
		{
			CONST ULONG i = (a / 100) << 1;
			CONST ULONG j = (a % 100) << 1;
			*buffer++ = gDigitsANSI[i];
			*buffer++ = gDigitsANSI[i + 1];
			*buffer++ = gDigitsANSI[j];
			*buffer++ = gDigitsANSI[j + 1];
		}

		CONST ULONG v0 = (ULONG) (value / 100000000);
		CONST ULONG v1 = (ULONG) (value % 100000000);

		CONST ULONG b0 = v0 / 10000;
		CONST ULONG c0 = v0 % 10000;

		CONST ULONG d1 = (b0 / 100) << 1;
		CONST ULONG d2 = (b0 % 100) << 1;

		CONST ULONG d3 = (c0 / 100) << 1;
		CONST ULONG d4 = (c0 % 100) << 1;

		CONST ULONG b1 = v1 / 10000;
		CONST ULONG c1 = v1 % 10000;

		CONST ULONG d5 = (b1 / 100) << 1;
		CONST ULONG d6 = (b1 % 100) << 1;

		CONST ULONG d7 = (c1 / 100) << 1;
		CONST ULONG d8 = (c1 % 100) << 1;

		*buffer++ = gDigitsANSI[d1];
		*buffer++ = gDigitsANSI[d1 + 1];
		*buffer++ = gDigitsANSI[d2];
		*buffer++ = gDigitsANSI[d2 + 1];
		*buffer++ = gDigitsANSI[d3];
		*buffer++ = gDigitsANSI[d3 + 1];
		*buffer++ = gDigitsANSI[d4];
		*buffer++ = gDigitsANSI[d4 + 1];
		*buffer++ = gDigitsANSI[d5];
		*buffer++ = gDigitsANSI[d5 + 1];
		*buffer++ = gDigitsANSI[d6];
		*buffer++ = gDigitsANSI[d6 + 1];
		*buffer++ = gDigitsANSI[d7];
		*buffer++ = gDigitsANSI[d7 + 1];
		*buffer++ = gDigitsANSI[d8];
		*buffer++ = gDigitsANSI[d8 + 1];
	}

	*buffer = '\0';
}

DECL_EXTERN_API(VOID, StringInt64ToStringA, LONG64 value, LPSTR buffer)
{
	ULONG64 u = (ULONG64) (value);
	if (value < 0)
	{
		*buffer++ = '-';
		u = ~u + 1;
	}

	HcStringUInt64ToStringA(u, buffer);
}


CONST WCHAR gDigitsUNICODE[200] =
{
	L'0',L'0',L'0',L'1',L'0',L'2',L'0',L'3',L'0',L'4',L'0',L'5',L'0',L'6',L'0',L'7',L'0',L'8',L'0',L'9',
	L'1',L'0',L'1',L'1',L'1',L'2',L'1',L'3',L'1',L'4',L'1',L'5',L'1',L'6',L'1',L'7',L'1',L'8',L'1',L'9',
	L'2',L'0',L'2',L'1',L'2',L'2',L'2',L'3',L'2',L'4',L'2',L'5',L'2',L'6',L'2',L'7',L'2',L'8',L'2',L'9',
	L'3',L'0',L'3',L'1',L'3',L'2',L'3',L'3',L'3',L'4',L'3',L'5',L'3',L'6',L'3',L'7',L'3',L'8',L'3',L'9',
	L'4',L'0',L'4',L'1',L'4',L'2',L'4',L'3',L'4',L'4',L'4',L'5',L'4',L'6',L'4',L'7',L'4',L'8',L'4',L'9',
	L'5',L'0',L'5',L'1',L'5',L'2',L'5',L'3',L'5',L'4',L'5',L'5',L'5',L'6',L'5',L'7',L'5',L'8',L'5',L'9',
	L'6',L'0',L'6',L'1',L'6',L'2',L'6',L'3',L'6',L'4',L'6',L'5',L'6',L'6',L'6',L'7',L'6',L'8',L'6',L'9',
	L'7',L'0',L'7',L'1',L'7',L'2',L'7',L'3',L'7',L'4',L'7',L'5',L'7',L'6',L'7',L'7',L'7',L'8',L'7',L'9',
	L'8',L'0',L'8',L'1',L'8',L'2',L'8',L'3',L'8',L'4',L'8',L'5',L'8',L'6',L'8',L'7',L'8',L'8',L'8',L'9',
	L'9',L'0',L'9',L'1',L'9',L'2',L'9',L'3',L'9',L'4',L'9',L'5',L'9',L'6',L'9',L'7',L'9',L'8',L'9',L'9'
};

DECL_EXTERN_API(VOID, StringUInt32ToStringW, ULONG value, LPWSTR buffer)
{
	if (value < 10000)
	{
		CONST ULONG d1 = (value / 100) << 1;
		CONST ULONG d2 = (value % 100) << 1;

		if (value >= 1000)
		{
			*buffer++ = gDigitsUNICODE[d1];
		}

		if (value >= 100)
		{
			*buffer++ = gDigitsUNICODE[d1 + 1];
		}

		if (value >= 10)
		{
			*buffer++ = gDigitsUNICODE[d2];
		}

		*buffer++ = gDigitsUNICODE[d2 + 1];
	}
	else if (value < 100000000)
	{
		// value = bbbbcccc
		CONST ULONG b = value / 10000;
		CONST ULONG c = value % 10000;

		CONST ULONG d1 = (b / 100) << 1;
		CONST ULONG d2 = (b % 100) << 1;

		CONST ULONG d3 = (c / 100) << 1;
		CONST ULONG d4 = (c % 100) << 1;

		if (value >= 10000000)
		{
			*buffer++ = gDigitsUNICODE[d1];
		}

		if (value >= 1000000)
		{
			*buffer++ = gDigitsUNICODE[d1 + 1];
		}

		if (value >= 100000)
		{
			*buffer++ = gDigitsUNICODE[d2];
		}

		*buffer++ = gDigitsUNICODE[d2 + 1];

		*buffer++ = gDigitsUNICODE[d3];
		*buffer++ = gDigitsUNICODE[d3 + 1];
		*buffer++ = gDigitsUNICODE[d4];
		*buffer++ = gDigitsUNICODE[d4 + 1];
	}
	else
	{
		// value = aabbbbcccc in decimal

		CONST ULONG a = value / 100000000; // 1 to 42
		value %= 100000000;

		if (a >= 10)
		{
			CONST unsigned i = a << 1;
			*buffer++ = gDigitsUNICODE[i];
			*buffer++ = gDigitsUNICODE[i + 1];
		}
		else
		{
			*buffer++ = L'0' + (char) a;
		}

		CONST ULONG b = value / 10000; // 0 to 9999
		CONST ULONG c = value % 10000; // 0 to 9999

		CONST ULONG d1 = (b / 100) << 1;
		CONST ULONG d2 = (b % 100) << 1;

		CONST ULONG d3 = (c / 100) << 1;
		CONST ULONG d4 = (c % 100) << 1;

		*buffer++ = gDigitsUNICODE[d1];
		*buffer++ = gDigitsUNICODE[d1 + 1];
		*buffer++ = gDigitsUNICODE[d2];
		*buffer++ = gDigitsUNICODE[d2 + 1];
		*buffer++ = gDigitsUNICODE[d3];
		*buffer++ = gDigitsUNICODE[d3 + 1];
		*buffer++ = gDigitsUNICODE[d4];
		*buffer++ = gDigitsUNICODE[d4 + 1];
	}
	*buffer++ = L'\0';
}

DECL_EXTERN_API(VOID, StringInt32ToStringW, LONG value, LPWSTR buffer)
{
	ULONG u = (ULONG) value;
	if (value < 0)
	{
		*buffer++ = L'-';
		u = ~u + 1;
	}

	HcStringUInt32ToStringW(u, buffer);
}

DECL_EXTERN_API(VOID, StringUInt64ToStringW, ULONG64 value, LPWSTR buffer)
{
	if (value < 100000000)
	{
		ULONG v = (ULONG) (value);
		if (v < 10000)
		{
			CONST ULONG d1 = (v / 100) << 1;
			CONST ULONG d2 = (v % 100) << 1;

			if (v >= 1000)
			{
				*buffer++ = gDigitsUNICODE[d1];
			}

			if (v >= 100)
			{
				*buffer++ = gDigitsUNICODE[d1 + 1];
			}

			if (v >= 10)
			{
				*buffer++ = gDigitsUNICODE[d2];
			}
			*buffer++ = gDigitsUNICODE[d2 + 1];
		}
		else
		{
			// value = bbbbcccc
			CONST ULONG b = v / 10000;
			CONST ULONG c = v % 10000;

			CONST ULONG d1 = (b / 100) << 1;
			CONST ULONG d2 = (b % 100) << 1;

			CONST ULONG d3 = (c / 100) << 1;
			CONST ULONG d4 = (c % 100) << 1;

			if (value >= 10000000)
			{
				*buffer++ = gDigitsUNICODE[d1];
			}

			if (value >= 1000000)
			{
				*buffer++ = gDigitsUNICODE[d1 + 1];
			}

			if (value >= 100000)
			{
				*buffer++ = gDigitsUNICODE[d2];
			}
			*buffer++ = gDigitsUNICODE[d2 + 1];

			*buffer++ = gDigitsUNICODE[d3];
			*buffer++ = gDigitsUNICODE[d3 + 1];
			*buffer++ = gDigitsUNICODE[d4];
			*buffer++ = gDigitsUNICODE[d4 + 1];
		}
	}
	else if (value < 10000000000000000)
	{
		CONST ULONG v0 = (ULONG) (value / 100000000);
		CONST ULONG v1 = (ULONG) (value % 100000000);

		CONST ULONG b0 = v0 / 10000;
		CONST ULONG c0 = v0 % 10000;

		CONST ULONG d1 = (b0 / 100) << 1;
		CONST ULONG d2 = (b0 % 100) << 1;

		CONST ULONG d3 = (c0 / 100) << 1;
		CONST ULONG d4 = (c0 % 100) << 1;

		CONST ULONG b1 = v1 / 10000;
		CONST ULONG c1 = v1 % 10000;

		CONST ULONG d5 = (b1 / 100) << 1;
		CONST ULONG d6 = (b1 % 100) << 1;

		CONST ULONG d7 = (c1 / 100) << 1;
		CONST ULONG d8 = (c1 % 100) << 1;

		if (value >= 1000000000000000)
		{
			*buffer++ = gDigitsUNICODE[d1];
		}

		if (value >= 100000000000000)
		{
			*buffer++ = gDigitsUNICODE[d1 + 1];
		}

		if (value >= 10000000000000)
		{
			*buffer++ = gDigitsUNICODE[d2];
		}

		if (value >= 1000000000000)
		{
			*buffer++ = gDigitsUNICODE[d2 + 1];
		}

		if (value >= 100000000000)
		{
			*buffer++ = gDigitsUNICODE[d3];
		}

		if (value >= 10000000000)
		{
			*buffer++ = gDigitsUNICODE[d3 + 1];
		}

		if (value >= 1000000000)
		{
			*buffer++ = gDigitsUNICODE[d4];
		}

		if (value >= 100000000)
		{
			*buffer++ = gDigitsUNICODE[d4 + 1];
		}

		*buffer++ = gDigitsUNICODE[d5];
		*buffer++ = gDigitsUNICODE[d5 + 1];
		*buffer++ = gDigitsUNICODE[d6];
		*buffer++ = gDigitsUNICODE[d6 + 1];
		*buffer++ = gDigitsUNICODE[d7];
		*buffer++ = gDigitsUNICODE[d7 + 1];
		*buffer++ = gDigitsUNICODE[d8];
		*buffer++ = gDigitsUNICODE[d8 + 1];
	}
	else
	{
		CONST ULONG a = (ULONG) (value / 10000000000000000); // 1 to 1844
		value %= 10000000000000000;

		if (a < 10)
		{
			*buffer++ = L'0' + (char) (a);
		}
		else if (a < 100)
		{
			CONST ULONG i = a << 1;
			*buffer++ = gDigitsUNICODE[i];
			*buffer++ = gDigitsUNICODE[i + 1];
		}
		else if (a < 1000)
		{
			*buffer++ = L'0' + (char) (a / 100);

			CONST ULONG i = (a % 100) << 1;
			*buffer++ = gDigitsUNICODE[i];
			*buffer++ = gDigitsUNICODE[i + 1];
		}
		else
		{
			CONST ULONG i = (a / 100) << 1;
			CONST ULONG j = (a % 100) << 1;
			*buffer++ = gDigitsUNICODE[i];
			*buffer++ = gDigitsUNICODE[i + 1];
			*buffer++ = gDigitsUNICODE[j];
			*buffer++ = gDigitsUNICODE[j + 1];
		}

		CONST ULONG v0 = (ULONG) (value / 100000000);
		CONST ULONG v1 = (ULONG) (value % 100000000);

		CONST ULONG b0 = v0 / 10000;
		CONST ULONG c0 = v0 % 10000;

		CONST ULONG d1 = (b0 / 100) << 1;
		CONST ULONG d2 = (b0 % 100) << 1;

		CONST ULONG d3 = (c0 / 100) << 1;
		CONST ULONG d4 = (c0 % 100) << 1;

		CONST ULONG b1 = v1 / 10000;
		CONST ULONG c1 = v1 % 10000;

		CONST ULONG d5 = (b1 / 100) << 1;
		CONST ULONG d6 = (b1 % 100) << 1;

		CONST ULONG d7 = (c1 / 100) << 1;
		CONST ULONG d8 = (c1 % 100) << 1;

		*buffer++ = gDigitsUNICODE[d1];
		*buffer++ = gDigitsUNICODE[d1 + 1];
		*buffer++ = gDigitsUNICODE[d2];
		*buffer++ = gDigitsUNICODE[d2 + 1];
		*buffer++ = gDigitsUNICODE[d3];
		*buffer++ = gDigitsUNICODE[d3 + 1];
		*buffer++ = gDigitsUNICODE[d4];
		*buffer++ = gDigitsUNICODE[d4 + 1];
		*buffer++ = gDigitsUNICODE[d5];
		*buffer++ = gDigitsUNICODE[d5 + 1];
		*buffer++ = gDigitsUNICODE[d6];
		*buffer++ = gDigitsUNICODE[d6 + 1];
		*buffer++ = gDigitsUNICODE[d7];
		*buffer++ = gDigitsUNICODE[d7 + 1];
		*buffer++ = gDigitsUNICODE[d8];
		*buffer++ = gDigitsUNICODE[d8 + 1];
	}

	*buffer = L'\0';
}

DECL_EXTERN_API(VOID, StringInt64ToStringW, LONG64 value, LPWSTR buffer)
{
	ULONG64 u = (ULONG64) (value);
	if (value < 0)
	{
		*buffer++ = L'-';
		u = ~u + 1;
	}

	HcStringUInt64ToStringW(u, buffer);
}
