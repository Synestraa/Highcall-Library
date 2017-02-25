#include <highcall.h>

#include "../../public/imports.h"

DECL_EXTERN_API(DWORD, PathGetFullPathNameA, IN LPCSTR lpFileName, OUT LPSTR lpBuffer)
{
	LPWSTR lpTemp = HcStringAllocW(MAX_PATH);
	LPWSTR lpConvertedName;
	DWORD Length;

	lpConvertedName = HcStringConvertAtoW(lpFileName);
	if (!lpConvertedName)
	{
		HcFree(lpTemp);
		return 0;
	}

	Length = HcPathGetFullPathNameW(lpConvertedName, lpTemp);
	if (Length > 0)
	{
		HcStringCopyConvertWtoA(lpTemp, lpBuffer, Length);
	}

	HcFree(lpTemp);
	HcFree(lpConvertedName);
	return Length;
}

DECL_EXTERN_API(DWORD, PathGetFullPathNameW, IN LPCWSTR lpFileName, OUT LPWSTR lpBuffer)
{
	/* Rewriting this would take ages, cba right now lol */
	return RtlGetFullPathName_U(lpFileName,
		MAX_PATH * sizeof(WCHAR),
		lpBuffer,
		NULL) / sizeof(WCHAR);
}

DECL_EXTERN_API(DWORD, PathGetTempFolderW, IN LPWSTR lpBuffer)
/* Rtl is safe to use in this case (there is barely any trace, no system calls) although it's still a @TODO due to import hooking. */
{
	return 0;
}

DECL_EXTERN_API(DWORD, PathGetTempFolderA, IN LPWSTR lpBuffer)
{
	return 0;
}
