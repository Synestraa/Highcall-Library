#include <highcall.h>

DECL_EXTERN_API(INT, GetClassNameW, HWND hWnd, LPWSTR lpClassName, int nMaxCount)
{
	UNICODE_STRING ClassName;
	int Result;

	ClassName.Buffer = lpClassName;
	ClassName.Length = nMaxCount;
	ClassName.MaximumLength = nMaxCount + 2;

	Result = HcUserGetClassName(hWnd,
		FALSE,
		&ClassName);

	return Result;
}