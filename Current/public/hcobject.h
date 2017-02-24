// Requires documentation

#ifndef HC_OBJECT_H
#define HC_OBJECT_H

#include "hcdef.h"

#define OBJECT_TYPE_ANY	-1

#if defined (__cplusplus)
extern "C" {
#endif

	HC_EXTERN_API HANDLE HCAPI HcObjectTranslateHandle(CONST IN HANDLE Handle);
	HC_EXTERN_API DWORD	HCAPI HcObjectTypeIndexByName(IN LPCWSTR lpObjectName);
	HC_EXTERN_API PLARGE_INTEGER HCAPI HcObjectMillisecondsToNano(OUT PLARGE_INTEGER Timeout, CONST IN DWORD dwMiliseconds);
	HC_EXTERN_API DWORD HCAPI HcObjectWaitMultiple(IN DWORD nCount,IN CONST HANDLE *lpHandles,IN BOOL bWaitAll,IN DWORD dwMilliseconds);
	HC_EXTERN_API DWORD HCAPI HcObjectWait(HANDLE hObject,IN DWORD dwMiliseconds);
	HC_EXTERN_API VOID HCAPI HcObjectClose(HANDLE hObject);

#if defined (__cplusplus)
}
#endif

#endif