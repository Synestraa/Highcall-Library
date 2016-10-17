#ifndef HC_OBJECT_H
#define HC_OBJECT_H

#include "hcdef.h"

#if defined (__cplusplus)
extern "C" {
#endif

	DWORD WINAPI HcObjectWaitMultiple(IN DWORD nCount,IN CONST HANDLE *lpHandles,IN BOOL bWaitAll,IN DWORD dwMilliseconds);
	DWORD HCAPI HcObjectWait(HANDLE hObject,IN DWORD dwMiliseconds);
	VOID HCAPI HcObjectClose(HANDLE hObject);

#if defined (__cplusplus)
}
#endif

#endif