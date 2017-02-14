// Requires documentation

#ifndef HC_OBJECT_H
#define HC_OBJECT_H

#include "hcdef.h"

#if defined (__cplusplus)
extern "C" {
#endif

	HC_EXTERN_API DWORD HCAPI HcObjectWaitMultiple(IN DWORD nCount,IN CONST HANDLE *lpHandles,IN BOOL bWaitAll,IN DWORD dwMilliseconds);
	HC_EXTERN_API DWORD HCAPI HcObjectWait(HANDLE hObject,IN DWORD dwMiliseconds);
	HC_EXTERN_API VOID HCAPI HcObjectClose(HANDLE hObject);

#if defined (__cplusplus)
}
#endif

#endif