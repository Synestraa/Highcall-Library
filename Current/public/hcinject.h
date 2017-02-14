/*++

Module Name:

hcinject.h

Abstract:

This module declares windows dll injecting functions.

Author:

Synestra 10/16/2016

Revision History:

--*/

#ifndef HC_INJECT_H
#define HC_INJECT_H

//
// Main definition file, i.e. HCAPI __stdcall
//
#include "hcdef.h"

#if defined (__cplusplus)
extern "C" {
#endif

	//
	// Implemented in hcinject.c
	//
	HC_EXTERN_API BOOLEAN HCAPI HcInjectManualMapW(HANDLE hProcess, LPCWSTR szcPath);
	HC_EXTERN_API BOOLEAN HCAPI HcInjectRemoteThreadW(HANDLE hProcess, LPCWSTR szcPath);
	
#if defined (__cplusplus)
}
#endif

#endif // HC_INJECT_H