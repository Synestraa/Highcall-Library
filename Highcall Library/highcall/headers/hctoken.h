/*++

Module Name:

hctoken.h

Abstract:

This module declares windows privilege handlers for hctoken.c

Author:

Synestra 9/11/2016

Revision History:

Synestra 10/15/2016

--*/

#ifndef HC_TOKEN_H
#define HC_TOKEN_H

//
// Main definition file.
//
#include "hcdef.h"

#if defined (__cplusplus)
extern "C" {
#endif

	//
	// Defined in hctoken.c
	//

	PLUID HCAPI HcLookupPrivilegeValueW(IN LPCWSTR Name);
	PLUID HCAPI HcLookupPrivilegeValueA(IN LPCSTR Name);

	NTSTATUS HCAPI HcTokenIsElevated(_In_ HANDLE TokenHandle, _Out_ PBOOLEAN Elevated);

#if defined (__cplusplus)
}
#endif

#endif