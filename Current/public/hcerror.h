/*++

Module Name:

hcerror.h

Abstract:

This module declares error handling functions from kernel32.dll, as well as a custom "note".

Author:

Synestra 10/10/2016, information was gathered from various sources.

Revision History:

--*/

#ifndef HC_ERROR_H
#define HC_ERROR_H

//
// Standard definition include.
//

#include "hcdef.h"

#include <winerror.h> // for the error codes

#if defined (__cplusplus)
extern "C" {
#endif

	//
	// Implemented in hcerror.c
	//

	HC_EXTERN_API VOID HCAPI HcErrorSetDosError(IN DWORD dwErrCode);
	HC_EXTERN_API DWORD HCAPI HcErrorGetDosError(VOID);

	HC_EXTERN_API DWORD HCAPI HcErrorSetNtStatus(IN NTSTATUS Status);
	HC_EXTERN_API NTSTATUS HCAPI HcErrorGetLastStatus();

#if defined (__cplusplus)
}
#endif

#endif
