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

#if defined (__cplusplus)
extern "C" {
#endif

	//
	// Implemented in hcerror.c
	//

	VOID HCAPI HcErrorSetNoteA(IN LPCSTR lpNote);
	VOID HCAPI HcErrorGetNoteA(OUT LPSTR lpOutNote);

	VOID HCAPI HcErrorSetNoteW(IN LPCWSTR lpNote);
	VOID HCAPI HcErrorGetNoteW(OUT LPWSTR lpOutNote);

	//
	// Unimplemented.
	//

	SIZE_T HCAPI HcErrorGetNoteSize();

	//
	// Implemented in hcerror.c
	//

	VOID HCAPI HcErrorSetDosError(IN DWORD dwErrCode);
	DWORD HCAPI HcErrorGetDosError(VOID);

	DWORD HCAPI HcErrorSetNtStatus(IN NTSTATUS Status);
	NTSTATUS HCAPI HcErrorGetLastStatus();

#if defined (__cplusplus)
}
#endif

#endif
