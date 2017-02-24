/*++

Module Name:

hcprocess.h

Abstract:

This module declares windows NT/WIN32 kernel "process" usermode handlers.

Author:

Synestra 9/7/2016

Revision History:

Synestra 10/15/2016

--*/
#ifndef HC_COMMON_H
#define HC_COMMON_H

#include "hcdef.h"

#if defined (__cplusplus)
extern "C" {
#endif

	HC_EXTERN_API VOID HCAPI HcSleep(CONST IN DWORD dwMilliseconds);

#if defined (__cplusplus)
}
#endif

#endif