#ifndef HC_DEFINE_H
#define HC_DEFINE_H

#include "../../native/native.h"

#if defined (__cplusplus)
extern "C" {
#endif

#define HCAPI __stdcall
#define HIGHCALL_STATUS signed long
typedef long SYS_INDEX;

#define HIGHCALL_ADVANCE(Status)				((HIGHCALL_STATUS)(Status) >= 0)
#define HIGHCALL_SUCCESS						((HIGHCALL_STATUS)0x00000000L)
#define HIGHCALL_FAILED							((HIGHCALL_STATUS)0xC0000001L)
#define HIGHCALL_VERSION_UNDEFINED				((HIGHCALL_STATUS)0xC0000002L)
#define HIGHCALL_WINDOWS_UNDEFINED				((HIGHCALL_STATUS)0xC0000004L)
#define HIGHCALL_SYSCALL_UNDEFINED				((HIGHCALL_STATUS)0xC0000005L)
#define HIGHCALL_IMPORT_UNDEFINED				((HIGHCALL_STATUS)0xC0000006L)

#ifndef INVALID_HANDLE
#define INVALID_HANDLE ((HANDLE)-1)
#endif

#ifdef __cplusplus
#define HC_GLOBAL extern "C"
#else
#define HC_GLOBAL extern
#endif

#ifndef In
#define In
#endif

#ifndef Out
#define Out
#endif

#if defined (__cplusplus)
}
#endif

#endif