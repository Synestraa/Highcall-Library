#ifndef HC_DEFINE_H
#define HC_DEFINE_H

#include "../public/native.h"

//
// Define HIGHCALL_DYNAMIC for .dll usage.
//
#ifdef _WINDLL
#define HIGHCALL_DYNAMIC
#endif

//
// Standard calling convention for highcall api functions.
//
#define HCAPI __stdcall

typedef signed long HIGHCALL_STATUS;
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

#ifndef INFINITE
#define INFINITE 0xFFFFFFFF  // Infinite timeout
#endif

#ifdef HIGHCALL_DYNAMIC

#ifdef __cplusplus
#define HC_EXTERN_API extern "C" __declspec(dllexport)
#else
#define HC_EXTERN_API extern __declspec(dllexport)
#endif // CPP

#else

#define HC_EXTERN_API

#endif // DYNAMIC LIBRARY

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

#endif