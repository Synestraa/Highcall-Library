#pragma once

#pragma region General Includes
#include "native.h" /* contains native.h, wintype.h */

#include <winerror.h> /* for DOS error codes */
#include <WinBase.h> /* definitions */
#pragma endregion

#pragma region General Usage Definitions
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

typedef long SYS_INDEX;

#ifndef INVALID_HANDLE
#define INVALID_HANDLE ((HANDLE)-1)
#endif

#ifndef INFINITE
#define INFINITE 0xFFFFFFFF  // Infinite timeout
#endif

#define SYSI_INVALID (SYS_INDEX) (0xffffffff)
#define SYSI_INVALID1 (SYS_INDEX) (0xfffffffe)
#define SYSI_INVALID2 (SYS_INDEX) (0xfffffffd)
#define SYSI_INVALID3 (SYS_INDEX) (0xfffffffc)
#define SYSI_INVALID4 (SYS_INDEX) (0xfffffffb)
#define SYSI_INVALID5 (SYS_INDEX) (0xfffffffa)
#define SYSI_INVALID6 (SYS_INDEX) (0xfffffff9)

//
// dll linkage
//
#ifdef HIGHCALL_DYNAMIC

#ifdef __cplusplus
#define HC_EXTERN_API extern "C" __declspec(dllexport)
#else
#define HC_EXTERN_API extern __declspec(dllexport)
#endif // CPP

#else
#define HC_EXTERN_API /* no linkage */
#endif

//
// .asm global fix, e
//
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

//
// Windows version defines for initialization routines.
//
#define WINDOWS_7				0
#define WINDOWS_7_1				1
#define WINDOWS_8				2
#define WINDOWS_8_1				3
#define WINDOWS_10_1507			4
#define WINDOWS_10_1511			5
#define WINDOWS_10_1607			6
#define WINDOWS_NOT_SUPPORTED	0
#define WINDOWS_NOT_DEFINED	   -1
#pragma endregion