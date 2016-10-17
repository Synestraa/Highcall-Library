#ifndef HIGHCALL_H
#define HIGHCALL_H

#include "../sys/hcsyscall.h"

#include "../headers/hcdef.h"
#include "../headers/hcimport.h"
#include "../headers/hchook.h"
#include "../headers/hcmodule.h"
#include "../headers/hcstring.h"
#include "../headers/hcprocess.h"
#include "../headers/hctoken.h"
#include "../headers/hcobject.h"
#include "../headers/hcpe.h"
#include "../headers/hcvirtual.h"
#include "../headers/hcinternal.h"
#include "../headers/global.h"
#include "../headers/hcerror.h"
#include "../headers/hcinject.h"

// Windows version defines for initialization routines.

#define WINDOWS_7 61
#define WINDOWS_8 62
#define WINDOWS_8_1 63
#define WINDOWS_10_1507 100
#define WINDOWS_10_1511 101
#define WINDOWS_10_1607 102
#define WINDOWS_NOT_SUPPORTED 0
#define WINDOWS_NOT_DEFINED -1

#if defined (__cplusplus)
extern "C" {
#endif

	HIGHCALL_STATUS 
		HCAPI
		HcInitialize();

#if defined (__cplusplus)
}
#endif

#endif