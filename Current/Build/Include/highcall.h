#ifndef HIGHCALL_H
#define HIGHCALL_H

#include "../../private/sys/hcsyscall.h"

#include "../../public/hcdef.h"
#include "../../public/hchook.h"
#include "../../public/hcmodule.h"
#include "../../public/hcstring.h"
#include "../../public/hcprocess.h"
#include "../../public/hctoken.h"
#include "../../public/hcobject.h"
#include "../../public/hcpe.h"
#include "../../public/hcvirtual.h"
#include "../../public/hcinternal.h"
#include "../../public/hcglobal.h"
#include "../../public/hcerror.h"
#include "../../public/hcinject.h"
#include "../../public/hcvolume.h"
#include "../../public/hcfile.h"

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