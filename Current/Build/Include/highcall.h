#ifndef HIGHCALL_H
#define HIGHCALL_H

#include "../../private/sys/hcsyscall.h" // should not include

#ifdef _NT_USER
#include "../../public/ntuser.h"
#endif

#ifdef _HC_IMPORTS
#include "../../public/imports.h"
#endif

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
#include "../../public/hccommon.h"

// Windows version defines for initialization routines.

#define WINDOWS_7				0061
#define WINDOWS_8				0062
#define WINDOWS_8_1				0063
#define WINDOWS_10_1507			0100
#define WINDOWS_10_1511			0101
#define WINDOWS_10_1607			0102
#define WINDOWS_NOT_SUPPORTED	0000
#define WINDOWS_NOT_DEFINED	   -0001

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