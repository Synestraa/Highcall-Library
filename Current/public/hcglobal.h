#ifndef GLOBAL_H
#define GLOBAL_H

#include "hcdef.h"

typedef enum
{
	undefined = 0,
	x86 = 1,
	x86_x64 = 2
} Architecture_Type;

typedef struct _HcGlobalEnv
{
	/* Is the process running with administrative privileges? */
	BOOLEAN IsElevated;

	ULONG WindowsVersion;
	Architecture_Type ProcessorArchitecture;

	/* Is the program running in Wow64? */
	BOOLEAN IsWow64;

	/* The base of kernel32.dll */
	HMODULE HandleKernel32;

	/* The base of ntdll.dll */
	HMODULE HandleNtdll;

	/* The base of user32.dll */
	HMODULE HandleUser32;

} HcGlobalEnv, *PHcGlobalEnv;

HC_GLOBAL HcGlobalEnv HcGlobal;

#endif