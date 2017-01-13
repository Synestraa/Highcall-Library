#ifndef HC_TRAMPOLINE_H
#define HC_TRAMPOLINE_H

#include "hcdef.h"

typedef long HStatus;

#define HOOK_NO_ERR					(HStatus)0x0000
#define HOOK_INVALID_SOURCE			(HStatus)0x0001
#define HOOK_INVALID_DESTINATION	(HStatus)0x0002
#define HOOK_NOT_ENOUGH_SPACE		(HStatus)0x0003
#define HOOK_CAVE_FAILURE			(HStatus)0x0004
#define HOOK_INVALID_SIZE			(HStatus)0x0005
#define HOOK_FAILED_API				(HStatus)0x0006
#define HOOK_PROTECTION_FAILURE		(HStatus)0x0007
#define HOOK_INVALID_RESTORATION	(HStatus)0x0008

typedef enum _DetourType
{
	Relative = 1,
	Absolute = 2
} DetourType;

typedef enum _DetourFlags
{
	Recreate		= (1 << 0),
	Single			= (1 << 1),
	SaveOriginal	= (1 << 2),
	JumpOriginal	= (1 << 3),
	Reconstruct		= (1 << 4),
	Default			= ((int)Recreate | JumpOriginal | SaveOriginal),
} DetourFlags;

typedef struct _DetourContext
{
	/* 
	--	*Required IN.
	--	Where it will be originated from. 
	*/
	LPVOID lpSource;

	/* 
	--	*Required IN.
	--	Where this hook will lead to. 
	*/
	LPVOID lpDestination;

	/*
	--	OUT.
	--	Length of the detour. 
	*/
	DWORD dwLength;

	/*
	--	OUT.
	--	Original function pointer.
	-- ** Contains relocation fixes.
	*/
	PBYTE pbReconstructed;

	/*
	--	OUT.
	--	Original function bytes;
	*/
	PBYTE pbOriginal;

	/*
	--	OUT.
	--	Hook type. [Relative/Absolute]
	*/
	DetourType Type;

	//
	// IN
	//
	DetourFlags Flags;

} DetourContext, *PDetourContext;

#if defined (__cplusplus)
extern "C" {
#endif

	HC_EXTERN_API HStatus HCAPI HcHookDetour(PDetourContext Context);
	HC_EXTERN_API HStatus HCAPI HcHookDetourContextRestore(PDetourContext Context);
	HC_EXTERN_API HStatus HCAPI HcHookRelocateCode(PBYTE Code, DWORD Size, SIZE_T Source);
	HC_EXTERN_API DWORD HCAPI HcHookAssertLength(LPVOID lpBaseAddress, DWORD MinimumLength);
	HC_EXTERN_API PVOID HCAPI HcHookRecreateCode(PBYTE lpBaseAddress, DWORD dwMinimumSize);

#endif
#if defined (__cplusplus)
}
#endif