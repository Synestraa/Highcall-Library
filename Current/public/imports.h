#ifndef HC_IMPORT_H
#define HC_IMPORT_H

#include "../public/hcdef.h"

//
// -- undocumented, cleared up.
// this header contains function imports for things that are not yet implemented but extremely necessary
// this is what is refered to as "being lazy"
// hopefully, one day, I will stop being a lazy fucking retard and actually update it with the proper code.
// cheers, me.
//
// well, seems like im using ntdll.lib now.
//

#pragma comment(lib, "ntdll.lib")

//
// RTL Path Types
//
typedef enum _RTL_PATH_TYPE
{
	RtlPathTypeUnknown,
	RtlPathTypeUncAbsolute,
	RtlPathTypeDriveAbsolute,
	RtlPathTypeDriveRelative,
	RtlPathTypeRooted,
	RtlPathTypeRelative,
	RtlPathTypeLocalDevice,
	RtlPathTypeRootLocalDevice,
} RTL_PATH_TYPE;

#define RtlProcessHeap() ((HANDLE)(NtCurrentPeb()->ProcessHeap))

NTSYSAPI NTSTATUS NTAPI RtlGetVersion(
	_Out_ PRTL_OSVERSIONINFOW lpInformation);

NTSYSAPI BOOLEAN NTAPI RtlEqualUnicodeString(
	_In_ PUNICODE_STRING String1,
	_In_ PUNICODE_STRING String2,
	_In_ BOOLEAN         CaseInSensitive);

NTSYSAPI VOID NTAPI RtlInitUnicodeString(
	_Out_    PUNICODE_STRING DestinationString,
	_In_opt_ PCWSTR          SourceString);

NTSYSAPI NTSTATUS NTAPI LdrLoadDll(
	IN PWCHAR		   PathToFile OPTIONAL,
	IN ULONG           Flags OPTIONAL,
	IN PUNICODE_STRING ModuleFileName,
	OUT PHANDLE        ModuleHandle);

NTSYSAPI VOID NTAPI RtlAcquirePebLock (VOID);
NTSYSAPI VOID NTAPI RtlReleasePebLock(VOID);

NTSYSAPI NTSTATUS NTAPI RtlLeaveCriticalSection(_In_ PRTL_CRITICAL_SECTION 	CriticalSection);
NTSYSAPI NTSTATUS NTAPI RtlEnterCriticalSection(_In_ PRTL_CRITICAL_SECTION 	CriticalSection);

NTSYSAPI BOOLEAN NTAPI RtlDosPathNameToNtPathName_U(
	_In_opt_z_ PCWSTR 	DosPathName,
	_Out_ PUNICODE_STRING 	NtPathName,
	_Out_opt_ PCWSTR * 	NtFileNamePart,
	_Out_opt_ PRTL_RELATIVE_NAME_U 	DirectoryInfo);

NTSYSAPI BOOLEAN NTAPI RtlFreeHeap(
	IN PVOID HeapHandle,
	IN ULONG 	Flags,
	IN PVOID 	HeapBase);

NTSYSAPI PVOID NTAPI RtlAllocateHeap(
	IN PVOID HeapHandle,
	IN ULONG 	Flags,
	IN SIZE_T 	Size);

NTSYSAPI BOOLEAN NTAPI RtlFreeHeap(IN PVOID HeapHandle,
	IN ULONG 	Flags,
	IN PVOID 	HeapBase);

#endif