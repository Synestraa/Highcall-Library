#ifndef HC_IMPORT_H
#define HC_IMPORT_H

#include "hcdef.h"

typedef NTSTATUS(HCAPI *t_RtlGetVersion) (_Out_ PRTL_OSVERSIONINFOW lpInformation);
HC_GLOBAL t_RtlGetVersion RtlGetVersion;

typedef BOOLEAN(HCAPI *t_RtlEqualUnicodeString) (
	_In_ PUNICODE_STRING String1,
	_In_ PUNICODE_STRING String2,
	_In_ BOOLEAN         CaseInSensitive);
HC_GLOBAL t_RtlEqualUnicodeString RtlEqualUnicodeString;

typedef VOID(HCAPI *t_RtlInitUnicodeString) (
	_Out_    PUNICODE_STRING DestinationString,
	_In_opt_ PCWSTR          SourceString
	);
HC_GLOBAL t_RtlInitUnicodeString RtlInitUnicodeString;

typedef NTSTATUS(HCAPI *t_LdrLoadDll) (IN PWCHAR PathToFile OPTIONAL,
	IN ULONG                Flags OPTIONAL,
	IN PUNICODE_STRING      ModuleFileName,
	OUT PHANDLE             ModuleHandle);
HC_GLOBAL t_LdrLoadDll LdrLoadDll;

#endif