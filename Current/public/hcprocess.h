/*++

Module Name:

hcprocess.h

Abstract:

This module declares windows NT/WIN32 kernel "process" usermode handlers. 

Author:

Synestra 9/7/2016

Revision History:

Synestra 10/15/2016

--*/

#ifndef HC_PROCESS_H
#define HC_PROCESS_H

#include "hcdef.h"
#include "hcobject.h"

#if defined (__cplusplus)
extern "C" {
#endif

	//
	// Struct used in callback for HcProcessEnumMappedImagesW, HcProcessEnumModulesW, contains information about
	// the current callback module.
	//
	typedef struct _HC_MODULE_INFORMATIONW
	{
		SIZE_T		Size;
		PVOID		Base;
		LPWSTR		Name;
		LPWSTR		Path;
	} HC_MODULE_INFORMATIONW, *PHC_MODULE_INFORMATIONW;

	//
	// Constructor for HC_MODULE_INFORMATIONW
	// Implemented in hcconstruct.c
	//
	HC_EXTERN_API PHC_MODULE_INFORMATIONW HCAPI HcInitializeModuleInformationW(DWORD NameBufferMax, DWORD PathBufferMax);

	//
	// Deconstructor for HC_MODULE_INFORMATIONW
	// Implemented in hcconstruct.c
	//
	HC_EXTERN_API VOID HCAPI HcDestroyModuleInformationW(PHC_MODULE_INFORMATIONW o);
	
	//
	// Callback for HcProcessEnumMappedImagesW, HcProcessEnumModulesW
	// 
	typedef BOOLEAN(CALLBACK* HC_MODULE_CALLBACK_EVENTW)(HC_MODULE_INFORMATIONW, LPARAM);

	//
	// Struct used in HcProcessQueryByNameExW callback, containing information about the current callback process.
	// Some information requires an open handle to the process, and even so, information is not guaranteed if having an open handle.
	//
	typedef struct _HC_PROCESS_INFORMATION_EXW
	{
		DWORD					Id;
		LPWSTR					Name;
		PHC_MODULE_INFORMATIONW	MainModule;
		BOOLEAN					CanAccess;
		DWORD					ParentProcessId;
	} HC_PROCESS_INFORMATION_EXW, *PHC_PROCESS_INFORMATION_EXW;

	//
	// Constructor for HC_PROCESS_INFORMATION_EXW
	// Implemented in hcconstruct.c
	//
	HC_EXTERN_API PHC_PROCESS_INFORMATION_EXW HCAPI HcInitializeProcessInformationExW(DWORD NameBufferMax);

	//
	// Deconstructor for HC_PROCESS_INFORMATION_EXW
	// Implemented in hcconstruct.c
	//
	HC_EXTERN_API VOID HCAPI HcDestroyProcessInformationExW(PHC_PROCESS_INFORMATION_EXW o);

	//
	// Callback for HcProcessEnumByNameExW
	//
	typedef BOOLEAN(CALLBACK* HC_PROCESS_CALLBACK_EXW)(CONST HC_PROCESS_INFORMATION_EXW, LPARAM);

	//
	// Struct used in HcProcessEnumByNameW callback, containing information about the current callback process.
	//
	typedef struct _HC_PROCESS_INFORMATIONW
	{
		DWORD	Id;
		LPWSTR	Name;
		DWORD   ParentProcessId;
	} HC_PROCESS_INFORMATIONW, *PHC_PROCESS_INFORMATIONW;

	//
	// Constructor for HC_PROCESS_INFORMATIONW
	// Implemented in hcconstruct.c
	//
	HC_EXTERN_API PHC_PROCESS_INFORMATIONW HCAPI HcInitializeProcessInformationW(DWORD NameBufferMax);

	//
	// Deconstructor for HC_PROCESS_INFORMATIONW
	// Implemented in hcconstruct.c
	//
	HC_EXTERN_API VOID HCAPI HcDestroyProcessInformationW(PHC_PROCESS_INFORMATIONW pObj);

	//
	// Callback for HcProcessEnumByNameW
	//
	typedef BOOLEAN(CALLBACK* HC_PROCESS_CALLBACKW)(CONST HC_PROCESS_INFORMATIONW Entry, LPARAM lParam);

	//
	// Callback for HcProcessEnumHandleEntries
	//
	typedef BOOLEAN(CALLBACK* HC_HANDLE_ENTRY_CALLBACKW)(CONST PSYSTEM_HANDLE_TABLE_ENTRY_INFO Entry, LPARAM lParam);

	//
	// Callback for HcProcessEnumHandles
	//
	typedef BOOLEAN(CALLBACK* HC_HANDLE_CALLBACKW)(CONST HANDLE Handle, CONST HANDLE hOwner, LPARAM lParam);

	HC_EXTERN_API DWORD HCAPI HcProcessGetCurrentId(VOID);
	HC_EXTERN_API DWORD HCAPI HcProcessGetId(IN HANDLE Process);

	HC_EXTERN_API BOOLEAN HCAPI HcProcessIsWow64Ex(CONST IN HANDLE hProcess);
	HC_EXTERN_API BOOLEAN HCAPI HcProcessIsWow64(CONST IN DWORD dwProcessId);

	HC_EXTERN_API BOOLEAN HCAPI HcProcessExitCode(CONST IN SIZE_T dwProcessId, IN LPDWORD lpExitCode);
	HC_EXTERN_API BOOLEAN HCAPI HcProcessExitCodeEx(CONST IN HANDLE hProcess, IN LPDWORD lpExitCode);

	HC_EXTERN_API HANDLE HCAPI HcProcessOpen(CONST SIZE_T dwProcessId, CONST ACCESS_MASK DesiredAccess);

	HC_EXTERN_API BOOLEAN HCAPI HcProcessWriteMemory(CONST HANDLE hProcess, CONST LPVOID lpBaseAddress, CONST VOID* lpBuffer, SIZE_T nSize, PSIZE_T lpNumberOfBytesWritten);
	HC_EXTERN_API BOOLEAN HCAPI HcProcessReadMemory(CONST IN HANDLE hProcess, IN LPCVOID lpBaseAddress, IN LPVOID lpBuffer, IN SIZE_T nSize, OUT SIZE_T* lpNumberOfBytesRead);

	HC_EXTERN_API HANDLE HCAPI HcProcessCreateThread(CONST IN HANDLE hProcess, CONST IN LPTHREAD_START_ROUTINE lpStartAddress, CONST IN LPVOID lpParamater, CONST IN DWORD dwCreationFlags);

	HC_EXTERN_API BOOLEAN HCAPI HcProcessReadNullifiedString(CONST HANDLE hProcess, CONST PUNICODE_STRING usStringIn, LPWSTR lpStringOut, CONST SIZE_T lpSize);

	HC_EXTERN_API BOOLEAN HCAPI HcProcessLdrModuleToHighCallModule(CONST IN HANDLE hProcess, CONST IN PLDR_DATA_TABLE_ENTRY Module, OUT PHC_MODULE_INFORMATIONW phcModuleOut);

	HC_EXTERN_API BOOLEAN HCAPI HcProcessQueryInformationModule(CONST IN HANDLE hProcess, IN HMODULE hModule OPTIONAL, OUT PHC_MODULE_INFORMATIONW phcModuleOut);

	HC_EXTERN_API BOOLEAN HCAPI HcProcessEnumModulesW(CONST HANDLE hProcess, CONST HC_MODULE_CALLBACK_EVENTW hcmCallback, LPARAM lParam);
	HC_EXTERN_API BOOLEAN HCAPI HcProcessEnumMappedImagesW(CONST HANDLE ProcessHandle, CONST HC_MODULE_CALLBACK_EVENTW hcmCallback, LPARAM lParam);

	HC_EXTERN_API BOOLEAN HCAPI HcProcessReady(CONST SIZE_T dwProcessId);
	HC_EXTERN_API BOOLEAN HCAPI HcProcessReadyEx(CONST HANDLE hProcess);

	HC_EXTERN_API BOOLEAN HCAPI HcProcessSuspend(CONST SIZE_T dwProcessId);
	HC_EXTERN_API BOOLEAN HCAPI HcProcessSuspendEx(CONST HANDLE hProcess);

	HC_EXTERN_API BOOLEAN HCAPI HcProcessResume(CONST SIZE_T dwProcessId);
	HC_EXTERN_API BOOLEAN HCAPI HcProcessResumeEx(CONST HANDLE hProcess);

	HC_EXTERN_API SIZE_T HCAPI HcWin32GetModuleFileName(CONST HANDLE hProcess, CONST LPVOID lpv, LPWSTR lpFilename, CONST DWORD nSize);
	HC_EXTERN_API SIZE_T HCAPI HcProcessModuleFileName(CONST HANDLE hProcess, CONST LPVOID lpv, LPWSTR lpFilename, CONST DWORD nSize);

	HC_EXTERN_API BOOLEAN HCAPI HcProcessGetById(CONST IN DWORD dwProcessId, OUT PHC_PROCESS_INFORMATIONW pProcessInfo);
	HC_EXTERN_API BOOLEAN HCAPI HcProcessGetByNameW(CONST IN LPCWSTR lpName, OUT PHC_PROCESS_INFORMATIONW pProcessInfo);

	HC_EXTERN_API BOOLEAN HCAPI HcProcessEnumHandleEntries(HC_HANDLE_ENTRY_CALLBACKW callback, LPARAM lParam);
	HC_EXTERN_API BOOLEAN HCAPI HcProcessEnumHandles(HC_HANDLE_CALLBACKW callback, DWORD dwTypeIndex, LPARAM lParam);

	HC_EXTERN_API BOOLEAN HCAPI HcProcessEnumByNameW(CONST LPCWSTR lpProcessName, HC_PROCESS_CALLBACKW Callback, LPARAM lParam);
	HC_EXTERN_API BOOLEAN HCAPI HcProcessEnumByNameExW(CONST LPCWSTR lpProcessName, HC_PROCESS_CALLBACK_EXW hcpCallback, LPARAM lParam);

	HC_EXTERN_API BOOLEAN HCAPI HcProcessSetPrivilegeA(CONST HANDLE hProcess, CONST LPCSTR Privilege, CONST BOOLEAN bEnablePrivilege);
	HC_EXTERN_API BOOLEAN HCAPI HcProcessSetPrivilegeW(CONST HANDLE hProcess, CONST LPCWSTR Privilege, CONST BOOLEAN bEnablePrivilege);

	HC_EXTERN_API BOOLEAN HCAPI HcProcessGetPeb(CONST HANDLE hProcess, PPEB pPeb);
	HC_EXTERN_API SIZE_T HCAPI HcProcessGetCommandLineA(CONST HANDLE hProcess, LPSTR* lpszCommandline, CONST BOOLEAN bAlloc);
	HC_EXTERN_API SIZE_T HCAPI HcProcessGetCommandLineW(CONST HANDLE hProcess, LPWSTR* lpszCommandline, CONST BOOLEAN bAlloc);
	HC_EXTERN_API SIZE_T HCAPI HcProcessGetCurrentDirectoryW(CONST HANDLE hProcess, LPWSTR* szDirectory);
	HC_EXTERN_API SIZE_T HCAPI HcProcessGetCurrentDirectoryA(CONST HANDLE hProcess, LPSTR* szDirectory);

#if defined (__cplusplus)
}
#endif

#endif