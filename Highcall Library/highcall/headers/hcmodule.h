// Requires documentation

#ifndef HC_MODULE_H
#define HC_MODULE_H

#include "hcdef.h"

//
// Callback function definition for HcModuleListExports.
//
typedef BOOLEAN(CALLBACK* HC_EXPORT_LIST_CALLBACK)(LPCSTR, LPARAM);

#if defined (__cplusplus)
extern "C" {
#endif


	HC_EXTERN_API HMODULE HCAPI HcModuleHandleW(LPCWSTR lpModuleName);
	HC_EXTERN_API HMODULE HCAPI HcModuleHandleA(LPCSTR lpModuleName);
	HC_EXTERN_API BOOLEAN HCAPI HcModuleListExports(HMODULE hModule, HC_EXPORT_LIST_CALLBACK callback, LPARAM lpParam);
	HC_EXTERN_API SIZE_T HCAPI HcModuleProcedureAddressA(HANDLE hModule, LPCSTR lpProcedureName);
	HC_EXTERN_API SIZE_T HCAPI HcModuleProcedureAddressW(HANDLE hModule, LPCWSTR lpProcedureName);
	HC_EXTERN_API HMODULE HCAPI HcModuleLoadA(LPCSTR lpPath);
	HC_EXTERN_API HMODULE HCAPI HcModuleLoadW(LPCWSTR lpPath);

#endif

#if defined (__cplusplus)
}
#endif