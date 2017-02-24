// Requires documentation

#ifndef HCPE_H
#define HCPE_H

#include "hcdef.h"

#if defined (__cplusplus)
extern "C" {
#endif

	HC_EXTERN_API BOOLEAN HCAPI HcPEIsValid(HMODULE);
	HC_EXTERN_API PIMAGE_DOS_HEADER HCAPI HcPEGetDosHeader(HMODULE);
	HC_EXTERN_API PIMAGE_NT_HEADERS HCAPI HcPEGetNtHeader(HMODULE);
	HC_EXTERN_API PIMAGE_EXPORT_DIRECTORY HCAPI HcPEGetExportDirectory(HMODULE);
	HC_EXTERN_API ULONG HCAPI HcPEOffsetFromRVA(PIMAGE_NT_HEADERS pImageHeader, PBYTE RVA);

#if defined (__cplusplus)
}
#endif

#endif