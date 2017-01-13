// Requires documentation

#ifndef HCPE_H
#define HCPE_H

#include "hcdef.h"

#if defined (__cplusplus)
extern "C" {
#endif

	HC_EXTERN_API BOOLEAN HCAPI HcPEIsValid(LPVOID);
	HC_EXTERN_API PIMAGE_DOS_HEADER HCAPI HcPEGetDosHeader(LPVOID);
	HC_EXTERN_API PIMAGE_NT_HEADERS HCAPI HcPEGetNtHeader(LPVOID);
	HC_EXTERN_API PIMAGE_EXPORT_DIRECTORY HCAPI HcPEGetExportDirectory(LPVOID);
	HC_EXTERN_API DWORD HCAPI HcPEGetRawFromRva(PIMAGE_NT_HEADERS pImageHeader, SIZE_T RVA);

#if defined (__cplusplus)
}
#endif

#endif