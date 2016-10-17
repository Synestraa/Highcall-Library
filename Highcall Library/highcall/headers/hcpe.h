#ifndef HCPE_H
#define HCPE_H

#include "hcdef.h"

#if defined (__cplusplus)
extern "C" {
#endif

	BOOLEAN HCAPI HcPEIsValid(LPVOID);
	PIMAGE_DOS_HEADER HCAPI HcPEGetDosHeader(LPVOID);
	PIMAGE_NT_HEADERS HCAPI HcPEGetNtHeader(LPVOID);
	PIMAGE_EXPORT_DIRECTORY HCAPI HcPEGetExportDirectory(LPVOID);
	DWORD HCAPI HcPEGetRawFromRva(PIMAGE_NT_HEADERS pImageHeader, SIZE_T RVA);

#if defined (__cplusplus)
}
#endif

#endif