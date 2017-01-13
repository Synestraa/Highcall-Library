#ifndef HC_VOLUME_H
#define HC_VOLUME_H

#include "hcdef.h"

typedef struct _FILE_FS_VOLUME_INFORMATION {
	LARGE_INTEGER	VolumeCreationTime;
	ULONG		VolumeSerialNumber;
	ULONG		VolumeLabelLength;
	BOOLEAN		SupportsObjects;
	WCHAR		VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION, *PFILE_FS_VOLUME_INFORMATION;

typedef struct _FILE_FS_ATTRIBUTE_INFORMATION {
	ULONG	FileSystemAttribute;
	LONG	MaximumComponentNameLength;
	ULONG	FileSystemNameLength;
	WCHAR	FileSystemName[1];
} FILE_FS_ATTRIBUTE_INFORMATION, *PFILE_FS_ATTRIBUTE_INFORMATION;

#define FS_VOLUME_BUFFER_SIZE (MAX_PATH * sizeof(WCHAR) + sizeof(FILE_FS_VOLUME_INFORMATION))
#define FS_ATTRIBUTE_BUFFER_SIZE (MAX_PATH * sizeof(WCHAR) + sizeof(FILE_FS_ATTRIBUTE_INFORMATION))

#if defined (__cplusplus)
extern "C" {
#endif

	//
	// Implemented in hcvolume.c
	//

	HC_EXTERN_API BOOLEAN HCAPI HcVolumeGetInformationA(
		_In_opt_  LPCSTR lpRootPathName,
		_Out_opt_ LPSTR  lpVolumeNameBuffer,
		_In_      DWORD   nVolumeNameSize,
		_Out_opt_ LPDWORD lpVolumeSerialNumber,
		_Out_opt_ LPDWORD lpMaximumComponentLength,
		_Out_opt_ LPDWORD lpFileSystemFlags,
		_Out_opt_ LPSTR  lpFileSystemNameBuffer,
		_In_      DWORD   nFileSystemNameSize
	);

	HC_EXTERN_API BOOLEAN HCAPI HcVolumeGetInformationW(
		_In_opt_  LPCWSTR lpRootPathName,
		_Out_opt_ LPWSTR  lpVolumeNameBuffer,
		_In_      DWORD   nVolumeNameSize,
		_Out_opt_ LPDWORD lpVolumeSerialNumber,
		_Out_opt_ LPDWORD lpMaximumComponentLength,
		_Out_opt_ LPDWORD lpFileSystemFlags,
		_Out_opt_ LPWSTR  lpFileSystemNameBuffer,
		_In_      DWORD   nFileSystemNameSize
	);

#endif
#if defined (__cplusplus)
}
#endif