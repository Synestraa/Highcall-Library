#include "../public/hcvolume.h"
#include "../public/hcerror.h"
#include "../public/hcvirtual.h"
#include "../public/hcstring.h"
#include "../public/hcobject.h"
#include "../public/hcfile.h"
#include "../public/imports.h"

#include "sys/hcsyscall.h"

static
HANDLE
HCAPI
HcFileOpenDirectory(IN LPCWSTR DirName,
	IN BOOLEAN Write)
{
	UNICODE_STRING NtPathU = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	NTSTATUS errCode;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	HANDLE hFile = NULL;

	if (!RtlDosPathNameToNtPathName_U(DirName, &NtPathU, NULL, NULL))
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
		return INVALID_HANDLE;
	}

	InitializeObjectAttributes(&ObjectAttributes,
		&NtPathU,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	errCode = HcCreateFile(&hFile,
		Write ? FILE_GENERIC_WRITE : FILE_GENERIC_READ,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		0,
		NULL,
		0);

	RtlFreeHeap(RtlProcessHeap(), 0, NtPathU.Buffer);

	if (!NT_SUCCESS(errCode))
	{
		HcErrorSetNtStatus(errCode);
		return INVALID_HANDLE;
	}

	return hFile;
}


HC_EXTERN_API 
BOOLEAN 
HCAPI 
HcVolumeGetInformationA(
	_In_opt_  LPCSTR  lpRootPathName,
	_Out_opt_ LPSTR   lpVolumeNameBuffer,
	_In_      DWORD   nVolumeNameSize,
	_Out_opt_ LPDWORD lpVolumeSerialNumber,
	_Out_opt_ LPDWORD lpMaximumComponentLength,
	_Out_opt_ LPDWORD lpFileSystemFlags,
	_Out_opt_ LPSTR   lpFileSystemNameBuffer,
	_In_      DWORD   nFileSystemNameSize
) {
	LPWSTR FileSystemNameU = NULL;
	LPWSTR VolumeNameU = NULL;
	PWCHAR RootPathNameW;
	BOOL Result;

	RootPathNameW = HcStringConvertAtoW(lpRootPathName);
	if (!RootPathNameW)
	{
		return FALSE;
	}

	if (lpVolumeNameBuffer)
	{
		VolumeNameU = HcStringAllocW(nVolumeNameSize);

		if (VolumeNameU == NULL)
		{
			goto FailNoMem;
		}
	}

	if (lpFileSystemNameBuffer)
	{
		FileSystemNameU = HcStringAllocW(nFileSystemNameSize);

		if (FileSystemNameU == NULL)
		{
			if (VolumeNameU != NULL)
			{
				HcFree(VolumeNameU);
			}

		FailNoMem:
			HcErrorSetNtStatus(STATUS_NO_MEMORY);
			return FALSE;
		}
	}

	Result = HcVolumeGetInformationW(RootPathNameW,
		VolumeNameU,
		nVolumeNameSize,
		lpVolumeSerialNumber,
		lpMaximumComponentLength,
		lpFileSystemFlags,
		FileSystemNameU,
		nFileSystemNameSize);

	if (Result)
	{
		if (lpVolumeNameBuffer)
		{
			HcStringCopyConvertWtoA(VolumeNameU, lpVolumeNameBuffer, nVolumeNameSize);
		}

		if (lpFileSystemNameBuffer)
		{
			HcStringCopyConvertWtoA(FileSystemNameU, lpFileSystemNameBuffer, nFileSystemNameSize);
		}
	}

	if (lpVolumeNameBuffer)
	{
		HcFree(VolumeNameU);
	}

	if (lpFileSystemNameBuffer)
	{
		HcFree(FileSystemNameU);
	}

	if (RootPathNameW)
	{
		HcFree(RootPathNameW);
	}

	return Result;
}

HC_EXTERN_API 
BOOLEAN 
HCAPI 
HcVolumeGetInformationW(
	_In_opt_  LPCWSTR lpRootPathName,
	_Out_opt_ LPWSTR  lpVolumeNameBuffer,
	_In_      DWORD   nVolumeNameSize,
	_Out_opt_ LPDWORD lpVolumeSerialNumber,
	_Out_opt_ LPDWORD lpMaximumComponentLength,
	_Out_opt_ LPDWORD lpFileSystemFlags,
	_Out_opt_ LPWSTR  lpFileSystemNameBuffer,
	_In_      DWORD   nFileSystemNameSize
) {
	UCHAR Buffer[max(FS_VOLUME_BUFFER_SIZE, FS_ATTRIBUTE_BUFFER_SIZE)] = { 0 };
	PFILE_FS_VOLUME_INFORMATION FileFsVolume = (PFILE_FS_VOLUME_INFORMATION)Buffer;
	PFILE_FS_ATTRIBUTE_INFORMATION FileFsAttribute = (PFILE_FS_ATTRIBUTE_INFORMATION)Buffer;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	WCHAR RootPathName[MAX_PATH] = { 0 };
	HANDLE hFile;
	NTSTATUS errCode;

	if (HcStringIsNullOrEmpty(lpRootPathName))
	{
		HcFileGetCurrentDirectoryW(MAX_PATH, RootPathName);
	}
	else
	{
		HcStringCopyW(RootPathName, lpRootPathName, 3);
	}
	RootPathName[3] = 0;

	hFile = HcFileOpenDirectory(RootPathName, FALSE);
	if (hFile == INVALID_HANDLE)
	{
		return FALSE;
	}

	errCode = HcQueryVolumeInformationFile(hFile,
		&IoStatusBlock,
		FileFsVolume,
		FS_VOLUME_BUFFER_SIZE,
		FileFsVolumeInformation);

	if (!NT_SUCCESS(errCode))
	{
		HcObjectClose(hFile);
		HcErrorSetNtStatus(errCode);
		return FALSE;
	}

	if (lpVolumeSerialNumber)
		*lpVolumeSerialNumber = FileFsVolume->VolumeSerialNumber;

	if (lpVolumeNameBuffer)
	{
		if (nVolumeNameSize * sizeof(WCHAR) >= FileFsVolume->VolumeLabelLength + sizeof(WCHAR))
		{
			HcInternalCopy(lpVolumeNameBuffer,
				FileFsVolume->VolumeLabel,
				FileFsVolume->VolumeLabelLength);

			lpVolumeNameBuffer[FileFsVolume->VolumeLabelLength / sizeof(WCHAR)] = 0;
		}
		else
		{
			HcObjectClose(hFile);
			HcErrorSetNtStatus(STATUS_INSUFFICIENT_RESOURCES);
			return FALSE;
		}
	}

	errCode = HcQueryVolumeInformationFile(hFile,
		&IoStatusBlock,
		FileFsAttribute,
		FS_ATTRIBUTE_BUFFER_SIZE,
		FileFsAttributeInformation);

	HcObjectClose(hFile);
	if (!NT_SUCCESS(errCode))
	{
		HcErrorSetNtStatus(errCode);
		return FALSE;
	}

	if (lpFileSystemFlags)
		*lpFileSystemFlags = FileFsAttribute->FileSystemAttribute;

	if (lpMaximumComponentLength)
		*lpMaximumComponentLength = FileFsAttribute->MaximumComponentNameLength;

	if (lpFileSystemNameBuffer)
	{
		if (nFileSystemNameSize * sizeof(WCHAR) >= FileFsAttribute->FileSystemNameLength + sizeof(WCHAR))
		{
			HcInternalCopy(lpFileSystemNameBuffer,
				FileFsAttribute->FileSystemName,
				FileFsAttribute->FileSystemNameLength);

			lpFileSystemNameBuffer[FileFsAttribute->FileSystemNameLength / sizeof(WCHAR)] = 0;
		}
		else
		{
			HcErrorSetNtStatus(STATUS_INSUFFICIENT_RESOURCES);
			return FALSE;
		}
	}
	return TRUE;
}