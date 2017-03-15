#include <highcall.h>

#include "../sys/syscall.h"
#include "../../public/imports.h"

DECL_EXTERN_API(BOOLEAN, VolumeGetInformationA, 
	IN  LPCSTR	lpRootPathName OPTIONAL,
	OUT LPSTR	lpVolumeNameBuffer OPTIONAL,
	IN  DWORD   nVolumeNameSize,
	OUT LPDWORD lpVolumeSerialNumber OPTIONAL,
	OUT LPDWORD lpMaximumComponentLength OPTIONAL,
	OUT LPDWORD lpFileSystemFlags OPTIONAL,
	OUT LPSTR	lpFileSystemNameBuffer OPTIONAL,
	IN  DWORD   nFileSystemNameSize)
{
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

DECL_EXTERN_API(BOOLEAN, VolumeGetInformationW, 
	IN  LPCWSTR lpRootPathName OPTIONAL,
	OUT LPWSTR  lpVolumeNameBuffer OPTIONAL,
	IN  DWORD   nVolumeNameSize,
	OUT LPDWORD lpVolumeSerialNumber OPTIONAL,
	OUT LPDWORD lpMaximumComponentLength OPTIONAL,
	OUT LPDWORD lpFileSystemFlags OPTIONAL,
	OUT LPWSTR  lpFileSystemNameBuffer OPTIONAL,
	IN  DWORD   nFileSystemNameSize)
{
	HANDLE hFile;
	NTSTATUS Status;
	UCHAR Buffer[max(FS_VOLUME_BUFFER_SIZE, FS_ATTRIBUTE_BUFFER_SIZE)];
	IO_STATUS_BLOCK IoStatusBlock;
	WCHAR RootPathName[MAX_PATH];
	PFILE_FS_VOLUME_INFORMATION FileFsVolume = (PFILE_FS_VOLUME_INFORMATION)Buffer;
	PFILE_FS_ATTRIBUTE_INFORMATION FileFsAttribute = (PFILE_FS_ATTRIBUTE_INFORMATION)Buffer;

	ZERO(&Buffer);
	ZERO(&IoStatusBlock);
	ZERO(&RootPathName);

	if (HcStringIsNullOrEmpty(lpRootPathName))
	{
		HcFileCurrentDirectoryW(RootPathName);
	}
	else
	{
		HcStringCopyW(RootPathName, lpRootPathName, 3);
	}
	RootPathName[3] = 0;

	hFile = HcFileOpenW(RootPathName, OPEN_EXISTING, GENERIC_READ);
	if (hFile == INVALID_HANDLE)
	{
		return FALSE;
	}

	Status = HcQueryVolumeInformationFile(hFile,
		&IoStatusBlock,
		FileFsVolume,
		FS_VOLUME_BUFFER_SIZE,
		FileFsVolumeInformation);

	if (!NT_SUCCESS(Status))
	{
		HcObjectClose(hFile);
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	if (lpVolumeSerialNumber)
	{
		*lpVolumeSerialNumber = FileFsVolume->VolumeSerialNumber;
	}

	if (lpVolumeNameBuffer)
	{
		HcStringCopyW(lpVolumeNameBuffer, FileFsVolume->VolumeLabel, nVolumeNameSize);
	}

	Status = HcQueryVolumeInformationFile(hFile,
		&IoStatusBlock,
		FileFsAttribute,
		FS_ATTRIBUTE_BUFFER_SIZE,
		FileFsAttributeInformation);

	HcObjectClose(hFile);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	if (lpFileSystemFlags)
	{
		*lpFileSystemFlags = FileFsAttribute->FileSystemAttribute;
	}

	if (lpMaximumComponentLength)
	{
		*lpMaximumComponentLength = FileFsAttribute->MaximumComponentNameLength;
	}

	if (lpFileSystemNameBuffer)
	{
		HcStringCopyW(lpFileSystemNameBuffer, FileFsAttribute->FileSystemName, nFileSystemNameSize);
	}
	return TRUE;
}