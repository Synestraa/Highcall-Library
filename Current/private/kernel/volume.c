#include <highcall.h>

#include "../sys/syscall.h"
#include "../../public/imports.h"

DECL_EXTERN_API(DWORD, VolumeLogicalDrives)
{
	NTSTATUS Status;
	PROCESS_DEVICEMAP_INFORMATION ProcessDeviceMapInfo;

	/* Get the Device Map for this Process */
	Status = HcQueryInformationProcessEx(NtCurrentProcess(),
		ProcessDeviceMap,
		&ProcessDeviceMapInfo,
		sizeof(ProcessDeviceMapInfo),
		NULL);

	HcErrorSetNtStatus(Status);

	/* Return the Drive Map */
	if (!NT_SUCCESS(Status))
	{
		return 0;
	}

	return ProcessDeviceMapInfo.Query.DriveMap;
}

DECL_EXTERN_API(DWORD, VolumeLogicalDriveStringsW, IN DWORD nBufferLength, IN LPWSTR lpBuffer)
{
	DWORD drive, count;
	DWORD dwDriveMap;
	LPWSTR p;

	dwDriveMap = HcVolumeLogicalDrives();

	for (drive = count = 0; drive < MAX_DOS_DRIVES; drive++)
	{
		if (dwDriveMap & (1 << drive))
			count++;
	}

	if ((count * 4) + 1 > nBufferLength) return ((count * 4) + 1);

	p = lpBuffer;
	for (drive = 0; drive < MAX_DOS_DRIVES; drive++)
		if (dwDriveMap & (1 << drive))
		{
			*p++ = (WCHAR) ('A' + drive);
			*p++ = (WCHAR)':';
			*p++ = (WCHAR)'\\';
			*p++ = (WCHAR)'\0';
		}
	*p = (WCHAR)'\0';

	return (count * 4);
}

DECL_EXTERN_API(BOOLEAN, VolumePathFromNtPath, IN LPCWSTR szNtPath, OUT LPWSTR DosPath)
{
	if (HcStringContainsW(szNtPath, L"\\Device\\LanmanRedirector\\", FALSE)) // Win XP
	{
		HcStringAppendW(&DosPath, L"\\\\", -1);
		HcStringAppendW(&DosPath, (szNtPath + 25), -1);
		return TRUE;
	}

	if (HcStringContainsW(szNtPath, L"\\Device\\Mup\\", FALSE)) // Win 7
	{
		HcStringAppendW(&DosPath, L"\\\\", -1);
		HcStringAppendW(&DosPath, (szNtPath + 12), -1);
		return TRUE;
	}


	WCHAR u16_Drives[300];
	if (!HcVolumeLogicalDriveStringsW(sizeof(u16_Drives), u16_Drives))
		return FALSE;

	WCHAR* u16_Drv = u16_Drives;
	while (u16_Drv[0])
	{
		WCHAR* u16_Next = u16_Drv + HcStringLenW(u16_Drv) + 1;
		u16_Drv[2] = 0; 

		WCHAR u16_NtVolume[1000];
		u16_NtVolume[0] = 0;

		if (!HcQueryDosDeviceW(u16_Drv, u16_NtVolume, sizeof(u16_NtVolume) / 2))
			return FALSE;

		DWORD s32_Len = HcStringLenW(u16_NtVolume);
		if (s32_Len > 0 && HcStringContainsW(szNtPath, u16_NtVolume, FALSE))
		{
			HcStringAppendW(&DosPath, u16_Drv, -1);
			HcStringAppendW(&DosPath, (szNtPath + s32_Len), -1);
			return TRUE;
		}

		u16_Drv = u16_Next;
	}
	
	HcErrorSetNtStatus(ERROR_BAD_PATHNAME);
	return FALSE;
}

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