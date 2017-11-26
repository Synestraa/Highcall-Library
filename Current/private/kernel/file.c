#include <highcall.h>

#include "../sys/syscall.h"
#include "../../public/imports.h"


DECL_EXTERN_API(DWORD, QueryDosDeviceW, LPCWSTR lpDeviceName, LPWSTR lpTargetPath, DWORD ucchMax)
{
	POBJECT_DIRECTORY_INFORMATION DirInfo;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING UnicodeString;
	HANDLE DirectoryHandle;
	HANDLE DeviceHandle;
	ULONG ReturnLength;
	ULONG NameLength;
	ULONG Length;
	ULONG Context;
	BOOLEAN RestartScan;
	NTSTATUS Status;
	UCHAR Buffer[512];
	PWSTR Ptr;

	/* Open the '\??' directory */
	RtlInitUnicodeString(&UnicodeString, L"\\??");
	InitializeObjectAttributes(&ObjectAttributes,
		&UnicodeString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	Status = HcOpenDirectoryObjectEx(&DirectoryHandle,
		DIRECTORY_QUERY,
		&ObjectAttributes);

	HcErrorSetNtStatus(Status);
	if (!NT_SUCCESS(Status))
	{
		return 0;
	}

	Length = 0;

	if (lpDeviceName != NULL)
	{
		/* Open the lpDeviceName link object */
		RtlInitUnicodeString(&UnicodeString, (PWSTR) lpDeviceName);
		InitializeObjectAttributes(&ObjectAttributes,
			&UnicodeString,
			OBJ_CASE_INSENSITIVE,
			DirectoryHandle,
			NULL);

		Status = HcOpenSymbolicLinkObjectEx(&DeviceHandle,
			SYMBOLIC_LINK_QUERY,
			&ObjectAttributes);

		HcErrorSetNtStatus(Status);
		if (!NT_SUCCESS(Status))
		{
			HcObjectClose(&DirectoryHandle);
			return 0;
		}

		/* Query link target */
		UnicodeString.Length = 0;
		UnicodeString.MaximumLength = (USHORT) ucchMax * sizeof(WCHAR);
		UnicodeString.Buffer = lpTargetPath;

		ReturnLength = 0;
		Status = HcQuerySymbolicLinkObjectEx(DeviceHandle,
			&UnicodeString,
			&ReturnLength);

		HcErrorSetNtStatus(Status);
		HcObjectClose(&DeviceHandle);
		HcObjectClose(&DirectoryHandle);

		if (!NT_SUCCESS(Status))
		{
			return 0;
		}

		Length = UnicodeString.Length / sizeof(WCHAR);
		if (Length < ucchMax)
		{
			/* Append null-character */
			lpTargetPath[Length] = UNICODE_NULL;
			Length++;
		}
		else
		{
			HcErrorSetNtStatus(STATUS_BUFFER_TOO_SMALL);
			return 0;
		}
	}
	else
	{
		RestartScan = TRUE;
		Context = 0;
		Ptr = lpTargetPath;
		DirInfo = (POBJECT_DIRECTORY_INFORMATION) Buffer;

		while (TRUE)
		{
			Status = HcQueryDirectoryObjectEx(DirectoryHandle,
				Buffer,
				sizeof(Buffer),
				TRUE,
				RestartScan,
				&Context,
				&ReturnLength);

			if (!NT_SUCCESS(Status))
			{
				if (Status == STATUS_NO_MORE_ENTRIES)
				{
					/* Terminate the buffer */
					*Ptr = UNICODE_NULL;
					Length++;

					Status = STATUS_SUCCESS;
				}
				else
				{
					Length = 0;
				}

				HcErrorSetNtStatus(Status);
				break;
			}

			if (HcStringEqualW(DirInfo->TypeName.Buffer, L"SymbolicLink", FALSE))
			{
				NameLength = DirInfo->Name.Length / sizeof(WCHAR);
				if (Length + NameLength + 1 >= ucchMax)
				{
					Length = 0;
					HcErrorSetNtStatus(STATUS_BUFFER_TOO_SMALL);
					break;
				}

				HcStringCopyW(Ptr, DirInfo->Name.Buffer, -1);
				Ptr += NameLength;
				Length += NameLength;
				*Ptr = UNICODE_NULL;
				Ptr++;
				Length++;
			}

			RestartScan = FALSE;
		}

		HcObjectClose(&DirectoryHandle);
	}

	return Length;
}

DECL_EXTERN_API(NTSTATUS, QueryDirectoryObjectEx, IN HANDLE DirectoryHandle,
	OUT PVOID Buffer,
	IN ULONG BufferLength,
	IN BOOLEAN ReturnSingleEntry,
	IN BOOLEAN RestartScan,
	IN OUT PULONG Context,
	OUT PULONG ReturnLength OPTIONAL)
{
	if (HcGlobal.IsWow64)
	{
		OBJECT_DIRECTORY_INFORMATION_WOW64 DirInfo;
		ZERO(&DirInfo);

		ConvertObjectDirectoryInformationWow64(&DirInfo, (POBJECT_DIRECTORY_INFORMATION) Buffer);
		NTSTATUS Status = HcQueryDirectoryObjectWow64((ULONG64) DirectoryHandle,
			(ULONG64) &DirInfo, 
			BufferLength, 
			ReturnSingleEntry, 
			RestartScan, 
			(ULONG64) Context, 
			(ULONG64) ReturnLength);

		if (NT_SUCCESS(Status))
		{
			ConvertObjectDirectoryInformationFromWow64(&DirInfo, (POBJECT_DIRECTORY_INFORMATION) Buffer);
		}

		return Status;
	}

	return HcQueryDirectoryObject(DirectoryHandle, Buffer, BufferLength, ReturnSingleEntry, RestartScan, Context, ReturnLength);
}

DECL_EXTERN_API(NTSTATUS, OpenSymbolicLinkObjectEx, OUT PHANDLE LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	if (HcGlobal.IsWow64)
	{
		PTR_64(HANDLE) LinkHandle64 = 0;

		OBJECT_ATTRIBUTES_WOW64 ObjectAttributes64;
		ZERO(&ObjectAttributes64);
		ConvertObjectAttributesWow64(&ObjectAttributes64, ObjectAttributes);

		NTSTATUS Status = HcOpenSymbolicLinkObjectWow64((ULONG64) &LinkHandle64, DesiredAccess, (ULONG64) &ObjectAttributes64);
		if (NT_SUCCESS(Status))
		{
			*LinkHandle = POINTER32_HARDCODED(HANDLE) LinkHandle64;
		}

		return Status;
	}

	return HcOpenSymbolicLinkObject(LinkHandle, DesiredAccess, ObjectAttributes);
}

DECL_EXTERN_API(NTSTATUS, QuerySymbolicLinkObjectEx, IN HANDLE LinkHandle,
	OUT PUNICODE_STRING LinkTarget,
	OUT PULONG ResultLength OPTIONAL)
{
	if (HcGlobal.IsWow64)
	{
		UNICODE_STRING64 LinkTarget64;
		ConvertStringWow64(&LinkTarget64, LinkTarget);

		NTSTATUS Status = HcQuerySymbolicLinkObjectWow64((ULONG64) LinkHandle, (ULONG64) &LinkTarget64, (ULONG64) ResultLength);
		if (NT_SUCCESS(Status))
		{
			ConvertUnicodeStringFromWow64(&LinkTarget64, LinkTarget);
		}

		return Status;
	}

	return HcQuerySymbolicLinkObject(LinkHandle, LinkTarget, ResultLength);
}

DECL_EXTERN_API(NTSTATUS, OpenDirectoryObjectEx, OUT PHANDLE DirectoryHandle, IN ACCESS_MASK AccessMask, IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	if (HcGlobal.IsWow64)
	{
		PTR_64(HANDLE) DirectoryHandle64 = 0;
		
		OBJECT_ATTRIBUTES_WOW64 ObjectAttributes64;
		ZERO(&ObjectAttributes64);

		ConvertObjectAttributesWow64(&ObjectAttributes64, ObjectAttributes);

		NTSTATUS Status = HcOpenDirectoryObjectWow64((ULONG64) &DirectoryHandle64, AccessMask, (ULONG64) &ObjectAttributes64);
		if (NT_SUCCESS(Status))
		{
			*DirectoryHandle = POINTER32_HARDCODED(HANDLE) DirectoryHandle64;
		}

		HcErrorSetNtStatus(Status);
		return Status;
	}

	return HcOpenDirectoryObject(DirectoryHandle, AccessMask, ObjectAttributes);
}

DECL_EXTERN_API(DWORD, FileRead, CONST IN HANDLE hFile, IN OUT LPVOID lpBuffer, CONST IN DWORD nNumberOfBytesToRead)
{
	NTSTATUS Status;
	IO_STATUS_BLOCK Iosb;
	DWORD dwNumberOfBytesRead = 0;

	ZERO(&Iosb);

	if (HcGlobal.IsWow64)
	{
		IO_STATUS_BLOCK_WOW64 Iosb64;
		ZERO(&Iosb64);

		Status = HcReadFileWow64((ULONG64) hFile, 
			0,
			0,
			0, 
			(ULONG64) &Iosb64,
			(ULONG64) lpBuffer, 
			nNumberOfBytesToRead,
			0, 
			0);

		Iosb.Information = (DWORD) Iosb64.Information;
		Iosb.Status = Iosb64.Status;
	}
	else
	{
		Status = HcReadFile(hFile,
			NULL,
			NULL,
			NULL,
			&Iosb,
			lpBuffer,
			nNumberOfBytesToRead,
			NULL,
			NULL);
	}

	HcErrorSetNtStatus(Status);

	/* Wait in case operation is pending */
	if (Status == STATUS_PENDING)
	{
		if (HcObjectWait(hFile, INFINITE))
		{
			Status = Iosb.Status;
		}
	}

	if (Status == STATUS_END_OF_FILE)
	{
		/*
		* lpNumberOfBytesRead must not be NULL here, in fact Win doesn't
		* check that case either and crashes (only after the operation
		* completed).
		*/
		return 0;
	}

	if (NT_SUCCESS(Status))
	{
		/*
		* lpNumberOfBytesRead must not be NULL here, in fact Win doesn't
		* check that case either and crashes (only after the operation
		* completed).
		*/
		dwNumberOfBytesRead = (DWORD) Iosb.Information;
	}

	return dwNumberOfBytesRead;
}

DECL_EXTERN_API(DWORD, FileSetCurrent, CONST IN HANDLE hFile, CONST IN LONG lDistanceToMove, CONST IN DWORD dwMoveMethod)
{
	FILE_POSITION_INFORMATION FilePosition;
	FILE_STANDARD_INFORMATION FileStandard;
	NTSTATUS errCode;
	IO_STATUS_BLOCK IoStatusBlock;
	LARGE_INTEGER Distance;

	ZERO(&FilePosition);
	ZERO(&FileStandard);
	ZERO(&IoStatusBlock);

	Distance.QuadPart = lDistanceToMove;

	switch (dwMoveMethod)
	{
	case FILE_CURRENT:
		errCode = HcQueryInformationFile(hFile,
			&IoStatusBlock,
			&FilePosition,
			sizeof(FILE_POSITION_INFORMATION),
			FilePositionInformation);

		FilePosition.CurrentByteOffset.QuadPart += Distance.QuadPart;
		if (!NT_SUCCESS(errCode))
		{
			HcErrorSetNtStatus(errCode);

			// @defineme
			return 0 /* INVALID_SET_FILE_POINTER */;
		}
		break;

	case FILE_END:
		errCode = HcQueryInformationFile(hFile,
			&IoStatusBlock,
			&FileStandard,
			sizeof(FILE_STANDARD_INFORMATION),
			FileStandardInformation);

		FilePosition.CurrentByteOffset.QuadPart =
			FileStandard.EndOfFile.QuadPart + Distance.QuadPart;

		if (!NT_SUCCESS(errCode))
		{
			HcErrorSetNtStatus(errCode);

			// @defineme
			return 0 /* INVALID_SET_FILE_POINTER */;
		}
		break;

	case FILE_BEGIN:
		FilePosition.CurrentByteOffset.QuadPart = Distance.QuadPart;
		break;

	default:
		HcErrorSetDosError(ERROR_INVALID_PARAMETER);

		// @defineme
		return 0/* INVALID_SET_FILE_POINTER */;
	}

	if (FilePosition.CurrentByteOffset.QuadPart < 0)
	{
		HcErrorSetDosError(ERROR_NEGATIVE_SEEK);
		
		// @defineme
		return 0 /* INVALID_SET_FILE_POINTER */;
	}

	errCode = HcSetInformationFile(hFile,
		&IoStatusBlock,
		&FilePosition,
		sizeof(FILE_POSITION_INFORMATION),
		FilePositionInformation);

	if (!NT_SUCCESS(errCode))
	{
		// @defineme
		return 0/* INVALID_SET_FILE_POINTER */;
	}

	if (FilePosition.CurrentByteOffset.u.LowPart == MAXDWORD)
	{
		/* The value of -1 is valid here, especially when the new
		file position is greater than 4 GB. Since NtSetInformationFile
		succeeded we never set an error code and we explicitly need
		to clear a previously set error code in this case, which
		an application will check if INVALID_SET_FILE_POINTER is returned! */
		HcErrorSetDosError(ERROR_SUCCESS);
	}

	return FilePosition.CurrentByteOffset.u.LowPart;
}

#include <stdio.h>
#include <windows.h>

DECL_EXTERN_API(HANDLE, FileOpenW, IN LPCWSTR lpFileName, IN DWORD dwCreationDisposition, IN DWORD dwDesiredAccess)
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	IO_STATUS_BLOCK_WOW64 IoStatusBlock64;
	UNICODE_STRING NtPathU;
	HANDLE FileHandle = NULL;
	NTSTATUS Status;
	ULONG FileAttributes = FILE_ATTRIBUTE_NORMAL & (FILE_ATTRIBUTE_VALID_FLAGS & ~FILE_ATTRIBUTE_DIRECTORY);
	ULONG Flags = FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE;
	PVOID EaBuffer = NULL;
	DWORD EaLength = 0;

	if (HcStringIsNullOrEmpty(lpFileName))
	{
		HcErrorSetDosError(ERROR_PATH_NOT_FOUND);
		return INVALID_HANDLE;
	}

	ZERO(&IoStatusBlock64);
	ZERO(&IoStatusBlock);

	/* validate & translate the creation disposition */
	switch (dwCreationDisposition)
	{
	case CREATE_NEW:
		dwCreationDisposition = FILE_CREATE;
		break;

	case CREATE_ALWAYS:
		dwCreationDisposition = FILE_OVERWRITE_IF;
		break;

	case OPEN_EXISTING:
		dwCreationDisposition = FILE_OPEN;
		break;

	case OPEN_ALWAYS:
		dwCreationDisposition = FILE_OPEN_IF;
		break;

	case TRUNCATE_EXISTING:
		dwCreationDisposition = FILE_OVERWRITE;
		break;

	default:
		HcErrorSetDosError(ERROR_INVALID_PARAMETER);
		return INVALID_HANDLE;
	}

	dwDesiredAccess |= SYNCHRONIZE | FILE_READ_ATTRIBUTES;

	/* validate & translate the filename */
	if (!RtlDosPathNameToNtPathName_U(lpFileName,
		&NtPathU,
		NULL,
		NULL))
	{
		HcErrorSetDosError(ERROR_FILE_NOT_FOUND);
		return INVALID_HANDLE;
	}

	if (HcGlobal.IsWow64)
	{
		PTR_64(HANDLE) FileHandle64 = 0;

		OBJECT_ATTRIBUTES_WOW64 ObjectAttributes64;
		UNICODE_STRING64 NtPathU64;

		ZERO(&ObjectAttributes64);
		ZERO(&NtPathU64);

		NtPathU64.Buffer = WOW64_CONVERT(LPWSTR) NtPathU.Buffer;
		NtPathU64.Length = NtPathU.Length;
		NtPathU64.MaximumLength = NtPathU.MaximumLength;

		InitializeObjectAttributesWow64(&ObjectAttributes64,
			&NtPathU64,
			0,
			0,
			NULL);

		Status = HcCreateFileWow64(
			(ULONG64) &FileHandle64,
			dwDesiredAccess,
			(ULONG64) &ObjectAttributes64,
			(ULONG64) &IoStatusBlock64,
			0,
			FileAttributes,
			FILE_SHARE_WRITE | FILE_SHARE_READ,
			dwCreationDisposition,
			Flags,
			0,
			0);

		if (NT_SUCCESS(Status))
		{
			FileHandle = (HANDLE) FileHandle64;
		}
	}
	else
	{
		InitializeObjectAttributes(&ObjectAttributes,
			&NtPathU,
			0,
			NULL,
			NULL);

		ObjectAttributes.Attributes |= OBJ_CASE_INSENSITIVE;

		Status = HcCreateFile(&FileHandle,
			dwDesiredAccess,
			&ObjectAttributes,
			&IoStatusBlock,
			NULL,
			FileAttributes,
			FILE_SHARE_WRITE | FILE_SHARE_READ,
			dwCreationDisposition,
			Flags,
			EaBuffer,
			EaLength);
	}

	/* Don't free with HcFree due to RtlDosPathNameToNtPathName_U allocation type. */
	RtlFreeHeap(RtlGetProcessHeap(), 0, NtPathU.Buffer);

	/* error */
	if (!NT_SUCCESS(Status))
	{
		/* In the case file creation was rejected due to CREATE_NEW flag
		* was specified and file with that name already exists, correct
		* last error is ERROR_FILE_EXISTS and not ERROR_ALREADY_EXISTS.
		* Note: RtlNtStatusToDosError is not the subject to blame here.
		*/
		if (Status == STATUS_OBJECT_NAME_COLLISION &&
			dwCreationDisposition == FILE_CREATE)
		{
			HcErrorSetDosError(ERROR_FILE_EXISTS);
		}
		else
		{
			HcErrorSetNtStatus(Status);
		}

		return INVALID_HANDLE;
	}

	/*
	create with OPEN_ALWAYS (FILE_OPEN_IF) returns info = FILE_OPENED or FILE_CREATED
	create with CREATE_ALWAYS (FILE_OVERWRITE_IF) returns info = FILE_OVERWRITTEN or FILE_CREATED
	*/
	if (dwCreationDisposition == FILE_OPEN_IF)
	{
		if (HcGlobal.IsWow64)
		{
			HcErrorSetDosError(
				IoStatusBlock64.Information == FILE_OPENED ?
				ERROR_ALREADY_EXISTS : ERROR_SUCCESS);
		}
		else
		{
			HcErrorSetDosError(
				IoStatusBlock.Information == FILE_OPENED ?
				ERROR_ALREADY_EXISTS : ERROR_SUCCESS);
		}
	}
	else if (dwCreationDisposition == FILE_OVERWRITE_IF)
	{
		if (HcGlobal.IsWow64)
		{
			HcErrorSetDosError(
				IoStatusBlock64.Information == FILE_OVERWRITTEN
				? ERROR_ALREADY_EXISTS : ERROR_SUCCESS);
		}
		else
		{
			HcErrorSetDosError(
				IoStatusBlock.Information == FILE_OVERWRITTEN
				? ERROR_ALREADY_EXISTS : ERROR_SUCCESS);
		}
	}
	else
	{
		HcErrorSetDosError(ERROR_SUCCESS);
	}

	return FileHandle;
}

DECL_EXTERN_API(HANDLE, FileOpenA, IN LPCSTR lpFileName, IN DWORD dwCreationDisposition, IN DWORD dwDesiredAccess)
{
	LPWSTR lpConverted;
	HANDLE hFile = NULL;
	
	lpConverted = HcStringConvertAtoW(lpFileName);
	if (lpConverted)
	{
		hFile = HcFileOpenW(lpConverted, dwCreationDisposition, dwDesiredAccess);
		HcFree(lpConverted);
	}

	return hFile;
}

DECL_EXTERN_API(BOOLEAN, FileExistsA, IN LPCSTR lpFilePath)
{
	BOOLEAN bReturn = FALSE;
	LPWSTR lpConverted;

	lpConverted = HcStringConvertAtoW(lpFilePath);
	if (lpConverted)
	{
		bReturn = HcFileExistsW(lpConverted);
		HcFree(lpConverted);
	}

	return bReturn;
}

DECL_EXTERN_API(BOOLEAN, FileExistsW, IN LPCWSTR lpFilePath)
{
	BOOLEAN bReturn = FALSE;
	HANDLE hFile;

	hFile = HcFileOpenW(lpFilePath, OPEN_EXISTING, GENERIC_READ);
	if (hFile != INVALID_HANDLE)
	{
		bReturn = TRUE;
		HcObjectClose(&hFile);
	}

	return bReturn;
}

DECL_EXTERN_API(DWORD, FileSize, CONST IN HANDLE hFile)
{
	NTSTATUS Status;
	IO_STATUS_BLOCK IoStatusBlock;
	FILE_STANDARD_INFORMATION FileStandard;

	ZERO(&IoStatusBlock);
	ZERO(&FileStandard);

	Status = HcQueryInformationFile(hFile,
		&IoStatusBlock,
		&FileStandard,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return 0;
	}

	return FileStandard.EndOfFile.u.LowPart;
}

DECL_EXTERN_API(DWORD, FileSizeA, IN LPCSTR lpPath)
{
	DWORD dwSize = 0;
	LPWSTR lpConverted; 
	
	lpConverted = HcStringConvertAtoW(lpPath);
	if (lpConverted)
	{
		dwSize = HcFileSizeW(lpConverted);
		HcFree(lpConverted);
	}

	return dwSize;
}

DECL_EXTERN_API(DWORD, FileSizeW, IN LPCWSTR lpPath)
{
	DWORD FileSize;
	HANDLE hFile;

	hFile = HcFileOpenW(lpPath, OPEN_EXISTING, GENERIC_READ);
	if (hFile == INVALID_HANDLE)
	{
		return 0;
	}

	FileSize = HcFileSize(hFile);

	HcObjectClose(&hFile);
	return FileSize; 
}

DECL_EXTERN_API(ULONG, FileOffsetByExportNameA, IN HMODULE hModule OPTIONAL, IN LPCSTR lpExportName)
{
	PIMAGE_NT_HEADERS pHeaderNT;
	LPBYTE VirtualAddress;

	if (!hModule)
	{
		hModule = NtCurrentPeb()->ImageBaseAddress;
	}

	pHeaderNT = HcImageGetNtHeader(hModule);
	if (!pHeaderNT)
	{
		return 0;
	}

	VirtualAddress = HcModuleProcedureA(hModule, lpExportName);
	if (VirtualAddress)
	{
		return HcImageOffsetFromRVA(pHeaderNT, HcImageVaToRva(hModule, VirtualAddress));
	}

	return 0;
}

DECL_EXTERN_API(ULONG, FileOffsetByExportNameW, IN HMODULE hModule OPTIONAL, IN LPCWSTR lpExportName)
{
	PIMAGE_NT_HEADERS pHeaderNT;
	LPBYTE VirtualAddress;

	if (!hModule)
	{
		hModule = NtCurrentPeb()->ImageBaseAddress;
	}

	pHeaderNT = HcImageGetNtHeader(hModule);
	if (!pHeaderNT)
	{
		return 0;
	}

	VirtualAddress = (LPBYTE)HcModuleProcedureW(hModule, lpExportName);
	if (VirtualAddress)
	{
		return HcImageOffsetFromRVA(pHeaderNT, HcImageVaToRva(hModule, VirtualAddress));
	}

	return 0;
}

DECL_EXTERN_API(ULONG, FileOffsetByVirtualAddress, IN LPCVOID lpAddress)
{
	PIMAGE_NT_HEADERS pHeaderNT;
	MEMORY_BASIC_INFORMATION memInfo;
	HMODULE hModule;

	ZERO(&memInfo);

	/* Find the module that allocated the address */
	if (!HcVirtualQuery(lpAddress,
		&memInfo,
		sizeof(memInfo)))
	{
		return 0;
	}

	/* Take the module */
	hModule = (HMODULE)memInfo.AllocationBase;
	if (!hModule)
	{
		return 0;
	}

	pHeaderNT = HcImageGetNtHeader(hModule);
	if (!pHeaderNT)
	{
		return 0;
	}

	return HcImageOffsetFromRVA(pHeaderNT, HcImageVaToRva(hModule, lpAddress));
}


DECL_EXTERN_API(DWORD, FileReadModuleA, CONST IN HMODULE hModule, IN LPCSTR lpExportName, IN OUT PBYTE lpBuffer, CONST IN DWORD dwCount)
{
	DWORD dwRead = 0;
	LPWSTR lpExportConverted;

	lpExportConverted = HcStringConvertAtoW(lpExportName);
	if (lpExportConverted)
	{
		dwRead = HcFileReadModuleW(hModule, lpExportConverted, lpBuffer, dwCount);
		HcFree(lpExportConverted);
	}

	return dwRead;
}

DECL_EXTERN_API(DWORD, FileReadModuleW, CONST IN HMODULE hModule, IN LPCWSTR lpExportName, IN OUT PBYTE lpBuffer, CONST IN DWORD dwCount)
{
	HANDLE hFile = INVALID_HANDLE;
	DWORD tBytesRead = 0;
	LPWSTR lpModulePath = NULL;
	ULONG_PTR dwFileOffset;

	dwFileOffset = HcFileOffsetByExportNameW(hModule, lpExportName);
	if (!dwFileOffset)
	{
		goto done;
	}

	lpModulePath = HcStringAllocW(MAX_PATH);
	if (!lpModulePath)
	{
		goto done;
	}

	/* Acquire path of targetted module. */
	if (!HcModulePathAdvancedW(hModule, lpModulePath))
	{
		goto done;
	}

	/* Open it up */
	hFile = HcFileOpenW(lpModulePath, OPEN_EXISTING, GENERIC_READ);
	if (!hFile)
	{
		goto done;
	}

	/* Run to the offset */
	if (!HcFileSetCurrent(hFile, (LONG) dwFileOffset, FILE_BEGIN))
	{
		goto done;
	}

	/* Snatch the data */
	tBytesRead = HcFileRead(hFile, lpBuffer, dwCount);

done:
	if (lpModulePath)
	{
		HcFree(lpModulePath);
	}

	if (hFile == INVALID_HANDLE)
	{
		HcObjectClose(&hFile);
	}

	return tBytesRead;
}

DECL_EXTERN_API(DWORD, FileReadAddress, IN LPCVOID lpBaseAddress, OUT PBYTE lpBufferOut, CONST IN DWORD dwCountToRead)
{
	DWORD dwFileOffset;
	LPWSTR lpModulePath = NULL;
	HANDLE hFile = INVALID_HANDLE;
	DWORD tBytesRead = 0;
	HMODULE hModule;
	MEMORY_BASIC_INFORMATION memInfo;

	ZERO(&memInfo);

	/* Find the module that allocated the address */
	if (!HcVirtualQuery(lpBaseAddress,
		&memInfo,
		sizeof(memInfo)))
	{
		goto done;
	}

	/* Take the module */
	hModule = (HMODULE)memInfo.AllocationBase;
	if (!hModule)
	{
		goto done;
	}

	/* Get the file offset */
	dwFileOffset = HcFileOffsetByVirtualAddress(lpBaseAddress);
	if (!dwFileOffset)
	{
		goto done;
	}

	/* Allocate for the path of the module */
	lpModulePath = HcStringAllocW(MAX_PATH);
	if (!lpModulePath)
	{
		HcErrorSetDosError(STATUS_INSUFFICIENT_RESOURCES);
		goto done;
	}

	/* Acquire path of targetted module. */
	if (!HcModulePathAdvancedW(hModule, lpModulePath))
	{
		goto done;
	}

	/* Open the file */
	hFile = HcFileOpenW(lpModulePath, OPEN_EXISTING, GENERIC_READ);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		goto done;
	}

	/* Go to the offset */
	if (!HcFileSetCurrent(hFile, dwFileOffset, FILE_BEGIN))
	{
		goto done;
	}

	/* Read it */
	tBytesRead = HcFileRead(hFile, lpBufferOut, dwCountToRead);
	if (tBytesRead != dwCountToRead)
	{
		HcErrorSetDosError(ERROR_PARTIAL_COPY);
	}

done:
	if (lpModulePath)
	{
		HcFree(lpModulePath);
	}

	if (hFile == INVALID_HANDLE)
	{
		HcObjectClose(&hFile);
	}

	return tBytesRead;
}


DECL_EXTERN_API(DWORD, FileCurrentDirectoryA, IN LPSTR lpBuffer)
{
	DWORD Length = 0;
	LPWSTR lpTemp;

	lpTemp = HcStringAllocW(MAX_PATH);
	if (lpTemp)
	{
		Length = HcFileCurrentDirectoryW(lpTemp);
		if (Length)
		{
			if (HcStringCopyConvertWtoA(lpTemp, lpBuffer, Length))
			{
				return Length;
			}

			Length = 0;
		}

		HcFree(lpTemp);
	}

	return Length;
}

DECL_EXTERN_API(DWORD, FileCurrentDirectoryW, IN LPWSTR lpBuffer)
{
	PUNICODE_STRING UsCurDir;
	ULONG ULen;

	RtlAcquirePebLock();

	UsCurDir = &NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath;
	ULen = UsCurDir->Length / sizeof(WCHAR);

	if (UsCurDir->Buffer[ULen - 1] == L'\\' && UsCurDir->Buffer[ULen - 2] != L':')
	{
		ULen--;
	}

	HcStringCopyW(lpBuffer, UsCurDir->Buffer, ULen);

	RtlReleasePebLock();
	return ULen;
}

DECL_EXTERN_API(DWORD, FileWrite, CONST IN HANDLE hFile, IN LPCVOID lpBuffer, IN DWORD nNumberOfBytesToWrite)
{
	NTSTATUS Status;
	DWORD dwNumberOfBytesWritten = 0;
	IO_STATUS_BLOCK Iosb;

	ZERO(&Iosb);

	Status = HcWriteFile(hFile,
		NULL,
		NULL,
		NULL,
		&Iosb,
		(PVOID)lpBuffer,
		nNumberOfBytesToWrite,
		NULL,
		NULL);

	/* Wait in case operation is pending */
	if (Status == STATUS_PENDING)
	{
		if (HcObjectWait(hFile, INFINITE))
		{
			Status = Iosb.Status;
		}
		else
		{
			Status = HcErrorGetLastStatus();
		}
	}

	if (NT_SUCCESS(Status))
	{
		/*
		* lpNumberOfBytesWritten must not be NULL here, in fact Win doesn't
		* check that case either and crashes (only after the operation
		* completed).
		*/
		dwNumberOfBytesWritten = (DWORD) Iosb.Information;
	}
	else
	{
		HcErrorSetNtStatus(Status);
		return 0;
	}

	return dwNumberOfBytesWritten;
}

DECL_EXTERN_API(BOOLEAN, FileFlush, IN HANDLE hFile)
{
	NTSTATUS Status;
	IO_STATUS_BLOCK IoStatusBlock;

	Status = HcFlushBuffersFile(hFile,
		&IoStatusBlock);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}
	return TRUE;
}