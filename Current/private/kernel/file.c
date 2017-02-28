#include <highcall.h>

#include "../sys/syscall.h"
#include "../../public/imports.h"

DECL_EXTERN_API(DWORD, FileRead, IN HANDLE hFile,
	IN LPVOID lpBuffer,
	IN DWORD nNumberOfBytesToRead)
{
	NTSTATUS Status;
	IO_STATUS_BLOCK Iosb;
	DWORD dwNumberOfBytesRead = 0;

	ZERO(&Iosb);

	hFile = HcObjectTranslateHandle(hFile);

	Status = HcReadFile(hFile,
		NULL,
		NULL,
		NULL,
		&Iosb,
		lpBuffer,
		nNumberOfBytesToRead,
		NULL,
		NULL);

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

DECL_EXTERN_API(DWORD, FileSetCurrent, HANDLE hFile,
	LONG lDistanceToMove,
	DWORD dwMoveMethod)
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

DECL_EXTERN_API(HANDLE, FileOpenW, LPCWSTR lpFileName, DWORD dwCreationDisposition, DWORD dwDesiredAccess)
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	UNICODE_STRING NtPathU;
	HANDLE FileHandle;
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

	/* build the object attributes */
	InitializeObjectAttributes(&ObjectAttributes,
		&NtPathU,
		0,
		NULL,
		NULL);

	ObjectAttributes.Attributes |= OBJ_CASE_INSENSITIVE;

	/* perform the call */
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
		HcErrorSetDosError(
			IoStatusBlock.Information == FILE_OPENED ?
			ERROR_ALREADY_EXISTS : ERROR_SUCCESS);
	}
	else if (dwCreationDisposition == FILE_OVERWRITE_IF)
	{
		HcErrorSetDosError(
			IoStatusBlock.Information == FILE_OVERWRITTEN 
			? ERROR_ALREADY_EXISTS : ERROR_SUCCESS);
	}
	else
	{
		HcErrorSetDosError(ERROR_SUCCESS);
	}

	return FileHandle;
}

DECL_EXTERN_API(HANDLE, FileOpenA, LPCSTR lpFileName, DWORD dwCreationDisposition, DWORD dwDesiredAccess)
{
	LPWSTR lpConverted = HcStringConvertAtoW(lpFileName);
	HANDLE hFile = HcFileOpenW(lpConverted, dwCreationDisposition, dwDesiredAccess);
	
	HcFree(lpConverted);
	return hFile;
}

DECL_EXTERN_API(BOOLEAN, FileExistsA, LPCSTR lpFilePath)
{
	LPWSTR lpConverted = HcStringConvertAtoW(lpFilePath);
	BOOLEAN bValue = HcFileExistsW(lpConverted);

	HcFree(lpConverted);
	return bValue;
}

DECL_EXTERN_API(BOOLEAN, FileExistsW, LPCWSTR lpFilePath)
{
	return HcFileOpenW(
		lpFilePath,
		OPEN_EXISTING,
		GENERIC_READ) != INVALID_HANDLE;
}

DECL_EXTERN_API(DWORD, FileSize, HANDLE hFile)
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

DECL_EXTERN_API(DWORD, FileSizeA, LPCSTR lpPath)
{
	LPWSTR lpConverted = HcStringConvertAtoW(lpPath);
	DWORD dwSize = HcFileSizeW(lpConverted);

	HcFree(lpConverted);
	return dwSize;
}

DECL_EXTERN_API(DWORD, FileSizeW, LPCWSTR lpPath)
{
	DWORD FileSize;
	HANDLE hFile;

	hFile = HcFileOpenW(lpPath, OPEN_EXISTING, GENERIC_READ);
	if (hFile == INVALID_HANDLE)
	{
		return 0;
	}

	FileSize = HcFileSize(hFile);

	/* Close handle and return */
	HcClose(hFile);
	return FileSize; 
}

DECL_EXTERN_API(ULONG, FileOffsetByExportNameA, HMODULE hModule, LPCSTR lpExportName)
{
	PIMAGE_NT_HEADERS pHeaderNT;
	LPBYTE RelativeVirtualAddress;
	LPBYTE VirtualAddress;
	LPBYTE lpModule;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	lpModule = (LPBYTE) hModule;
	pHeaderNT = HcPEGetNtHeader(hModule);

	if (!pHeaderNT)
	{
		return 0;
	}

	//
	// Get the absolute address of requested export, subtract the module's base,
	// pass to the PE handler function.
	//
	VirtualAddress = HcModuleProcedureAddressA(hModule, lpExportName);
	if (VirtualAddress)
	{
		/* Calculate the relative offset */
		RelativeVirtualAddress = (LPBYTE) (VirtualAddress - lpModule);

		return HcPEOffsetFromRVA(pHeaderNT, RelativeVirtualAddress);
	}

	return 0;
}

DECL_EXTERN_API(ULONG, FileOffsetByExportNameW, HMODULE hModule, LPCWSTR lpExportName)
{
	PIMAGE_NT_HEADERS pHeaderNT;
	LPBYTE RelativeVirtualAddress;
	LPBYTE VirtualAddress;
	LPBYTE lpModule;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	lpModule = (LPBYTE)hModule;

	pHeaderNT = HcPEGetNtHeader(hModule);
	if (!pHeaderNT)
	{
		return 0;
	}

	//
	// Get the absolute address of requested export, subtract the module's base,
	// pass to the PE handler function.
	//
	VirtualAddress = (LPBYTE)HcModuleProcedureW(hModule, lpExportName);
	if (VirtualAddress)
	{
		/* Calculate the relative offset */
		RelativeVirtualAddress = (LPBYTE) (VirtualAddress - lpModule);

		return HcPEOffsetFromRVA(pHeaderNT, RelativeVirtualAddress);
	}

	return 0;
}

DECL_EXTERN_API(ULONG, FileOffsetByVirtualAddress, LPCVOID lpAddress)
{
	PIMAGE_NT_HEADERS pHeaderNT;
	PBYTE RelativeVirtualAddress;
	PBYTE lpModule;
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

	lpModule = (PBYTE)hModule;

	pHeaderNT = HcPEGetNtHeader(hModule);
	if (!pHeaderNT)
	{
		return 0;
	}

	/* Calculate the relative offset */
	RelativeVirtualAddress = (LPBYTE)((PBYTE)lpAddress - lpModule);

	return HcPEOffsetFromRVA(pHeaderNT, RelativeVirtualAddress);
}


DECL_EXTERN_API(DWORD, FileReadModuleA, HMODULE hModule, LPCSTR lpExportName, PBYTE lpBuffer, DWORD dwCount)
{
	DWORD dwRead;
	LPWSTR lpExportConverted = HcStringConvertAtoW(lpExportName);

	dwRead = HcFileReadModuleW(hModule, lpExportConverted, lpBuffer, dwCount);

	HcFree(lpExportConverted);
	return dwRead;
}

DECL_EXTERN_API(DWORD, FileReadModuleW, HMODULE hModule, LPCWSTR lpExportName, PBYTE lpBuffer, DWORD dwCount)
{
	HANDLE hFile;
	DWORD tBytesRead;
	LPWSTR lpModulePath = HcStringAllocW(MAX_PATH);
	ULONG_PTR dwFileOffset = HcFileOffsetByExportNameW(hModule, lpExportName);

	if (!dwFileOffset || !lpModulePath)
	{
		return 0;
	}

	/* Acquire path of targetted module. */
	if (!HcProcessModuleFileName(NtCurrentProcess, hModule, lpModulePath, MAX_PATH))
	{
		return 0;
	}

	/* Open it up */
	hFile = HcFileOpenW(lpModulePath, OPEN_EXISTING, GENERIC_READ);
	if (!hFile)
	{
		HcFree(lpModulePath);
		return 0;
	}

	/* Run to the offset */
	if (!(HcFileSetCurrent(hFile, (LONG) dwFileOffset, FILE_BEGIN)))
	{
		HcFree(lpModulePath);
		HcObjectClose(hFile);
		return 0;
	}

	/* Snatch the data */
	tBytesRead = HcFileRead(hFile, lpBuffer, dwCount);
	if (tBytesRead != dwCount)
	{
		HcFree(lpModulePath);
		HcObjectClose(hFile);
		return 0;
	}

	/* Fuck off */
	HcFree(lpModulePath);
	HcObjectClose(hFile);
	return tBytesRead;
}

DECL_EXTERN_API(DWORD, FileReadAddress, LPCVOID lpBaseAddress, PBYTE lpBufferOut, DWORD dwCountToRead)
{
	DWORD dwFileOffset;
	LPWSTR lpModulePath;
	HANDLE hFile;
	DWORD tBytesRead;
	HMODULE hModule;
	MEMORY_BASIC_INFORMATION memInfo;

	ZERO(&memInfo);

	/* Find the module that allocated the address */
	if (!HcVirtualQuery(lpBaseAddress,
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

	/* Get the file offset */
	dwFileOffset = HcFileOffsetByVirtualAddress(lpBaseAddress);
	if (!dwFileOffset)
	{
		return 0;
	}

	/* Allocate for the path of the module */
	lpModulePath = HcStringAllocW(MAX_PATH);
	if (!lpModulePath)
	{
		HcErrorSetDosError(STATUS_INSUFFICIENT_RESOURCES);
		return 0;
	}

	/* Acquire path of targetted module. */
	if (!HcProcessModuleFileName(NtCurrentProcess, hModule, lpModulePath, MAX_PATH))
	{
		HcFree(lpModulePath);
		return 0;
	}

	/* Open the file */
	hFile = HcFileOpenW(lpModulePath, OPEN_EXISTING, GENERIC_READ);
	if (!hFile)
	{
		HcFree(lpModulePath);
		return 0;
	}

	/* Go to the offset */
	if (!(HcFileSetCurrent(hFile, dwFileOffset, FILE_BEGIN)))
	{
		HcFree(lpModulePath);
		HcClose(hFile);
		return 0;
	}

	/* Read it */
	tBytesRead = HcFileRead(hFile, lpBufferOut, dwCountToRead);
	if (tBytesRead != dwCountToRead)
	{
		HcFree(lpModulePath);
		HcClose(hFile);

		HcErrorSetDosError(ERROR_PARTIAL_COPY);
		return 0;
	}

	HcFree(lpModulePath);
	HcClose(hFile);
	return tBytesRead;
}

DECL_EXTERN_API(SIZE_T, FileGetCurrentDirectoryW, LPWSTR lpBuffer)
{
	PUNICODE_STRING UsCurDir;
	ULONG ULen;

	RtlAcquirePebLock();

	UsCurDir = &NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath;
	ULen = UsCurDir->Length / sizeof(WCHAR);

	if (UsCurDir->Buffer[ULen - 1] == '\\' && UsCurDir->Buffer[ULen - 2] != ':')
	{
		ULen--;
	}

	HcStringCopyW(lpBuffer, UsCurDir->Buffer, ULen);

	RtlReleasePebLock();
	return ULen * sizeof(WCHAR);
}

DECL_EXTERN_API(DWORD, FileWrite, IN HANDLE hFile,
	IN LPCVOID lpBuffer,
	IN DWORD nNumberOfBytesToWrite OPTIONAL)
{
	NTSTATUS Status;
	DWORD dwNumberOfBytesWritten = 0;
	IO_STATUS_BLOCK Iosb;

	ZERO(&Iosb);

	hFile = HcObjectTranslateHandle(hFile);

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
		Status = HcWaitForSingleObject(hFile, FALSE, NULL);
		if (NT_SUCCESS(Status))
		{
			Status = Iosb.Status;
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