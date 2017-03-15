#include <highcall.h>

#include "../sys/syscall.h"
#include "../../public/imports.h"

DECL_EXTERN_API(DWORD, FileRead, CONST IN HANDLE hFile, IN OUT LPVOID lpBuffer, CONST IN DWORD nNumberOfBytesToRead)
{
	NTSTATUS Status;
	IO_STATUS_BLOCK Iosb;
	DWORD dwNumberOfBytesRead = 0;

	ZERO(&Iosb);

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

DECL_EXTERN_API(HANDLE, FileOpenW, IN LPCWSTR lpFileName, IN DWORD dwCreationDisposition, IN DWORD dwDesiredAccess)
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

	HcClose(hFile);
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
	if (!HcModulePathW(hModule, lpModulePath))
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
	if (!HcModulePathW(hModule, lpModulePath))
	{
		goto done;
	}

	/* Open the file */
	hFile = HcFileOpenW(lpModulePath, OPEN_EXISTING, GENERIC_READ);
	if (!hFile)
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