#include <highcall.h>

#include "syscall.h"
#include "../../public/imports.h"

#define NT_SYMBOL "Nt"
#define SYSINDEX_ASSERT(x) \
{ \
	if (HcStringCompareContentA(lpCurrentFunction, NT_SYMBOL #x)) \
	{\
		sci##x = dwIndex;\
		continue;\
	} \
}

#pragma region System Call Indicies
SYS_INDEX 
sciQueryInformationToken = SYSI_INVALID,
sciOpenProcessToken = SYSI_INVALID,
sciResumeProcess = SYSI_INVALID,
sciSuspendProcess = SYSI_INVALID,
sciAllocateVirtualMemory = SYSI_INVALID,
sciFreeVirtualMemory = SYSI_INVALID,
sciResumeThread = SYSI_INVALID,
sciQueryInformationThread = SYSI_INVALID,
sciCreateThread = SYSI_INVALID,
sciFlushInstructionCache = SYSI_INVALID,
sciOpenProcess = SYSI_INVALID,
sciProtectVirtualMemory = SYSI_INVALID,
sciReadVirtualMemory = SYSI_INVALID,
sciWriteVirtualMemory = SYSI_INVALID,
sciQueryInformationProcess = SYSI_INVALID,
sciQuerySystemInformation = SYSI_INVALID,
sciClose = SYSI_INVALID,
sciQueryVirtualMemory = SYSI_INVALID,
sciAdjustPrivilegesToken = SYSI_INVALID,
sciSetInformationThread = SYSI_INVALID,
sciOpenDirectoryObject = SYSI_INVALID,
sciCreateThreadEx = SYSI_INVALID,
sciWaitForSingleObject = SYSI_INVALID,
sciWaitForMultipleObjects = SYSI_INVALID,
sciLockVirtualMemory = SYSI_INVALID,
sciUnlockVirtualMemory = SYSI_INVALID,
sciCreateFile = SYSI_INVALID,
sciQueryInformationFile = SYSI_INVALID,
sciQueryVolumeInformationFile = SYSI_INVALID,
sciQueryObject = SYSI_INVALID,
sciDelayExecution = SYSI_INVALID,
sciWriteFile = SYSI_INVALID,
sciTerminateProcess = SYSI_INVALID,
sciDeviceIoControlFile,
sciCreateEvent = SYSI_INVALID,
sciSetInformationFile = SYSI_INVALID,
sciReadFile = SYSI_INVALID,
sciDuplicateObject = SYSI_INVALID;
#pragma endregion

static
BOOLEAN
HCAPI
IsSyscall(LPBYTE lpAddress)
{
#ifdef _WIN64
	return *lpAddress == 0x4c && *(lpAddress + 3) == 0xb8;
#else
	return *lpAddress == 0xb8;
#endif
}

static
SYS_INDEX
ExtractSyscallIndex(LPBYTE lpByte)
{
#ifndef _WIN64
	/* mov eax, syscallindex */
	/* buffer + 1 is the syscall index, 0xB8 is the mov instruction */
	return *(ULONG*)(lpByte + 1);
#else
	/* mov r10, rcx */
	/* mov eax, syscall index */
	return *(ULONG*)(lpByte + 4);
#endif
}

//
// The purpose of this function is to update system call indicies based on a buffer received from reading ntdll.dll.
//
// lpModule is required to be the base of ntdll.dll!
//
static BOOLEAN update_syscall_list(PBYTE lpBuffer, PBYTE lpModule)
{
	PIMAGE_EXPORT_DIRECTORY pExports;
	PDWORD pExportNames;
	PDWORD pExportFunctions;
	PWORD pExportOrdinals;
	LPSTR lpCurrentFunction;
	PIMAGE_NT_HEADERS pHeaderNT;
	DWORD dwFileOffset = 0;
	LPBYTE VirtualAddress = 0;
	LPBYTE RelativeVirtualAddress = 0;

	pHeaderNT = HcPEGetNtHeader((HMODULE)lpModule);
	if (!pHeaderNT)
	{
		return FALSE;
	}

	pExports = HcPEGetExportDirectory(HcGlobal.HandleNtdll);
	if (!pExports)
	{
		return FALSE;
	}

	/* Get the address containg null terminated export names, in ASCII */
	pExportNames = (PDWORD)(pExports->AddressOfNames + lpModule);
	pExportOrdinals = (PWORD)(pExports->AddressOfNameOrdinals + lpModule);
	pExportFunctions = (PDWORD)(pExports->AddressOfFunctions + lpModule);

	/* List through functions */
	for (unsigned int i = 0; i < pExports->NumberOfFunctions; i++)
	{
		lpCurrentFunction = (LPSTR)(pExportNames[i] + lpModule);
		if (!lpCurrentFunction)
		{
			continue;
		}

		VirtualAddress = pExportFunctions[pExportOrdinals[i]] + lpModule;
		if (VirtualAddress)
		{
			/* Calculate the relative offset */
			RelativeVirtualAddress = (LPBYTE)(VirtualAddress - lpModule);

			dwFileOffset = HcPEOffsetFromRVA(pHeaderNT, RelativeVirtualAddress);

			PBYTE lpbFn = lpBuffer + dwFileOffset;
			if (!IsSyscall(lpbFn))
			{
				continue;
			}

			DWORD dwIndex = ExtractSyscallIndex(lpbFn);

			/* Syscall identification begin */

			SYSINDEX_ASSERT(QueryInformationToken);
			SYSINDEX_ASSERT(OpenProcessToken);
			SYSINDEX_ASSERT(ResumeProcess);
			SYSINDEX_ASSERT(SuspendProcess);
			SYSINDEX_ASSERT(AllocateVirtualMemory);
			SYSINDEX_ASSERT(FreeVirtualMemory);
			SYSINDEX_ASSERT(ResumeThread);
			SYSINDEX_ASSERT(QueryInformationThread);
			SYSINDEX_ASSERT(CreateThread);
			SYSINDEX_ASSERT(FlushInstructionCache);
			SYSINDEX_ASSERT(OpenProcess);
			SYSINDEX_ASSERT(ProtectVirtualMemory);
			SYSINDEX_ASSERT(ReadVirtualMemory);
			SYSINDEX_ASSERT(WriteVirtualMemory);
			SYSINDEX_ASSERT(QueryInformationProcess);
			SYSINDEX_ASSERT(QuerySystemInformation);
			SYSINDEX_ASSERT(Close);
			SYSINDEX_ASSERT(QueryVirtualMemory);
			SYSINDEX_ASSERT(AdjustPrivilegesToken);
			SYSINDEX_ASSERT(SetInformationThread);
			SYSINDEX_ASSERT(OpenDirectoryObject);
			SYSINDEX_ASSERT(CreateThreadEx);
			SYSINDEX_ASSERT(WaitForSingleObject);
			SYSINDEX_ASSERT(WaitForMultipleObjects);
			SYSINDEX_ASSERT(LockVirtualMemory);
			SYSINDEX_ASSERT(UnlockVirtualMemory);
			SYSINDEX_ASSERT(CreateFile);
			SYSINDEX_ASSERT(QueryInformationFile);
			SYSINDEX_ASSERT(QueryVolumeInformationFile);
			SYSINDEX_ASSERT(QueryObject);
			SYSINDEX_ASSERT(DelayExecution);
			SYSINDEX_ASSERT(WriteFile);
			SYSINDEX_ASSERT(TerminateProcess);
			SYSINDEX_ASSERT(DeviceIoControlFile);
			SYSINDEX_ASSERT(CreateEvent);
			SYSINDEX_ASSERT(DuplicateObject);
			SYSINDEX_ASSERT(SetInformationFile);
			SYSINDEX_ASSERT(ReadFile);

			/* Syscwall identification end */
		}
	}

	return TRUE;
}

/*
 * This function should not be exported.
 * It's use is defined on a per session basis.
 * Use of highcall syscalls unpermitted due to undefined indicies.
 * This function will define system call indicies.
 */
BOOLEAN
HCAPI
HcSysInitializeNativeSystem()
{
	NTSTATUS Status;
	PBYTE lpBuffer;
	HANDLE hFile;
	LPWSTR lpModulePath;
	LPBYTE lpModule = (LPBYTE) HcGlobal.HandleNtdll;
	HMODULE hModule = HcGlobal.HandleNtdll;
	DWORD dwFileSize;
	FILE_STANDARD_INFORMATION FileStandard;
	IO_STATUS_BLOCK IoStatusBlock;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING NtPathU;
	PVOID EaBuffer = NULL;
	DWORD EaLength = 0; 
	DWORD dwNumberOfBytesRead = 0;

	ZERO(&IoStatusBlock);
	ZERO(&FileStandard);

	lpModulePath = HcStringAllocW(MAX_PATH);

	if (!HcModuleFileNameW(hModule, lpModulePath))
	{
		HcFree(lpModulePath);
		return FALSE;
	}

	/* validate & translate the filename */
	if (!RtlDosPathNameToNtPathName_U(lpModulePath,
		&NtPathU,
		NULL,
		NULL))
	{
		HcFree(lpModulePath);
		return FALSE;
	}

	/* build the object attributes */
	InitializeObjectAttributes(&ObjectAttributes,
		&NtPathU,
		0,
		NULL,
		NULL);

	ObjectAttributes.Attributes |= OBJ_CASE_INSENSITIVE;

	/* Open the file */
	Status = NtCreateFile(&hFile,
		GENERIC_READ | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL & (FILE_ATTRIBUTE_VALID_FLAGS & ~FILE_ATTRIBUTE_DIRECTORY),
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		EaBuffer,
		EaLength);

	/* Don't free with HcFree due to RtlDosPathNameToNtPathName_U allocation type. */
	RtlFreeHeap(RtlGetProcessHeap(), 0, NtPathU.Buffer);

	if (!NT_SUCCESS(Status))
	{
		HcFree(lpModulePath);
		return FALSE;
	}

	/* Zero it out for the next call. */
	ZERO(&IoStatusBlock);

	Status = NtQueryInformationFile(hFile,
		&IoStatusBlock,
		&FileStandard,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);

	if (!NT_SUCCESS(Status))
	{
		HcFree(lpModulePath);
		return FALSE;
	}

	dwFileSize = FileStandard.EndOfFile.u.LowPart;
	lpBuffer = (PBYTE)HcAlloc(dwFileSize);

	HcFree(lpModulePath);

	/* Zero it out again, for the next call. */
	ZERO(&IoStatusBlock);

	/* Snatch the data */
	Status = NtReadFile(hFile,
		NULL,
		NULL,
		NULL,
		&IoStatusBlock,
		lpBuffer,
		dwFileSize,
		NULL,
		NULL);

	/* Wait in case operation is pending */
	if (Status == STATUS_PENDING)
	{
		if (HcObjectWait(hFile, INFINITE))
		{
			Status = IoStatusBlock.Status;
		}
	}

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		HcFree(lpBuffer);
		return FALSE;
	}

	dwNumberOfBytesRead = (DWORD)IoStatusBlock.Information;
	if (dwNumberOfBytesRead != dwFileSize)
	{
		HcFree(lpBuffer);
		return FALSE;
	}

	NtClose(hFile);

	update_syscall_list(lpBuffer, lpModule);

	HcFree(lpBuffer);
	return TRUE;
}

/* The logic behind this function is checking whether the wow64 call gate is active or not. */
BOOLEAN
#ifndef _WIN64
__declspec(naked)
#else
__stdcall
#endif
HcIsWow64()
{
#ifndef _WIN64
	__asm
	{
		mov eax, fs:[0c0h]
		test eax, eax
		jne wow64
		ret
		wow64:
		mov eax, 1
		ret
	}
#else
	return FALSE;
#endif
}