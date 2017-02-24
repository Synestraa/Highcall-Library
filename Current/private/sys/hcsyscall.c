#include "hcsyscall.h"

#include "../../public/hcmodule.h"
#include "../../public/hcfile.h"
#include "../../public/hcglobal.h"
#include "../../public/hcvirtual.h"
#include "../../public/hcprocess.h"
#include "../../public/imports.h"
#include "../../public/hcstring.h"
#include "../../public/hcpe.h"

#define NT_SYMBOL "Nt"
#define SYSINDEX_ASSERT(x) \
{ \
	if (HcStringCompareContentA(lpCurrentFunction, NT_SYMBOL #x)) \
	{\
		sci##x = dwIndex;\
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

/*
 *
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
	ULONG_PTR dwFileOffset = 0;
	LPBYTE VirtualAddress = 0;
	LPWSTR lpModulePath = HcStringAllocW(MAX_PATH);
	PIMAGE_EXPORT_DIRECTORY pExports = NULL;
	PDWORD pExportNames = NULL;
	PDWORD pExportFunctions = NULL;
	PWORD pExportOrdinals = NULL;
	LPSTR lpCurrentFunction = NULL;
	PIMAGE_NT_HEADERS pHeaderNT = NULL;
	LPBYTE RelativeVirtualAddress = 0;
	LPBYTE lpModule = (LPBYTE) HcGlobal.HandleNtdll;
	HMODULE hModule = HcGlobal.HandleNtdll;
	SIZE_T FileSize;
	FILE_STANDARD_INFORMATION FileStandard;
	IO_STATUS_BLOCK IoStatusBlock;

	pHeaderNT = HcPEGetNtHeader(hModule);
	if (!pHeaderNT || !lpModulePath)
	{
		return 0;
	}

	pExports = HcPEGetExportDirectory(HcGlobal.HandleNtdll);
	if (!pExports)
	{
		return FALSE;
	}

	wchar_t path[] = L"C:/Windows/System32/ntdll.dll";
	HcStringCopyW(lpModulePath, path, sizeof(path));


	/* Open it up */
	hFile = HcFileOpenW(lpModulePath, OPEN_EXISTING, GENERIC_READ);
	if (hFile == INVALID_HANDLE)
	{
		return FALSE;
	}

	Status = NtQueryInformationFile(hFile,
		&IoStatusBlock,
		&FileStandard,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);

	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	FileSize = FileStandard.EndOfFile.u.LowPart;
	lpBuffer = (PBYTE)HcAlloc(FileSize);

	HcFree(lpModulePath);

	/* Snatch the data */
	if (HcFileRead(hFile, lpBuffer, (DWORD) FileSize) != FileSize)
	{
		NtClose(hFile);
		return FALSE;
	}

	NtClose(hFile);

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
		}
	}

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