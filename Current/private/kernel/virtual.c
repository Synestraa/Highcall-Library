#include <highcall.h>

#include "../sys/syscall.h"
#include "../../public/imports.h"

DECL_EXTERN_API(LPVOID, VirtualAllocEx, 
	CONST IN HANDLE hProcess,
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	CONST IN DWORD flAllocationType,
	CONST IN DWORD flProtect)
{
	NTSTATUS Status;

	/* Allocate the memory */
	Status = HcAllocateVirtualMemory(hProcess,
		&lpAddress,
		0,
		&dwSize,
		flAllocationType,
		flProtect);

	/* Check for status */
	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		HcErrorSetNtStatus(Status);
		return NULL;
	}

	/* Return the allocated address */
	return lpAddress;
}

DECL_EXTERN_API(ULONG64, VirtualAllocWow64Ex, 
	CONST IN HANDLE hProcess, 
	IN ULONG64 Address, 
	IN ULONG64 Size, 
	CONST IN DWORD flAllocationType, 
	CONST IN DWORD flProtect)
{
	NTSTATUS Status;

	Status = HcWow64AllocateVirtualMemory64(hProcess, &Address, 0, &Size, flAllocationType, flProtect);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return 0;
	}

	return Address;
}

DECL_EXTERN_API(ULONG64, VirtualAlloc64Ex, CONST IN HANDLE hProcess,
	IN ULONG64 Address,
	IN ULONG64 Size,
	CONST IN DWORD flAllocationType,
	CONST IN DWORD flProtect)
{
#ifdef _WIN64
	return (ULONG64) HcVirtualAllocEx(hProcess, (LPVOID) Address, Size, flAllocationType, flProtect);
#else
	return HcVirtualAllocWow64Ex(hProcess, Address, Size, flAllocationType, flProtect);
#endif
}

DECL_EXTERN_API(LPVOID, VirtualAlloc, IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	CONST IN DWORD flAllocationType,
	CONST IN DWORD flProtect)
{
	/* Call the extended API */
	return HcVirtualAllocEx(NtCurrentProcess(),
		lpAddress,
		dwSize,
		flAllocationType,
		flProtect);
}

DECL_EXTERN_API(BOOL, VirtualFreeEx, 
	CONST IN HANDLE hProcess,
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	CONST IN DWORD dwFreeType)
{
	NTSTATUS Status;

	/* Validate size and flags */
	if (!dwSize || !(dwFreeType & MEM_RELEASE))
	{
		/* Free the memory */
		Status = HcFreeVirtualMemory(hProcess,
			&lpAddress,
			&dwSize,
			dwFreeType);

		if (!NT_SUCCESS(Status))
		{
			/* We failed */
			HcErrorSetNtStatus(Status);
			return FALSE;
		}

		/* Return success */
		return TRUE;
	}

	/* Invalid combo */
	HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
	return FALSE;
}


DECL_EXTERN_API(BOOL, VirtualFree, 
	IN LPVOID lpAddress,
	CONST IN SIZE_T dwSize,
	CONST IN DWORD dwFreeType)
{
	/* Call the extended API */
	return HcVirtualFreeEx(NtCurrentProcess(),
		lpAddress,
		dwSize,
		dwFreeType);
}

DECL_EXTERN_API(BOOL, VirtualProtect, 
	IN LPVOID lpAddress,
	CONST IN SIZE_T dwSize,
	CONST IN DWORD flNewProtect,
	OUT PDWORD lpflOldProtect)
{
	/* Call the extended API */
	return HcVirtualProtectEx(NtCurrentProcess(),
		lpAddress,
		dwSize,
		flNewProtect,
		lpflOldProtect);
}

DECL_EXTERN_API(BOOL, VirtualProtectEx, 
	CONST IN HANDLE hProcess,
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	CONST IN DWORD flNewProtect,
	OUT PDWORD lpflOldProtect)
{
	NTSTATUS Status;

	/* Make the call. */
	Status = HcProtectVirtualMemory(hProcess,
		&lpAddress,
		&dwSize,
		flNewProtect,
		(PULONG)lpflOldProtect);

	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	/* Return success */
	return TRUE;
}

DECL_EXTERN_API(BOOL, VirtualLock, IN LPVOID lpAddress, CONST IN SIZE_T dwSize)
{
	NTSTATUS Status;
	SIZE_T RegionSize = dwSize;
	PVOID BaseAddress = lpAddress;

	/* Make the call. */
	Status = HcLockVirtualMemory(NtCurrentProcess(),
		&BaseAddress,
		&RegionSize,
		MAP_PROCESS);

	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	/* Return success */
	return TRUE;
}

DECL_EXTERN_API(SIZE_T, VirtualQuery, 
	IN LPCVOID lpAddress,
	OUT PMEMORY_BASIC_INFORMATION lpBuffer,
	CONST IN SIZE_T dwLength)
{
	/* Call the extended API */
	return HcVirtualQueryEx(NtCurrentProcess(),
		lpAddress,
		lpBuffer,
		dwLength);
}

DECL_EXTERN_API(SIZE_T, VirtualQueryEx, 
	CONST IN HANDLE hProcess,
	IN LPCVOID lpAddress,
	OUT PMEMORY_BASIC_INFORMATION lpBuffer,
	CONST IN SIZE_T dwLength)
{
	NTSTATUS Status; 
	SIZE_T ResultLength = 0;

	/* Make the call. */
	Status = HcQueryVirtualMemory(hProcess,
		(LPVOID)lpAddress,
		MemoryBasicInformation,
		lpBuffer,
		dwLength,
		&ResultLength);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return ResultLength;
	}

	/* Return the length returned */
	return ResultLength;
}

DECL_EXTERN_API(BOOL, VirtualUnlock, IN LPVOID lpAddress, CONST IN SIZE_T dwSize)
{
	NTSTATUS Status;
	SIZE_T RegionSize = dwSize;
	PVOID BaseAddress = lpAddress;

	/* Make the call. */
	Status = HcUnlockVirtualMemory(NtCurrentProcess(),
		&BaseAddress,
		&RegionSize,
		MAP_PROCESS);

	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	/* Return success */
	return TRUE;
}

DECL_EXTERN_API(LPVOID, Alloc32, CONST IN SIZE_T Size)
{
	PBYTE FreeSpace = NULL;
	MEMORY_BASIC_INFORMATION mbi;
	ZERO(&mbi);

	for (PBYTE Addr = (PBYTE)0x1000; Addr < (PBYTE)USER_MAX_ADDRESS + Size;)
	{
		/* Check the block */
		if (!HcVirtualQuery((LPCVOID)Addr, &mbi, sizeof(mbi)))
		{
			break;
		}

		if (mbi.State == MEM_FREE)
		{
			/* Try and allocate on this spot. */
			FreeSpace = (PBYTE)HcVirtualAlloc((LPVOID)Addr,
				Size,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_READWRITE);

			if (FreeSpace)
			{
				break;
			}
		}

		Addr += 0x1000;
		if (Addr > (PBYTE)USER_MAX_ADDRESS)
		{
			return NULL;
		}
	}

	return (LPVOID) FreeSpace;
}

DECL_EXTERN_API(PVOID, Alloc, CONST IN SIZE_T Size)
{
	LPVOID Alloc = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
	if (!Alloc)
	{
		HcErrorSetNtStatus(STATUS_MEMORY_NOT_ALLOCATED);
	}
	return Alloc;
}

DECL_EXTERN_API(VOID, Free, CONST IN LPVOID lpAddress)
{
	RtlFreeHeap(RtlGetProcessHeap(), 0, lpAddress);
}

DECL_EXTERN_API(PVOID, AllocPage, CONST IN SIZE_T Size)
{
	LPVOID Alloc = HcVirtualAlloc(NULL, Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!Alloc)
	{
		HcErrorSetNtStatus(STATUS_MEMORY_NOT_ALLOCATED);
	}
	return Alloc;
}

DECL_EXTERN_API(VOID, FreePage, CONST IN LPVOID lpAddress)
{
	HcVirtualFree(lpAddress, 0, MEM_RELEASE);
}

DECL_EXTERN_API(ULONG64, Alloc64, CONST IN ULONG64 Size)
{
	return HcVirtualAlloc64Ex(NtCurrentProcess(), 0, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}