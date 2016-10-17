#ifndef HC_SYSCALL_H
#define HC_SYSCALL_H

/* Assembly files are to be kept in seperate .asm files. 
-  While unconvenient and harder to maintain, it prevents all of the functions from being hooked by one edit. */

#include "../headers/hcdef.h"

#ifndef _WIN64
#define NAKED __declspec(naked)
#define EMIT(a) __asm __emit (a)

#define X64_Start_with_CS(_cs) \
{ \
EMIT(0x6A) EMIT(_cs)                         /*  push   _cs             */ \
EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)   /*  call   $+5             */ \
EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(5)        /*  add    dword [esp], 5  */ \
EMIT(0xCB)                                   /*  retf                   */ \
}

#define X64_End_with_CS(_cs) \
{ \
EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                 /*  call   $+5                   */ \
EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(4) EMIT(_cs) EMIT(0) EMIT(0) EMIT(0) /*  mov    dword [rsp + 4], _cs  */ \
EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(0xD)                                    /*  add    dword [rsp], 0xD      */ \
EMIT(0xCB)                                                                 /*  retf                         */ \
}

#define X64_Start() X64_Start_with_CS(0x33)
#define X64_End() X64_End_with_CS(0x23)

#define _RAX  0
#define _RCX  1
#define _RDX  2
#define _RBX  3
#define _RSP  4
#define _RBP  5
#define _RSI  6
#define _RDI  7
#define _R8   8
#define _R9   9
#define _R10 10
#define _R11 11
#define _R12 12
#define _R13 13
#define _R14 14
#define _R15 15

#define X64_Push(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x50 | ((r) & 7))
#define X64_Pop(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x58 | ((r) & 7))
#else
#define NAKED __stdcall
#endif

#if defined (__cplusplus)
extern "C" {
#endif

BOOLEAN
HCAPI
HcIsSyscallExport(LPVOID lpAddress);

SYS_INDEX
HCAPI
HcSyscallIndexA(LPCSTR lpName);

SYS_INDEX
HCAPI
HcSyscallIndexW(LPCWSTR lpName);

BOOLEAN
HcIsWow64();

NTSTATUS
HCAPI 
HcWow64SystemCall(DWORD SysIndex, DWORD argC, va_list args);

SYS_INDEX extern sciQueryInformationToken;
NTSTATUS HcQueryInformationToken(_In_ HANDLE TokenHandle,
	_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
	_Out_writes_bytes_(TokenInformationLength) LPVOID TokenInformation,
	_In_ ULONG TokenInformationLength,
	_Out_ PULONG ReturnLength);

SYS_INDEX extern sciOpenProcessToken;
NTSTATUS HcOpenProcessToken(_In_ HANDLE hProcess,
	_In_ ACCESS_MASK DesiredAccess,
	_Out_ PHANDLE TokenHandle);

SYS_INDEX extern sciResumeProcess;
NTSTATUS HcResumeProcess(IN HANDLE ProcessHandle);

SYS_INDEX extern sciSuspendProcess;
NTSTATUS HcSuspendProcess(IN HANDLE ProcessHandle);

SYS_INDEX extern sciAllocateVirtualMemory;
NTSTATUS HcAllocateVirtualMemory(IN HANDLE hProcess,
	IN LPVOID* UBaseAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T URegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

SYS_INDEX extern sciFreeVirtualMemory;
NTSTATUS HcFreeVirtualMemory(IN HANDLE hProcess,
	IN LPVOID* UBaseAddress,
	IN PSIZE_T URegionSize,
	IN ULONG FreeType);

SYS_INDEX extern sciResumeThread;
NTSTATUS HcResumeThread(IN HANDLE ThreadHandle,
	OUT PULONG SuspendCount OPTIONAL);

SYS_INDEX extern sciQueryInformationThread;
NTSTATUS HcQueryInformationThread(IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT LPVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

SYS_INDEX extern sciCreateThread;
NTSTATUS HcCreateThread(OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN HANDLE               ProcessHandle,
	OUT PCLIENT_ID          ClientId,
	IN PCONTEXT             ThreadContext,
	IN PINITIAL_TEB         InitialTeb,
	IN BOOLEAN              CreateSuspended);

SYS_INDEX extern sciFlushInstructionCache;
NTSTATUS HcFlushInstructionCache(IN HANDLE ProcessHandle,
	IN LPVOID BaseAddress,
	IN SIZE_T NumberOfBytesToFlush);

SYS_INDEX extern sciOpenProcess;
NTSTATUS HcOpenProcess(_Out_ PHANDLE ProcessHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID         ClientId
);

SYS_INDEX extern sciProtectVirtualMemory;
NTSTATUS HcProtectVirtualMemory(IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN OUT PSIZE_T NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection);

SYS_INDEX extern sciReadVirtualMemory;
NTSTATUS HcReadVirtualMemory(HANDLE ProcessHandle,
	LPVOID BaseAddress,
	LPVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead);

SYS_INDEX extern sciWriteVirtualMemory;
NTSTATUS HcWriteVirtualMemory(HANDLE ProcessHandle,
	LPVOID BaseAddress, 
	CONST VOID *Buffer,
	SIZE_T BufferSize, 
	PSIZE_T NumberOfBytesWritten);

SYS_INDEX extern sciQueryInformationProcess;
NTSTATUS HcQueryInformationProcess(
	__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) LPVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength);

SYS_INDEX extern sciQuerySystemInformation;
NTSTATUS HcQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) LPVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength);

SYS_INDEX extern sciClose;
NTSTATUS HcClose(HANDLE hObject);

SYS_INDEX extern sciQueryVirtualMemory;
NTSTATUS HcQueryVirtualMemory(IN HANDLE ProcessHandle,
	IN LPVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT LPVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength);

SYS_INDEX extern sciAdjustPrivilegesToken;
NTSTATUS HcAdjustPrivilegesToken(HANDLE TokenHandle,
	BOOLEAN 	DisableAllPrivileges,
	PTOKEN_PRIVILEGES 	NewState,
	DWORD 	BufferLength,
	PTOKEN_PRIVILEGES 	PreviousState,
	PDWORD 	ReturnLength);

SYS_INDEX extern sciSetInformationThread;
NTSTATUS HcSetInformationThread(IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength);

SYS_INDEX extern sciOpenDirectoryObject;
NTSTATUS HcOpenDirectoryObject(OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

SYS_INDEX extern sciCreateThreadEx;
NTSTATUS HcCreateThreadEx(_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits,
	_In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList);

SYS_INDEX extern sciWaitForSingleObject;
NTSTATUS HcWaitForSingleObject(IN HANDLE hObject,
	IN BOOLEAN bAlertable,
	IN PLARGE_INTEGER Timeout);

SYS_INDEX extern sciWaitForMultipleObjects;
NTSTATUS HcWaitForMultipleObjects(IN ULONG ObjectCount,
	IN PHANDLE HandleArray,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER TimeOut OPTIONAL);

SYS_INDEX extern sciUnlockVirtualMemory;
NTSTATUS HcUnlockVirtualMemory(IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T NumberOfBytesToUnlock,
	IN ULONG MapType);


SYS_INDEX extern sciLockVirtualMemory;
NTSTATUS HcLockVirtualMemory(IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T NumberOfBytesToLock,
	IN ULONG MapType);

SYS_INDEX extern sciCreateFile;
NTSTATUS HcCreateFile(
	_Out_    PHANDLE            FileHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_    PIO_STATUS_BLOCK   IoStatusBlock,
	_In_opt_ PLARGE_INTEGER     AllocationSize,
	_In_     ULONG              FileAttributes,
	_In_     ULONG              ShareAccess,
	_In_     ULONG              CreateDisposition,
	_In_     ULONG              CreateOptions,
	_In_     PVOID              EaBuffer,
	_In_     ULONG              EaLength
);

SYS_INDEX extern sciQueryInformationFile;
NTSTATUS HcQueryInformationFile(
	_In_  HANDLE                 FileHandle,
	_Out_ PIO_STATUS_BLOCK       IoStatusBlock,
	_Out_ PVOID                  FileInformation,
	_In_  ULONG                  Length,
	_In_  FILE_INFORMATION_CLASS FileInformationClass
);

SYS_INDEX extern sciQueryVolumeInformationFile;
NTSTATUS HcQueryVolumeInformationFile(
	_In_  HANDLE               FileHandle,
	_Out_ PIO_STATUS_BLOCK     IoStatusBlock,
	_Out_ PVOID                FsInformation,
	_In_  ULONG                Length,
	_In_  FS_INFORMATION_CLASS FsInformationClass
);

#if defined (__cplusplus)
}
#endif

#endif