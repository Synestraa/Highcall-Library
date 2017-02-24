#ifndef HC_SYSCALL_H
#define HC_SYSCALL_H

#include "../../public/hcdef.h"

//
// SYS_INDEX invalid code
//
#define SYSI_INVALID   (0xffffffff)

#if defined (__cplusplus)
extern "C" {
#endif

/* Initialization functions should be called once per session. */
BOOLEAN
HCAPI
HcSysInitializeNativeSystem();

BOOLEAN
HcIsWow64();

#pragma region Native System Call Definitions

HC_GLOBAL SYS_INDEX sciQueryInformationToken;
NTSTATUS HcQueryInformationToken(CONST IN HANDLE TokenHandle,
	CONST IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	_Out_writes_bytes_(TokenInformationLength) LPVOID TokenInformation,
	CONST IN ULONG TokenInformationLength,
	OUT PULONG ReturnLength);

HC_GLOBAL SYS_INDEX sciOpenProcessToken;
NTSTATUS HcOpenProcessToken(CONST IN HANDLE hProcess,
	CONST IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle);

HC_GLOBAL SYS_INDEX sciResumeProcess;
NTSTATUS HcResumeProcess(CONST IN HANDLE ProcessHandle);

HC_GLOBAL SYS_INDEX sciSuspendProcess;
NTSTATUS HcSuspendProcess(CONST IN HANDLE ProcessHandle);

HC_GLOBAL SYS_INDEX sciAllocateVirtualMemory;
NTSTATUS HcAllocateVirtualMemory(CONST IN HANDLE hProcess,
	IN LPVOID* UBaseAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T URegionSize,
	CONST IN ULONG AllocationType,
	CONST IN ULONG Protect);

HC_GLOBAL SYS_INDEX sciFreeVirtualMemory;
NTSTATUS HcFreeVirtualMemory(CONST IN HANDLE hProcess,
	IN LPVOID* UBaseAddress,
	IN PSIZE_T URegionSize,
	CONST IN ULONG FreeType);

HC_GLOBAL SYS_INDEX sciResumeThread;
NTSTATUS HcResumeThread(CONST IN HANDLE ThreadHandle,
	OUT PULONG SuspendCount OPTIONAL);

HC_GLOBAL SYS_INDEX sciQueryInformationThread;
NTSTATUS HcQueryInformationThread(CONST IN HANDLE ThreadHandle,
	CONST IN THREADINFOCLASS ThreadInformationClass,
	OUT LPVOID ThreadInformation,
	CONST IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

HC_GLOBAL SYS_INDEX sciCreateThread;
NTSTATUS HcCreateThread(OUT PHANDLE ThreadHandle,
	CONST IN ACCESS_MASK			DesiredAccess,
	IN POBJECT_ATTRIBUTES			ObjectAttributes OPTIONAL,
	CONST IN HANDLE					ProcessHandle,
	OUT PCLIENT_ID					ClientId,
	IN PCONTEXT						ThreadContext,
	IN PINITIAL_TEB					InitialTeb,
	CONST IN BOOLEAN				CreateSuspended);

HC_GLOBAL SYS_INDEX sciFlushInstructionCache;
NTSTATUS HcFlushInstructionCache(CONST IN HANDLE ProcessHandle,
	CONST IN LPVOID BaseAddress,
	CONST IN SIZE_T NumberOfBytesToFlush);

HC_GLOBAL SYS_INDEX sciOpenProcess;
NTSTATUS HcOpenProcess(OUT PHANDLE	ProcessHandle,
	CONST IN    ACCESS_MASK			DesiredAccess,
	CONST IN    POBJECT_ATTRIBUTES	ObjectAttributes,
	IN			PCLIENT_ID			ClientId OPTIONAL
);

HC_GLOBAL SYS_INDEX sciProtectVirtualMemory;
NTSTATUS HcProtectVirtualMemory(CONST IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN OUT PSIZE_T NumberOfBytesToProtect,
	CONST IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection);

HC_GLOBAL SYS_INDEX sciReadVirtualMemory;
NTSTATUS HcReadVirtualMemory(CONST HANDLE ProcessHandle,
	CONST LPVOID BaseAddress,
	LPVOID Buffer,
	CONST SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead);

HC_GLOBAL SYS_INDEX sciWriteVirtualMemory;
NTSTATUS HcWriteVirtualMemory(CONST HANDLE ProcessHandle,
	CONST LPVOID BaseAddress,
	CONST VOID *Buffer,
	CONST SIZE_T BufferSize,
	PSIZE_T NumberOfBytesWritten);

HC_GLOBAL SYS_INDEX sciQueryInformationProcess;
NTSTATUS HcQueryInformationProcess(
	__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) LPVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength);

HC_GLOBAL SYS_INDEX sciQuerySystemInformation;
NTSTATUS HcQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) LPVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength);

HC_GLOBAL SYS_INDEX sciClose;
NTSTATUS HcClose(HANDLE hObject);

HC_GLOBAL SYS_INDEX sciQueryVirtualMemory;
NTSTATUS HcQueryVirtualMemory(IN HANDLE ProcessHandle,
	IN LPVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT LPVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength);

HC_GLOBAL SYS_INDEX sciAdjustPrivilegesToken;
NTSTATUS HcAdjustPrivilegesToken(HANDLE TokenHandle,
	BOOLEAN 	DisableAllPrivileges,
	PTOKEN_PRIVILEGES 	NewState,
	DWORD 	BufferLength,
	PTOKEN_PRIVILEGES 	PreviousState,
	PDWORD 	ReturnLength);

HC_GLOBAL SYS_INDEX sciSetInformationThread;
NTSTATUS HcSetInformationThread(IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength);

HC_GLOBAL SYS_INDEX sciOpenDirectoryObject;
NTSTATUS HcOpenDirectoryObject(OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

HC_GLOBAL SYS_INDEX sciCreateThreadEx;
NTSTATUS HcCreateThreadEx(OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	IN ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits,
	_In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList);

HC_GLOBAL SYS_INDEX sciWaitForSingleObject;
NTSTATUS HcWaitForSingleObject(IN HANDLE hObject,
	IN BOOLEAN bAlertable,
	IN PLARGE_INTEGER Timeout);

HC_GLOBAL SYS_INDEX sciWaitForMultipleObjects;
NTSTATUS HcWaitForMultipleObjects(IN ULONG ObjectCount,
	IN PHANDLE HandleArray,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER TimeOut OPTIONAL);

HC_GLOBAL SYS_INDEX sciUnlockVirtualMemory;
NTSTATUS HcUnlockVirtualMemory(IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T NumberOfBytesToUnlock,
	IN ULONG MapType);


HC_GLOBAL SYS_INDEX sciLockVirtualMemory;
NTSTATUS HcLockVirtualMemory(IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T NumberOfBytesToLock,
	IN ULONG MapType);

HC_GLOBAL SYS_INDEX sciCreateFile;
NTSTATUS HcCreateFile(
	OUT    PHANDLE            FileHandle,
	IN     ACCESS_MASK        DesiredAccess,
	IN     POBJECT_ATTRIBUTES ObjectAttributes,
	OUT    PIO_STATUS_BLOCK   IoStatusBlock,
	_In_opt_ PLARGE_INTEGER     AllocationSize,
	IN     ULONG              FileAttributes,
	IN     ULONG              ShareAccess,
	IN     ULONG              CreateDisposition,
	IN     ULONG              CreateOptions,
	IN     PVOID              EaBuffer,
	IN     ULONG              EaLength
);

HC_GLOBAL SYS_INDEX sciQueryInformationFile;
NTSTATUS HcQueryInformationFile(
	IN  HANDLE                 FileHandle,
	OUT PIO_STATUS_BLOCK       IoStatusBlock,
	OUT PVOID                  FileInformation,
	IN  ULONG                  Length,
	IN  FILE_INFORMATION_CLASS FileInformationClass
);

HC_GLOBAL SYS_INDEX sciQueryVolumeInformationFile;
NTSTATUS HcQueryVolumeInformationFile(
	IN  HANDLE               FileHandle,
	OUT PIO_STATUS_BLOCK     IoStatusBlock,
	OUT PVOID                FsInformation,
	IN  ULONG                Length,
	IN  FS_INFORMATION_CLASS FsInformationClass
);

HC_GLOBAL SYS_INDEX sciQueryObject;
NTSTATUS HcQueryObject(
	IN  HANDLE                   Handle OPTIONAL,
	IN  OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID                    ObjectInformation OPTIONAL,
	IN  ULONG                    ObjectInformationLength,
	OUT PULONG                   ReturnLength OPTIONAL
);

HC_GLOBAL SYS_INDEX sciDuplicateObject;
NTSTATUS HcDuplicateObject(
	IN HANDLE      SourceProcessHandle,
	IN HANDLE      SourceHandle,
	IN HANDLE      TargetProcessHandle OPTIONAL,
	IN PHANDLE     TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG       HandleAttributes,
	IN ULONG       Options
);

HC_GLOBAL SYS_INDEX sciDelayExecution;
NTSTATUS HcDelayExecution(IN BOOLEAN Alertable,
	IN PLARGE_INTEGER DelayInterval);

HC_GLOBAL SYS_INDEX sciWriteFile;
NTSTATUS HcWriteFile(
	IN  HANDLE           FileHandle,
	IN	HANDLE           Event OPTIONAL,
	IN	PIO_APC_ROUTINE  ApcRoutine OPTIONAL,
	IN	PVOID            ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN  PVOID            Buffer,
	IN  ULONG            Length,
	IN	PLARGE_INTEGER   ByteOffset OPTIONAL,
	IN	PULONG           Key OPTIONAL
);

HC_GLOBAL SYS_INDEX sciTerminateProcess;
NTSTATUS HcTerminateProcess(
	IN HANDLE   ProcessHandle OPTIONAL,
	IN NTSTATUS ExitStatus
);

HC_GLOBAL SYS_INDEX sciDeviceIoControlFile;
NTSTATUS HcDeviceIoControlFile(
	IN HANDLE DeviceHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE UserApcRoutine OPTIONAL,
	IN PVOID UserApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG IoControlCode,
	IN PVOID InputBuffer,
	IN ULONG InputBufferLength OPTIONAL,
	OUT PVOID OutputBuffer,
	IN ULONG OutputBufferLength OPTIONAL);

HC_GLOBAL SYS_INDEX sciCreateEvent;
NTSTATUS HcCreateEvent(
	OUT PHANDLE            EventHandle,
	IN  ACCESS_MASK        DesiredAccess,
	IN	POBJECT_ATTRIBUTES ObjectAttributes,
	IN  EVENT_TYPE         EventType,
	IN  BOOLEAN            InitialState);

HC_GLOBAL SYS_INDEX sciSetInformationFile;
NTSTATUS HcSetInformationFile(
	IN  HANDLE                 FileHandle,
	OUT PIO_STATUS_BLOCK       IoStatusBlock,
	IN  PVOID                  FileInformation,
	IN  ULONG                  Length,
	IN  FILE_INFORMATION_CLASS FileInformationClass);

#if defined (__cplusplus)
}
#endif

#endif