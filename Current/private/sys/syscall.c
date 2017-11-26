#include <highcall.h>

#include "syscall.h"
#include "../../public/imports.h"

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

#ifdef SDFGSDFGFDS

NTSTATUS SYSCALLAPI HcQueryInformationToken(CONST IN HANDLE TokenHandle,
	CONST IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	_Out_writes_bytes_(TokenInformationLength) LPVOID TokenInformation,
	CONST IN ULONG TokenInformationLength,
	OUT PULONG ReturnLength)
{
	return (NTSTATUS) HcWow64Syscall(sciQueryInformationToken, 5, (DWORD64) TokenHandle, (DWORD64) TokenInformationClass, (DWORD64) TokenInformation, (DWORD64) TokenInformationLength, (DWORD64) ReturnLength);
}


NTSTATUS SYSCALLAPI HcOpenProcessToken(CONST IN HANDLE hProcess,
	CONST IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle)
{
	return (NTSTATUS) HcWow64Syscall(sciOpenProcessToken, 3, (DWORD64) hProcess, (DWORD64) DesiredAccess, (DWORD64) TokenHandle);
}



NTSTATUS SYSCALLAPI HcAllocateVirtualMemory(CONST IN HANDLE hProcess,
	IN LPVOID* UBaseAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T URegionSize,
	CONST IN ULONG AllocationType,
	CONST IN ULONG Protect)
{
	return (NTSTATUS) HcWow64Syscall(sciAllocateVirtualMemory, 6, (DWORD64) hProcess, (DWORD64) UBaseAddress, (DWORD64) ZeroBits, (DWORD64) URegionSize, (DWORD64) AllocationType, (DWORD64) Protect);
}

NTSTATUS SYSCALLAPI HcResumeThread(CONST IN HANDLE ThreadHandle,
	OUT PULONG SuspendCount OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciResumeThread, 2, (DWORD64) ThreadHandle, (DWORD64) SuspendCount);
}


NTSTATUS SYSCALLAPI HcOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciOpenThread, 4, (DWORD64) ThreadHandle, (DWORD64) DesiredAccess, (DWORD64) ObjectAttributes, (DWORD64) ClientId);
}


NTSTATUS SYSCALLAPI HcSuspendThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciSuspendThread, 2, (DWORD64) ThreadHandle, (DWORD64) PreviousSuspendCount);
}


NTSTATUS SYSCALLAPI HcQueryInformationThread(CONST IN HANDLE ThreadHandle,
	CONST IN THREADINFOCLASS ThreadInformationClass,
	OUT LPVOID ThreadInformation,
	CONST IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciQueryInformationThread, 5, (DWORD64) ThreadHandle, (DWORD64) ThreadInformationClass, (DWORD64) ThreadInformation, (DWORD64) ThreadInformationLength, (DWORD64) ReturnLength);
}


NTSTATUS SYSCALLAPI HcCreateThread(OUT PHANDLE ThreadHandle,
	CONST IN ACCESS_MASK			DesiredAccess,
	IN POBJECT_ATTRIBUTES			ObjectAttributes OPTIONAL,
	CONST IN HANDLE					ProcessHandle,
	OUT PCLIENT_ID					ClientId,
	IN PCONTEXT						ThreadContext,
	IN PINITIAL_TEB					InitialTeb,
	CONST IN BOOLEAN				CreateSuspended)
{
	return (NTSTATUS) HcWow64Syscall(sciCreateThread, 8, (DWORD64) ThreadHandle, (DWORD64) DesiredAccess, (DWORD64) ObjectAttributes, (DWORD64) ProcessHandle, (DWORD64) ClientId, (DWORD64) ThreadContext, (DWORD64) InitialTeb, (DWORD64) CreateSuspended);
}


NTSTATUS SYSCALLAPI HcFlushInstructionCache(CONST IN HANDLE ProcessHandle,
	CONST IN LPVOID BaseAddress,
	CONST IN SIZE_T NumberOfBytesToFlush)
{
	return (NTSTATUS) HcWow64Syscall(sciFlushInstructionCache, 3, (DWORD64) ProcessHandle, (DWORD64) BaseAddress, (DWORD64) NumberOfBytesToFlush);
}

NTSTATUS SYSCALLAPI HcOpenProcess(
	OUT			PHANDLE				ProcessHandle,
	CONST IN    ACCESS_MASK			DesiredAccess,
	CONST IN    POBJECT_ATTRIBUTES	ObjectAttributes,
	IN			PCLIENT_ID			ClientId OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciOpenProcess, 4, (DWORD64) ProcessHandle, (DWORD64) DesiredAccess, (DWORD64) ObjectAttributes, (DWORD64) ClientId);
}


NTSTATUS SYSCALLAPI HcProtectVirtualMemory(CONST IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T NumberOfBytesToProtect,
	CONST IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection)
{
	return (NTSTATUS) HcWow64Syscall(sciProtectVirtualMemory, 5, (DWORD64) ProcessHandle, (DWORD64) BaseAddress, (DWORD64) NumberOfBytesToProtect, (DWORD64) NewAccessProtection, (DWORD64) OldAccessProtection);
}


NTSTATUS SYSCALLAPI HcReadVirtualMemory(CONST HANDLE ProcessHandle,
	CONST LPVOID BaseAddress,
	LPVOID Buffer,
	CONST SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead)
{
	return (NTSTATUS) HcWow64Syscall(sciReadVirtualMemory, 5, (DWORD64) ProcessHandle, (DWORD64) BaseAddress, (DWORD64) Buffer, (DWORD64) BufferSize, (DWORD64) NumberOfBytesRead);
}


NTSTATUS SYSCALLAPI HcWriteVirtualMemory(CONST HANDLE ProcessHandle,
	CONST LPVOID BaseAddress,
	CONST VOID *Buffer,
	CONST SIZE_T BufferSize,
	PSIZE_T NumberOfBytesWritten)
{
	return (NTSTATUS) HcWow64Syscall(sciWriteVirtualMemory, 5, (DWORD64) ProcessHandle, (DWORD64) BaseAddress, (DWORD64) Buffer, (DWORD64) BufferSize, (DWORD64) NumberOfBytesWritten);
}


NTSTATUS SYSCALLAPI HcQueryInformationProcess(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) LPVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength)
{
	return (NTSTATUS) HcWow64Syscall(sciQueryInformationProcess, 5, (DWORD64) ProcessHandle, (DWORD64) ProcessInformationClass, (DWORD64) ProcessInformation, (DWORD64) ProcessInformationLength, (DWORD64) ReturnLength);
}


NTSTATUS SYSCALLAPI HcQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) LPVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength)
{
	return (NTSTATUS) HcWow64Syscall(sciQuerySystemInformation, 4, (DWORD64) SystemInformationClass, (DWORD64) SystemInformation, (DWORD64) SystemInformationLength, (DWORD64) ReturnLength);
}


NTSTATUS SYSCALLAPI HcClose(HANDLE hObject)
{
	return (NTSTATUS) HcWow64Syscall(sciClose, 1, (DWORD64) hObject);
}


NTSTATUS SYSCALLAPI HcQueryVirtualMemory(IN HANDLE ProcessHandle,
	IN LPVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT LPVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength)
{
	return (NTSTATUS) HcWow64Syscall(sciQueryVirtualMemory, 6, (DWORD64) ProcessHandle, (DWORD64) BaseAddress, (DWORD64) MemoryInformationClass, (DWORD64) MemoryInformation, (DWORD64) MemoryInformationLength, (DWORD64) ReturnLength);
}

NTSTATUS SYSCALLAPI HcSetInformationThread(IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength)
{
	return (NTSTATUS) HcWow64Syscall(sciSetInformationThread, 4, (DWORD64) ThreadHandle, (DWORD64) ThreadInformationClass, (DWORD64) ThreadInformation, (DWORD64) ThreadInformationLength);
}


NTSTATUS SYSCALLAPI HcOpenDirectoryObject(OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	return (NTSTATUS) HcWow64Syscall(sciOpenDirectoryObject, 3, (DWORD64) DirectoryHandle, (DWORD64) DesiredAccess, (DWORD64) ObjectAttributes);
}


NTSTATUS SYSCALLAPI HcCreateThreadEx(OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	IN ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits,
	_In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList)
{
	return (NTSTATUS) HcWow64Syscall(sciCreateThreadEx, 11, (DWORD64) ThreadHandle, (DWORD64) DesiredAccess, (DWORD64) ObjectAttributes, (DWORD64) ProcessHandle, (DWORD64) StartRoutine, (DWORD64) Argument, (DWORD64) CreateFlags, (DWORD64) ZeroBits, (DWORD64) StackSize, (DWORD64) MaximumStackSize, (DWORD64) AttributeList);
}


NTSTATUS SYSCALLAPI HcWaitForSingleObject(IN HANDLE hObject,
	IN BOOLEAN bAlertable,
	IN PLARGE_INTEGER Timeout)
{
	return (NTSTATUS) HcWow64Syscall(sciWaitForSingleObject, 3, (DWORD64) hObject, (DWORD64) bAlertable, (DWORD64) Timeout);
}


NTSTATUS SYSCALLAPI HcWaitForMultipleObjects(IN ULONG ObjectCount,
	IN PHANDLE HandleArray,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER TimeOut OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciWaitForMultipleObjects, 5, (DWORD64) ObjectCount, (DWORD64) HandleArray, (DWORD64) WaitType, (DWORD64) Alertable, (DWORD64) TimeOut);
}


NTSTATUS SYSCALLAPI HcUnlockVirtualMemory(IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T NumberOfBytesToUnlock,
	IN ULONG MapType)
{
	return (NTSTATUS) HcWow64Syscall(sciUnlockVirtualMemory, 4, (DWORD64) ProcessHandle, (DWORD64) BaseAddress, (DWORD64) NumberOfBytesToUnlock, (DWORD64) MapType);
}



NTSTATUS SYSCALLAPI HcLockVirtualMemory(IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T NumberOfBytesToLock,
	IN ULONG MapType)
{
	return (NTSTATUS) HcWow64Syscall(sciLockVirtualMemory, 4, (DWORD64) ProcessHandle, (DWORD64) BaseAddress, (DWORD64) NumberOfBytesToLock, (DWORD64) MapType);
}


NTSTATUS SYSCALLAPI HcCreateFile(
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
)
{
	return (NTSTATUS) HcWow64Syscall(sciCreateFile, 11, (DWORD64) FileHandle, (DWORD64) DesiredAccess, (DWORD64) ObjectAttributes, (DWORD64) IoStatusBlock, (DWORD64) AllocationSize, (DWORD64) FileAttributes, (DWORD64) ShareAccess, (DWORD64) CreateDisposition, (DWORD64) CreateOptions, (DWORD64) EaBuffer, (DWORD64) EaLength);
}


NTSTATUS SYSCALLAPI HcQueryInformationFile(
	IN  HANDLE                 FileHandle,
	OUT PIO_STATUS_BLOCK       IoStatusBlock,
	OUT PVOID                  FileInformation,
	IN  ULONG                  Length,
	IN  FILE_INFORMATION_CLASS FileInformationClass
)
{
	return (NTSTATUS) HcWow64Syscall(sciQueryInformationFile, 5, (DWORD64) FileHandle, (DWORD64) IoStatusBlock, (DWORD64) FileInformation, (DWORD64) Length, (DWORD64) FileInformationClass);
}


NTSTATUS SYSCALLAPI HcQueryVolumeInformationFile(
	IN  HANDLE               FileHandle,
	OUT PIO_STATUS_BLOCK     IoStatusBlock,
	OUT PVOID                FsInformation,
	IN  ULONG                Length,
	IN  FS_INFORMATION_CLASS FsInformationClass
)
{
	return (NTSTATUS) HcWow64Syscall(sciQueryVolumeInformationFile, 5, (DWORD64) FileHandle, (DWORD64) IoStatusBlock, (DWORD64) FsInformation, (DWORD64) Length, (DWORD64) FsInformationClass);
}


NTSTATUS SYSCALLAPI HcQueryObject(
	IN  HANDLE                   Handle OPTIONAL,
	IN  OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID                    ObjectInformation OPTIONAL,
	IN  ULONG                    ObjectInformationLength,
	OUT PULONG                   ReturnLength OPTIONAL
)
{
	return (NTSTATUS) HcWow64Syscall(sciQueryObject, 5, (DWORD64) Handle, (DWORD64) ObjectInformationClass, (DWORD64) ObjectInformation, (DWORD64) ObjectInformationLength, (DWORD64) ReturnLength);
}


NTSTATUS SYSCALLAPI HcDuplicateObject(
	IN HANDLE      SourceProcessHandle,
	IN HANDLE      SourceHandle,
	IN HANDLE      TargetProcessHandle OPTIONAL,
	IN PHANDLE     TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG       HandleAttributes,
	IN ULONG       Options
)
{
	return (NTSTATUS) HcWow64Syscall(sciDuplicateObject, 7, (DWORD64) SourceProcessHandle, (DWORD64) SourceHandle, (DWORD64) TargetProcessHandle, (DWORD64) TargetHandle, (DWORD64) DesiredAccess, (DWORD64) HandleAttributes, (DWORD64) Options);
}


NTSTATUS SYSCALLAPI HcDelayExecution(IN BOOLEAN Alertable,
	IN PLARGE_INTEGER DelayInterval)
{
	return (NTSTATUS) HcWow64Syscall(sciDelayExecution, 2, (DWORD64) Alertable, (DWORD64) DelayInterval);
}


NTSTATUS SYSCALLAPI HcWriteFile(
	IN  HANDLE           FileHandle,
	IN	HANDLE           Event OPTIONAL,
	IN	PIO_APC_ROUTINE  ApcRoutine OPTIONAL,
	IN	PVOID            ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN  PVOID            Buffer,
	IN  ULONG            Length,
	IN	PLARGE_INTEGER   ByteOffset OPTIONAL,
	IN	PULONG           Key OPTIONAL
)
{
	return (NTSTATUS) HcWow64Syscall(sciWriteFile, 9, (DWORD64) FileHandle, (DWORD64) Event, (DWORD64) ApcRoutine, (DWORD64) ApcContext, (DWORD64) IoStatusBlock, (DWORD64) Buffer, (DWORD64) Length, (DWORD64) ByteOffset, (DWORD64) Key);
}


NTSTATUS SYSCALLAPI HcTerminateProcess(
	IN HANDLE   ProcessHandle OPTIONAL,
	IN NTSTATUS ExitStatus
)
{
	return (NTSTATUS) HcWow64Syscall(sciTerminateProcess, 2, (DWORD64) ProcessHandle, (DWORD64) ExitStatus);
}


NTSTATUS SYSCALLAPI HcDeviceIoControlFile(
	IN HANDLE DeviceHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE UserApcRoutine OPTIONAL,
	IN PVOID UserApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG IoControlCode,
	IN PVOID InputBuffer,
	IN ULONG InputBufferLength OPTIONAL,
	OUT PVOID OutputBuffer,
	IN ULONG OutputBufferLength OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciDeviceIoControlFile, 10, (DWORD64) DeviceHandle, (DWORD64) Event, (DWORD64) UserApcRoutine, (DWORD64) UserApcContext, (DWORD64) IoStatusBlock, (DWORD64) IoControlCode, (DWORD64) InputBuffer, (DWORD64) InputBufferLength, (DWORD64) OutputBuffer, (DWORD64) OutputBufferLength);
}


NTSTATUS SYSCALLAPI HcFsControlFile(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG FsControlCode,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength)
{
	return (NTSTATUS) HcWow64Syscall(sciFsControlFile, 10, (DWORD64) FileHandle, (DWORD64) Event, (DWORD64) ApcRoutine, (DWORD64) ApcContext, (DWORD64) IoStatusBlock, (DWORD64) FsControlCode, (DWORD64) InputBuffer, (DWORD64) InputBufferLength, (DWORD64) OutputBuffer, (DWORD64) OutputBufferLength);
}


NTSTATUS SYSCALLAPI HcCreateEvent(
	OUT PHANDLE            EventHandle,
	IN  ACCESS_MASK        DesiredAccess,
	IN	POBJECT_ATTRIBUTES ObjectAttributes,
	IN  EVENT_TYPE         EventType,
	IN  BOOLEAN            InitialState)
{
	return (NTSTATUS) HcWow64Syscall(sciCreateEvent, 5, (DWORD64) EventHandle, (DWORD64) DesiredAccess, (DWORD64) ObjectAttributes, (DWORD64) EventType, (DWORD64) InitialState);
}


NTSTATUS SYSCALLAPI HcCreateMutant(
	OUT PHANDLE            MutantHandle,
	IN  ACCESS_MASK        DesiredAccess,
	IN	POBJECT_ATTRIBUTES ObjectAttributes,
	IN  BOOLEAN            InitialOwner)
{
	return (NTSTATUS) HcWow64Syscall(sciCreateMutant, 4, (DWORD64) MutantHandle, (DWORD64) DesiredAccess, (DWORD64) ObjectAttributes, (DWORD64) InitialOwner);
}


NTSTATUS SYSCALLAPI HcOpenThreadToken(
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN BOOLEAN OpenAsSelf,
	OUT PHANDLE TokenHandle)
{
	return (NTSTATUS) HcWow64Syscall(sciOpenThreadToken, 4, (DWORD64) ThreadHandle, (DWORD64) DesiredAccess, (DWORD64) OpenAsSelf, (DWORD64) TokenHandle);
}


NTSTATUS SYSCALLAPI HcSetInformationFile(
	IN  HANDLE                 FileHandle,
	OUT PIO_STATUS_BLOCK       IoStatusBlock,
	IN  PVOID                  FileInformation,
	IN  ULONG                  Length,
	IN  FILE_INFORMATION_CLASS FileInformationClass)
{
	return (NTSTATUS) HcWow64Syscall(sciSetInformationFile, 5, (DWORD64) FileHandle, (DWORD64) IoStatusBlock, (DWORD64) FileInformation, (DWORD64) Length, (DWORD64) FileInformationClass);
}


NTSTATUS SYSCALLAPI HcReadFile(
	IN  HANDLE           FileHandle,
	IN  HANDLE           Event OPTIONAL,
	IN  PIO_APC_ROUTINE  ApcRoutine OPTIONAL,
	IN  PVOID            ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID            Buffer,
	IN  ULONG            Length,
	IN  PLARGE_INTEGER   ByteOffset OPTIONAL,
	IN  PULONG           Key OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciReadFile, 9, (DWORD64) FileHandle, (DWORD64) Event, (DWORD64) ApcRoutine, (DWORD64) ApcContext, (DWORD64) IoStatusBlock, (DWORD64) Buffer, (DWORD64) Length, (DWORD64) ByteOffset, (DWORD64) Key);
}


NTSTATUS SYSCALLAPI HcWow64QueryInformationProcess64(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation64,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciWow64QueryInformationProcess64, 5, (DWORD64) ProcessHandle, (DWORD64) ProcessInformationClass, (DWORD64) ProcessInformation64, (DWORD64) ProcessInformationLength, (DWORD64) ReturnLength);
}


NTSTATUS SYSCALLAPI HcWow64ReadVirtualMemory64(
	IN HANDLE ProcessHandle,
	IN PVOID64 BaseAddress OPTIONAL,
	IN PVOID Buffer,
	IN ULONG64 BufferSize,
	OUT PULONGLONG NumberOfBytesRead OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciWow64ReadVirtualMemory64, 5, (DWORD64) ProcessHandle, (DWORD64) BaseAddress, (DWORD64) Buffer, (DWORD64) BufferSize, (DWORD64) NumberOfBytesRead);
}


NTSTATUS SYSCALLAPI HcWow64WriteVirtualMemory64(
	IN HANDLE ProcessHandle,
	IN PVOID64 BaseAddress OPTIONAL,
	IN PVOID Buffer,
	IN ULONG64 BufferSize,
	OUT PULONG64 NumberOfBytesWritten OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciWow64WriteVirtualMemory64, 5, (DWORD64) ProcessHandle, (DWORD64) BaseAddress, (DWORD64) Buffer, (DWORD64) BufferSize, (DWORD64) NumberOfBytesWritten);
}


NTSTATUS SYSCALLAPI HcWow64AllocateVirtualMemory64(
	IN  HANDLE   ProcessHandle,
	IN  PULONG64 BaseAddress,
	IN  ULONG64  ZeroBits,
	IN  PULONG64 Size,
	IN  ULONG    AllocationType,
	IN  ULONG    Protection)
{
	return (NTSTATUS) HcWow64Syscall(sciWow64AllocateVirtualMemory64, 6, (DWORD64) ProcessHandle, (DWORD64) BaseAddress, (DWORD64) ZeroBits, (DWORD64) Size, (DWORD64) AllocationType, (DWORD64) Protection);
}


NTSTATUS SYSCALLAPI HcFlushBuffersFile(
	IN HANDLE hFile,
	OUT PIO_STATUS_BLOCK IoStatusBlock)
{
	return (NTSTATUS) HcWow64Syscall(sciFlushBuffersFile, 2, (DWORD64) hFile, (DWORD64) IoStatusBlock);
}


NTSTATUS SYSCALLAPI HcLoadDriver(
	IN PUNICODE_STRING DriverServiceName)
{
	return (NTSTATUS) HcWow64Syscall(sciLoadDriver, 1, (DWORD64) DriverServiceName);
}


NTSTATUS SYSCALLAPI HcUnloadDriver(
	IN PUNICODE_STRING DriverServiceName)
{
	return (NTSTATUS) HcWow64Syscall(sciUnloadDriver, 1, (DWORD64) DriverServiceName);
}


NTSTATUS SYSCALLAPI HcOpenKey(
	OUT PHANDLE            KeyHandle,
	IN  ACCESS_MASK        DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes)
{
	return (NTSTATUS) HcWow64Syscall(sciOpenKey, 3, (DWORD64) KeyHandle, (DWORD64) DesiredAccess, (DWORD64) ObjectAttributes);
}


NTSTATUS SYSCALLAPI HcOpenKeyEx(
	OUT PHANDLE            KeyHandle,
	IN  ACCESS_MASK        DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes,
	IN  ULONG              OpenOptions)
{
	return (NTSTATUS) HcWow64Syscall(sciOpenKeyEx, 4, (DWORD64) KeyHandle, (DWORD64) DesiredAccess, (DWORD64) ObjectAttributes, (DWORD64) OpenOptions);
}


NTSTATUS SYSCALLAPI HcQueryValueKey(
	IN      HANDLE                      KeyHandle,
	IN      PUNICODE_STRING             ValueName,
	IN      KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID                           KeyValueInformation OPTIONAL,
	IN      ULONG                       Length,
	OUT     PULONG                      ResultLength)
{
	return (NTSTATUS) HcWow64Syscall(sciQueryValueKey, 6, (DWORD64) KeyHandle, (DWORD64) ValueName, (DWORD64) KeyValueInformationClass, (DWORD64) KeyValueInformation, (DWORD64) Length, (DWORD64) ResultLength);
}


NTSTATUS SYSCALLAPI HcSetValueKey(
	IN     HANDLE          KeyHandle,
	IN     PUNICODE_STRING ValueName,
	IN 	 ULONG           TitleIndex OPTIONAL,
	IN     ULONG           Type,
	IN 	 PVOID           Data OPTIONAL,
	IN     ULONG           DataSize)
{
	return (NTSTATUS) HcWow64Syscall(sciSetValueKey, 6, (DWORD64) KeyHandle, (DWORD64) ValueName, (DWORD64) TitleIndex, (DWORD64) Type, (DWORD64) Data, (DWORD64) DataSize);
}


NTSTATUS SYSCALLAPI HcCreateKey(
	OUT      PHANDLE            KeyHandle,
	IN       ACCESS_MASK        DesiredAccess,
	IN       POBJECT_ATTRIBUTES ObjectAttributes,
	IN       ULONG              TitleIndex,
	IN   	   PUNICODE_STRING    Class OPTIONAL,
	IN       ULONG              CreateOptions,
	OUT  	   PULONG             Disposition OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciCreateKey, 7, (DWORD64) KeyHandle, (DWORD64) DesiredAccess, (DWORD64) ObjectAttributes, (DWORD64) TitleIndex, (DWORD64) Class, (DWORD64) CreateOptions, (DWORD64) Disposition);
}


NTSTATUS
SYSCALLAPI
HcGetContextThread(
	HANDLE ThreadHandle,
	PCONTEXT Context)
{
	return (NTSTATUS) HcWow64Syscall(sciGetContextThread, 2, (DWORD64) ThreadHandle, (DWORD64) Context);
}


NTSTATUS
SYSCALLAPI
HcSetContextThread(
	HANDLE ThreadHandle,
	PCONTEXT Context)
{
	return (NTSTATUS) HcWow64Syscall(sciSetContextThread, 2, (DWORD64) ThreadHandle, (DWORD64) Context);
}


NTSTATUS
SYSCALLAPI
HcSetDebugFilterState(
	ULONG ComponentId,
	ULONG Level,
	BOOLEAN State)
{
	return (NTSTATUS) HcWow64Syscall(sciSetDebugFilterState, 3, (DWORD64) ComponentId, (DWORD64) Level, (DWORD64) State);
}

NTSTATUS
SYSCALLAPI
HcCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags)
{
	return (NTSTATUS) HcWow64Syscall(sciCreateDebugObject, 4, (DWORD64) DebugObjectHandle, (DWORD64) DesiredAccess, (DWORD64) ObjectAttributes, (DWORD64) Flags);
}


#endif

NTSTATUS SYSCALLAPI HcResumeProcessWow64(CONST IN PTR_64(HANDLE) ProcessHandle)
{
	return (NTSTATUS) HcWow64Syscall(sciResumeProcess, 1, ProcessHandle);
}

NTSTATUS SYSCALLAPI HcSuspendProcessWow64(CONST IN PTR_64(HANDLE) ProcessHandle)
{
	return (NTSTATUS) HcWow64Syscall(sciSuspendProcess, 1, ProcessHandle);
}

NTSTATUS SYSCALLAPI HcOpenProcessTokenWow64(CONST IN PTR_64(HANDLE) hProcess,
	CONST IN ACCESS_MASK DesiredAccess,
	OUT PTR_64(PHANDLE) TokenHandle)
{
	return (NTSTATUS) HcWow64Syscall(sciOpenProcessToken, 3, hProcess, (DWORD64) DesiredAccess, TokenHandle);
}


NTSTATUS SYSCALLAPI HcWaitForSingleObjectWow64(IN PTR_64(HANDLE) hObject,
	IN BOOLEAN bAlertable,
	IN PTR_64(PLARGE_INTEGER) Timeout)
{
	return (NTSTATUS) HcWow64Syscall(sciWaitForSingleObject, 3, hObject, (DWORD64) bAlertable, Timeout);
}

NTSTATUS SYSCALLAPI HcDelayExecutionWow64(IN BOOLEAN Alertable,
	IN PTR_64(PLARGE_INTEGER) DelayInterval)
{
	return (NTSTATUS) HcWow64Syscall(sciDelayExecution, 2, (DWORD64) Alertable, DelayInterval);
}


NTSTATUS SYSCALLAPI HcAdjustPrivilegesTokenWow64(PTR_64(HANDLE) TokenHandle,
	BOOLEAN DisableAllPrivileges,
	PTR_64(PTOKEN_PRIVILEGES) NewState,
	DWORD BufferLength,
	PTR_64(PTOKEN_PRIVILEGES) PreviousState,
	PTR_64(PDWORD) ReturnLength)
{
	return (NTSTATUS) HcWow64Syscall(sciAdjustPrivilegesToken, 6, TokenHandle, (DWORD64) DisableAllPrivileges, NewState, (DWORD64) BufferLength, PreviousState, ReturnLength);
}

NTSTATUS SYSCALLAPI HcOpenProcessWow64(
	OUT PTR_64(PHANDLE)	ProcessHandle,
	CONST IN PTR_64(ACCESS_MASK) DesiredAccess,
	CONST IN PTR_64(POBJECT_ATTRIBUTES_WOW64) ObjectAttributes,
	IN PTR_64(PCLIENT_ID_WOW64) ClientId OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciOpenProcess, 4, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS SYSCALLAPI HcProtectVirtualMemoryWow64(CONST IN PTR_64(HANDLE) ProcessHandle,
	IN OUT PTR_64(PVOID*) BaseAddress,
	IN OUT PTR_64(PSIZE_T) NumberOfBytesToProtect,
	CONST IN ULONG NewAccessProtection,
	OUT PTR_64(PULONG) OldAccessProtection)
{
	return (NTSTATUS) HcWow64Syscall(sciProtectVirtualMemory, 5, ProcessHandle, BaseAddress, NumberOfBytesToProtect, (ULONG64) NewAccessProtection, OldAccessProtection);
}

NTSTATUS SYSCALLAPI HcQueryVirtualMemoryWow64(IN PTR_64(HANDLE) ProcessHandle,
	IN PTR_64(LPVOID) BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PTR_64(LPVOID) MemoryInformation,
	IN PTR_64(SIZE_T) MemoryInformationLength,
	OUT PTR_64(PSIZE_T) ReturnLength)
{
	return (NTSTATUS) HcWow64Syscall(sciQueryVirtualMemory, 6, ProcessHandle, BaseAddress, (DWORD64) MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

NTSTATUS SYSCALLAPI HcReadVirtualMemoryWow64(CONST PTR_64(HANDLE) ProcessHandle,
	CONST PTR_64(PVOID) BaseAddress,
	PTR_64(LPVOID) Buffer,
	CONST SIZE_T BufferSize,
	PTR_64(PSIZE_T) NumberOfBytesRead)
{
	return (NTSTATUS) HcWow64Syscall(sciReadVirtualMemory, 5, ProcessHandle, BaseAddress, Buffer, (ULONG64) BufferSize, NumberOfBytesRead);
}

NTSTATUS SYSCALLAPI HcWriteVirtualMemoryWow64(CONST PTR_64(HANDLE) ProcessHandle,
	CONST PTR_64(LPVOID) BaseAddress,
	CONST PTR_64(VOID*) Buffer,
	CONST SIZE_T BufferSize,
	PTR_64(PSIZE_T) NumberOfBytesWritten)
{
	return (NTSTATUS) HcWow64Syscall(sciWriteVirtualMemory, 5, ProcessHandle, BaseAddress, Buffer, (ULONG64) BufferSize, NumberOfBytesWritten);
}

NTSTATUS SYSCALLAPI HcFreeVirtualMemoryWow64(CONST IN PTR_64(HANDLE) hProcess,
	IN PTR_64(LPVOID*) UBaseAddress,
	IN PTR_64(PSIZE_T) URegionSize,
	CONST IN PTR_64(ULONG) FreeType)
{
	return (NTSTATUS) HcWow64Syscall(sciFreeVirtualMemory, 4, hProcess, UBaseAddress, URegionSize, FreeType);
}


NTSTATUS SYSCALLAPI HcAllocateVirtualMemoryWow64(CONST IN PTR_64(HANDLE) hProcess,
	IN PTR_64(LPVOID*) UBaseAddress,
	IN ULONG64 ZeroBits,
	IN OUT PTR_64(PSIZE_T) URegionSize,
	CONST IN PTR_64(ULONG) AllocationType,
	CONST IN PTR_64(ULONG) Protect)
{
	return (NTSTATUS) HcWow64Syscall(sciAllocateVirtualMemory, 6, hProcess, UBaseAddress, ZeroBits, URegionSize, AllocationType, Protect);
}

NTSTATUS SYSCALLAPI HcReadFileWow64(
	IN  PTR_64(HANDLE)			 FileHandle,
	IN  PTR_64(HANDLE)			 Event OPTIONAL,
	IN  PTR_64(PIO_APC_ROUTINE_WOW64)  ApcRoutine OPTIONAL,
	IN  PTR_64(PVOID)			 ApcContext OPTIONAL,
	OUT PTR_64(PIO_STATUS_BLOCK_WOW64) IoStatusBlock,
	OUT PTR_64(PVOID)            Buffer,
	IN  ULONG					 Length,
	IN  PTR_64(PLARGE_INTEGER)   ByteOffset OPTIONAL,
	IN  PTR_64(PULONG)           Key OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciReadFile, 9, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, (DWORD64) Length, ByteOffset, Key);
}

NTSTATUS SYSCALLAPI HcCreateFileWow64(
	OUT		 PTR_64(PHANDLE)			FileHandle,
	IN		 ACCESS_MASK				DesiredAccess,
	IN		 PTR_64(POBJECT_ATTRIBUTES_WOW64)	ObjectAttributes,
	OUT		 PTR_64(PIO_STATUS_BLOCK_WOW64)	IoStatusBlock,
	_In_opt_ PTR_64(PLARGE_INTEGER)     AllocationSize,
	IN		 ULONG						FileAttributes,
	IN		 ULONG						ShareAccess,
	IN		 ULONG						CreateDisposition,
	IN		 ULONG						CreateOptions,
	IN		 PTR_64(PVOID)				EaBuffer,
	IN		 ULONG						EaLength)
{
	return (NTSTATUS) HcWow64Syscall(sciCreateFile, 11, FileHandle, 
		(DWORD64) DesiredAccess,
		ObjectAttributes, 
		IoStatusBlock, 
		AllocationSize,
		(DWORD64) FileAttributes, 
		(DWORD64) ShareAccess, 
		(DWORD64) CreateDisposition, 
		(DWORD64) CreateOptions, 
		EaBuffer, 
		(DWORD64) EaLength);
}


NTSTATUS
SYSCALLAPI
HcCloseWow64(IN PTR_64(HANDLE) hObj)
{
	return (NTSTATUS) HcWow64Syscall(sciClose, 1, hObj);
}

NTSTATUS
SYSCALLAPI
HcCreateThreadExWow64(OUT PTR_64(PHANDLE) PtrThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN PTR_64(OBJECT_ATTRIBUTES_WOW64) PtrObjectAttributes OPTIONAL,
	IN PTR_64(HANDLE) ProcessHandle,
	IN PTR_64(PVOID) StartRoutine,
	IN PTR_64(PVOID) Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN PTR_64(ULONG_PTR) ZeroBits OPTIONAL,
	IN PTR_64(SIZE_T) StackSize OPTIONAL,
	IN PTR_64(SIZE_T) MaximumStackSize OPTIONAL,
	IN PTR_64(PVOID) AttributeList OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciCreateThreadEx, 11, PtrThreadHandle,
		(DWORD64) DesiredAccess,
		PtrObjectAttributes OPTIONAL,
		ProcessHandle,
		StartRoutine,
		Argument OPTIONAL,
		(DWORD64) CreateFlags,
		ZeroBits OPTIONAL,
		StackSize OPTIONAL,
		MaximumStackSize OPTIONAL,
		AttributeList OPTIONAL);
}

NTSTATUS SYSCALLAPI HcQuerySystemInformationWow64(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PTR_64(LPVOID) SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength)
{
	return (NTSTATUS) HcWow64Syscall(sciQuerySystemInformation, 4, (DWORD64) SystemInformationClass, SystemInformation, (DWORD64) SystemInformationLength, (DWORD64) ReturnLength);
}

NTSTATUS SYSCALLAPI HcOpenDirectoryObjectWow64(OUT PTR_64(PHANDLE) DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN PTR_64(POBJECT_ATTRIBUTES_WOW64) ObjectAttributes)
{
	return (NTSTATUS) HcWow64Syscall(sciOpenDirectoryObject, 3, DirectoryHandle, (DWORD64) DesiredAccess, ObjectAttributes);
}

NTSTATUS SYSCALLAPI HcOpenSymbolicLinkObjectWow64(OUT PTR_64(PHANDLE) LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN PTR_64(POBJECT_ATTRIBUTES_WOW64) ObjectAttributes)
{
	return (NTSTATUS) HcWow64Syscall(sciOpenSymbolicLinkObject, 3, LinkHandle, (DWORD64) DesiredAccess, ObjectAttributes);
}

NTSTATUS SYSCALLAPI HcQuerySymbolicLinkObjectWow64(IN PTR_64(HANDLE) LinkHandle,
	OUT PTR_64(PUNICODE_STRING64) LinkTarget,
	OUT PTR_64(PULONG) ResultLength OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciQuerySymbolicLinkObject, 3, LinkHandle, LinkTarget, ResultLength);
}

NTSTATUS SYSCALLAPI HcQueryDirectoryObjectWow64(IN PTR_64(HANDLE) DirectoryHandle,
	OUT PTR_64(VOID) Buffer,
	IN ULONG BufferLength,
	IN BOOLEAN ReturnSingleEntry,
	IN BOOLEAN RestartScan,
	IN OUT PTR_64(PULONG) Context,
	OUT PTR_64(PULONG) ReturnLength OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciQueryDirectoryObject, 7, DirectoryHandle, Buffer, (DWORD64) BufferLength, (DWORD64) ReturnSingleEntry, (DWORD64) RestartScan, Context, ReturnLength);
}

NTSTATUS SYSCALLAPI HcQueryInformationProcessWow64(
	IN PTR_64(HANDLE) ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PTR_64(LPVOID) ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PTR_64(PULONG) ReturnLength OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciQueryInformationProcess, 5, ProcessHandle, (DWORD64) ProcessInformationClass, ProcessInformation, (DWORD64) ProcessInformationLength, ReturnLength);
}

NTSTATUS SYSCALLAPI HcFlushInstructionCacheWow64(CONST IN PTR_64(HANDLE) ProcessHandle,
	CONST IN PTR_64(LPVOID) BaseAddress,
	CONST IN SIZE_T NumberOfBytesToFlush)
{
	return (NTSTATUS) HcWow64Syscall(sciFlushInstructionCache, 3, ProcessHandle, BaseAddress, (DWORD64) NumberOfBytesToFlush);
}

#ifndef _WIN64
#include <windows.h> /* this shouldn't include any libraries. */

union reg64 {
	unsigned long dw[2];
	unsigned long long v;
};

// warning C4409: illegal instruction size
#pragma warning(disable : 4409)
DWORD64 X64SyscallV(int idx, int argC, va_list args)
{
	/* grab the first four arguments to accompany the x86_64 calling convention. */
	DWORD64 _rcx = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _rdx = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _r8 = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _r9 = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	union reg64 _rax;
	DWORD32 _idx = idx;
	_rax.v = 0;

	DWORD64 restArgs = (DWORD64) &va_arg(args, DWORD64);

	/* easier use in inline assembly. */
	DWORD64 _argC = argC;
	DWORD back_esp = 0;

	__asm
	{
		/* save the esp. */
		mov    back_esp, esp

		/* align esp to prepare for the 64bit rsp conversion. */
		and esp, 0xFFFFFFF8

		X64_Start();

		/* x86_64 calling convention. first 4 arguments go into rcx, rdx, r8, r9 */
		push _rcx
		X64_Pop(_RCX);
		push _rdx
		X64_Pop(_RDX);
		push _r8
		X64_Pop(_R8);
		push _r9
		X64_Pop(_R9);

		push edi

		push restArgs
		X64_Pop(_RDI);

		push _argC
		X64_Pop(_RAX);

		/* put rest of arguments on the stack */
		test eax, eax
		jz _ls_e
		lea edi, dword ptr[edi + 8 * eax - 8]

	_ls:
		test eax, eax
		jz _ls_e
		push dword ptr[edi]
		sub edi, 8
		sub eax, 1
		jmp _ls

	_ls_e :
		/* create stack space for spilling registers */
		sub esp, 0x28

		mov eax, _idx
		push _rcx
		X64_Pop(_R10);
		e(0x0F) e(0x05); /* syscall */

		/* cleanup stack */
		push   _argC
		X64_Pop(_RCX);
		lea    esp, dword ptr[esp + 8 * ecx + 0x20]
		pop    edi

		/* set return value */
		X64_Push(_RAX);
		pop _rax.dw[0]
		X64_End();

		mov    esp, back_esp
	}

	return _rax.v;
}

DWORD64
SYSCALLAPI
HcWow64Syscall(int idx, int argC, ...)
{
	va_list args;
	va_start(args, argC);

	return X64SyscallV(idx, argC, args);
}
#pragma warning(default : 4409)
#else

DWORD64
SYSCALLAPI
HcWow64Syscall(int idx, int argC, ...)
{
	return STATUS_NOT_IMPLEMENTED;
}

#endif /* not _win64 */

