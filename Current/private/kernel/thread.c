#include <highcall.h>

DECL_EXTERN_API(DWORD, ThreadCurrentId)
{
	return HandleToUlong(NtCurrentTeb()->ClientId.UniqueThread);
}

DECL_EXTERN_API(HANDLE, ThreadOpen, IN DWORD dwThreadId, IN DWORD dwDesiredAccess)
{
	NTSTATUS Status;
	HANDLE ThreadHandle;
	OBJECT_ATTRIBUTES ObjectAttributes;
	CLIENT_ID ClientId;

	ClientId.UniqueProcess = 0;
	ClientId.UniqueThread = ULongToHandle(dwThreadId);

	InitializeObjectAttributes(&ObjectAttributes,
		NULL,
		0 /* no inheritance */,
		NULL,
		NULL);

	Status = HcOpenThread(&ThreadHandle,
		dwDesiredAccess,
		&ObjectAttributes,
		&ClientId);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return NULL;
	}

	return ThreadHandle;
}

DECL_EXTERN_API(BOOLEAN, ThreadExitCode, IN CONST HANDLE hThread, OUT PULONG lpExitCode)
{
	THREAD_BASIC_INFORMATION ThreadBasic;
	NTSTATUS Status;

	ZERO(&ThreadBasic);

	Status = HcQueryInformationThread(hThread,
		ThreadBasicInformation,
		&ThreadBasic,
		sizeof(THREAD_BASIC_INFORMATION),
		NULL);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	*lpExitCode = ThreadBasic.ExitStatus;
	return TRUE;
}

DECL_EXTERN_API(DWORD, ThreadSuspend, IN HANDLE hThread)
{
	ULONG PreviousSuspendCount;
	NTSTATUS Status;

	Status = HcSuspendThread(hThread, &PreviousSuspendCount);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return -1;
	}

	return PreviousSuspendCount;
}

DECL_EXTERN_API(BOOLEAN, ThreadResume, IN HANDLE hThread)
{
	ULONG SuspendCount = 0;
	NTSTATUS Return = HcResumeThread(hThread, &SuspendCount);

	for (DWORD i = 0; i < SuspendCount; i++)
		HcResumeThread(hThread, NULL);

	return NT_SUCCESS(Return);
}

DECL_EXTERN_API(BOOLEAN, ThreadGetContext, HANDLE hThread, LPCONTEXT lpContext)
{
	NTSTATUS Status;
	BOOLEAN Result;

	Status = HcGetContextThread(hThread, lpContext);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		Result = FALSE;
	}
	else
	{
		Result = TRUE;
	}

	return Result;
}

DECL_EXTERN_API(BOOLEAN, ThreadSetContext, HANDLE hThread, LPCONTEXT lpContext)
{
	NTSTATUS Status;
	BOOLEAN Result;

	Status = HcSetContextThread(hThread, lpContext);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		Result = FALSE;
	}
	else
	{
		Result = TRUE;
	}

	return Result;
}

DECL_EXTERN_API(BOOLEAN, ThreadGetAllThreadIds, DWORD ProcessId, DWORD* ThreadList, DWORD* dwThreadListCount)
{
	DWORD ReturnLength = 0;
	LPVOID Buffer;
	PSYSTEM_PROCESS_INFORMATION pSysList;
	NTSTATUS Status;
	LPVOID SystemInformation64 = NULL;

	if (ThreadList == NULL || dwThreadListCount == NULL || *dwThreadListCount == 0)
	{
		return FALSE;
	}

	Status = HcQuerySystemInformationInternal(SystemProcessInformation, NULL, 0, &ReturnLength, &SystemInformation64);
	if (Status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return FALSE;
	}

	Buffer = HcAlloc(ReturnLength);

	for (;;)
	{
		/* Query the process list. */
		Status = HcQuerySystemInformationInternal(SystemProcessInformation, Buffer, ReturnLength, &ReturnLength, &SystemInformation64);
		if (Status != STATUS_INFO_LENGTH_MISMATCH)
		{
			break;
		}
		else
		{
			ReturnLength += 0xffff;

			HcFree(Buffer);
			Buffer = HcAlloc(ReturnLength);
		}
	}

	pSysList = (PSYSTEM_PROCESS_INFORMATION) Buffer;

	/* Loop through the process list */
	while (TRUE)
	{
		if ((DWORD) (DWORD_PTR) pSysList->UniqueProcessId == ProcessId)
		{
			if (*dwThreadListCount < pSysList->NumberOfThreads)
			{
				Status = STATUS_INSUFFICIENT_RESOURCES;
				goto done;
			}

			*dwThreadListCount = pSysList->NumberOfThreads;

			for (DWORD i = 0; i < pSysList->NumberOfThreads; i++)
			{
				ThreadList[i] = (DWORD) (DWORD_PTR) pSysList->Threads[i].ClientId.UniqueThread;
			}

			goto done;
		}

		if (!pSysList->NextEntryOffset)
		{
			break;
		}

		/* Calculate the next entry address */
		pSysList = (PSYSTEM_PROCESS_INFORMATION) ((SIZE_T) pSysList + pSysList->NextEntryOffset);
	}

done:
	HcFree(Buffer);
	return NT_SUCCESS(Status);
}

//
// Selector Names
//
#define RPL_MASK                0x0003
#define MODE_MASK               0x0001
#define KGDT_R0_CODE            0x8
#define KGDT_R0_DATA            0x10
#define KGDT_R3_CODE            0x18
#define KGDT_R3_DATA            0x20
#define KGDT_TSS                0x28
#define KGDT_R0_PCR             0x30
#define KGDT_R3_TEB             0x38
#define KGDT_LDT                0x48
#define KGDT_DF_TSS             0x50
#define KGDT_NMI_TSS            0x58

//
// EFlags
//
#define EFLAGS_CF               0x01L
#define EFLAGS_ZF               0x40L
#define EFLAGS_TF               0x100L
#define EFLAGS_INTERRUPT_MASK   0x200L
#define EFLAGS_DF               0x400L
#define EFLAGS_IOPL             0x3000L
#define EFLAGS_NESTED_TASK      0x4000L
#define EFLAGS_RF               0x10000
#define EFLAGS_V86_MASK         0x20000
#define EFLAGS_ALIGN_CHECK      0x40000
#define EFLAGS_VIF              0x80000
#define EFLAGS_VIP              0x100000
#define EFLAGS_ID               0x200000
#define EFLAGS_USER_SANITIZE    0x3F4DD7
#define EFLAG_SIGN              0x8000
#define EFLAG_ZERO              0x4000

#define ROUND_DOWN(n, align) (((ULONG)n) & ~((align) - 1l))
#define ROUND_UP(n,align) ROUND_DOWN(((ULONG) n) + (align) -1, (align))


/*
* @implemented
*/
VOID
NTAPI
RtlInitializeContext(IN HANDLE ProcessHandle,
	OUT PCONTEXT ThreadContext,
	IN PVOID ThreadStartParam  OPTIONAL,
	IN PTHREAD_START_ROUTINE ThreadStartAddress,
	IN PINITIAL_TEB InitialTeb)
{
#ifndef _WIN64
	/*
	* Set the Initial Registers
	* This is based on NT's default values -- crazy apps might expect this...
	*/
	ThreadContext->Ebp = 0;
	ThreadContext->Eax = 0;
	ThreadContext->Ebx = 1;
	ThreadContext->Ecx = 2;
	ThreadContext->Edx = 3;
	ThreadContext->Esi = 4;
	ThreadContext->Edi = 5;

	/* Set the Selectors */
	ThreadContext->SegGs = 0;
	ThreadContext->SegFs = KGDT_R3_TEB;
	ThreadContext->SegEs = KGDT_R3_DATA;
	ThreadContext->SegDs = KGDT_R3_DATA;
	ThreadContext->SegSs = KGDT_R3_DATA;
	ThreadContext->SegCs = KGDT_R3_CODE;

	/* Enable Interrupts */
	ThreadContext->EFlags = EFLAGS_INTERRUPT_MASK;

	/* Settings passed */
	ThreadContext->Eip = (ULONG) ThreadStartAddress;
	ThreadContext->Esp = (ULONG) InitialTeb;

	/* Only the basic Context is initialized */
	ThreadContext->ContextFlags = CONTEXT_CONTROL |
		CONTEXT_INTEGER |
		CONTEXT_SEGMENTS;

	/* Set up ESP to the right value */
	ThreadContext->Esp -= sizeof(PVOID);
	HcWriteVirtualMemory(ProcessHandle,
		(PVOID) ThreadContext->Esp,
		(PVOID) &ThreadStartParam,
		sizeof(PVOID),
		NULL);

	/* Push it down one more notch for RETEIP */
	ThreadContext->Esp -= sizeof(PVOID);
#else
	/*
	* Set the Initial Registers
	* This is based on NT's default values -- crazy apps might expect this...
	*/
	ThreadContext->Rbp = 0;
	ThreadContext->Rax = 0;
	ThreadContext->Rbx = 1;
	ThreadContext->Rcx = 2;
	ThreadContext->Rdx = 3;
	ThreadContext->Rsi = 4;
	ThreadContext->Rdi = 5;

	/* Set the Selectors */
	ThreadContext->SegGs = 0;
	ThreadContext->SegFs = KGDT_R3_TEB;
	ThreadContext->SegEs = KGDT_R3_DATA;
	ThreadContext->SegDs = KGDT_R3_DATA;
	ThreadContext->SegSs = KGDT_R3_DATA;
	ThreadContext->SegCs = KGDT_R3_CODE;

	/* Enable Interrupts */
	ThreadContext->EFlags = EFLAGS_INTERRUPT_MASK;

	/* Settings passed */
	ThreadContext->Rip = (ULONG_PTR) ThreadStartAddress;
	ThreadContext->Rsp = (ULONG_PTR) InitialTeb;

	/* Only the basic Context is initialized */
	ThreadContext->ContextFlags = CONTEXT_CONTROL |
		CONTEXT_INTEGER |
		CONTEXT_SEGMENTS;

	/* Set up ESP to the right value */
	ThreadContext->Rsp -= sizeof(PVOID);
	HcWriteVirtualMemory(ProcessHandle,
		(PVOID) ThreadContext->Rsp,
		(PVOID) &ThreadStartParam,
		sizeof(PVOID),
		NULL);

	/* Push it down one more notch for RETEIP */
	ThreadContext->Rsp -= sizeof(PVOID);
#endif
}

NTSTATUS
NTAPI
RtlpCreateUserStack(IN HANDLE hProcess,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN ULONG StackZeroBits OPTIONAL,
	OUT PINITIAL_TEB InitialTeb)
{
	NTSTATUS Status;
	SYSTEM_BASIC_INFORMATION SystemBasicInfo;
	PIMAGE_NT_HEADERS Headers;
	ULONG_PTR Stack = 0;
	BOOLEAN UseGuard = FALSE;
	ULONG Dummy;
	SIZE_T GuardPageSize;

	/* Get some memory information */
	Status = HcQuerySystemInformation(SystemBasicInformation,
		&SystemBasicInfo,
		sizeof(SYSTEM_BASIC_INFORMATION),
		NULL);
	if (!NT_SUCCESS(Status)) return Status;

	/* Use the Image Settings if we are dealing with the current Process */
	if (hProcess == NtCurrentProcess())
	{
		/* Get the Image Headers */
		Headers = HcImageGetNtHeader(NtCurrentPeb()->ImageBaseAddress);
		if (!Headers) return STATUS_INVALID_IMAGE_FORMAT;

		/* If we didn't get the parameters, find them ourselves */
		if (!StackReserve) StackReserve = Headers->OptionalHeader.
			SizeOfStackReserve;
		if (!StackCommit) StackCommit = Headers->OptionalHeader.
			SizeOfStackCommit;
	}
	else
	{
		/* Use the System Settings if needed */
		if (!StackReserve) StackReserve = SystemBasicInfo.AllocationGranularity;
		if (!StackCommit) StackCommit = SystemBasicInfo.PageSize;
	}

	/* Check if the commit is higher than the reserve*/
	if (StackCommit >= StackReserve)
	{
		/* Grow the reserve beyond the commit, up to 1MB alignment */
		StackReserve = ROUND_UP(StackCommit, 1024 * 1024);
	}

	/* Align everything to Page Size */
	StackReserve = ROUND_UP(StackReserve, SystemBasicInfo.AllocationGranularity);
	StackCommit = ROUND_UP(StackCommit, SystemBasicInfo.PageSize);

	/* Reserve memory for the stack */
	Status = HcAllocateVirtualMemory(hProcess,
		(PVOID*) &Stack,
		StackZeroBits,
		&StackReserve,
		MEM_RESERVE,
		PAGE_READWRITE);

	if (!NT_SUCCESS(Status)) return Status;

	/* Now set up some basic Initial TEB Parameters */
	InitialTeb->PreviousStackBase = NULL;
	InitialTeb->PreviousStackLimit = NULL;
	InitialTeb->AllocatedStackBase = (PVOID) Stack;
	InitialTeb->StackBase = (PVOID) (Stack + StackReserve);

	/* Update the Stack Position */
	Stack += StackReserve - StackCommit;

	/* Check if we will need a guard page */
	if (StackReserve > StackCommit)
	{
		/* Remove a page to set as guard page */
		Stack -= SystemBasicInfo.PageSize;
		StackCommit += SystemBasicInfo.PageSize;
		UseGuard = TRUE;
	}

	/* Allocate memory for the stack */
	Status = HcAllocateVirtualMemory(hProcess,
		(PVOID*) &Stack,
		0,
		&StackCommit,
		MEM_COMMIT,
		PAGE_READWRITE);

	if (!NT_SUCCESS(Status)) return Status;

	/* Now set the current Stack Limit */
	InitialTeb->StackLimit = (PVOID) Stack;

	/* Create a guard page */
	if (UseGuard)
	{
		/* Attempt maximum space possible */
		GuardPageSize = SystemBasicInfo.PageSize;
		Status = HcProtectVirtualMemory(hProcess,
			(PVOID*) &Stack,
			&GuardPageSize,
			PAGE_GUARD | PAGE_READWRITE,
			&Dummy);
		if (!NT_SUCCESS(Status)) return Status;

		/* Update the Stack Limit keeping in mind the Guard Page */
		InitialTeb->StackLimit = (PVOID) ((ULONG_PTR) InitialTeb->StackLimit +
			GuardPageSize);
	}

	/* We are done! */
	return STATUS_SUCCESS;
}

/*
 @implemented
*/
NTSTATUS
NTAPI
RtlCreateUserThread(IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN PTHREAD_START_ROUTINE StartAddress,
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT PCLIENT_ID ClientId OPTIONAL)
{
	NTSTATUS Status;
	HANDLE Handle;
	CLIENT_ID ThreadCid;
	INITIAL_TEB InitialTeb;
	OBJECT_ATTRIBUTES ObjectAttributes;
	CONTEXT Context;

	/* First, we'll create the Stack */
	Status = RtlpCreateUserStack(ProcessHandle,
		StackReserve,
		StackCommit,
		StackZeroBits,
		&InitialTeb);
	if (!NT_SUCCESS(Status)) return Status;

	/* Next, we'll set up the Initial Context */
	RtlInitializeContext(ProcessHandle,
		&Context,
		Parameter,
		StartAddress,
		InitialTeb.StackBase);

	/* We are now ready to create the Kernel Thread Object */
	InitializeObjectAttributes(&ObjectAttributes,
		NULL,
		0,
		NULL,
		SecurityDescriptor);
	Status = HcCreateThread(&Handle,
		THREAD_ALL_ACCESS,
		&ObjectAttributes,
		ProcessHandle,
		&ThreadCid,
		&Context,
		&InitialTeb,
		CreateSuspended);
	if (!NT_SUCCESS(Status))
	{
		/* Free the stack */
		//RtlpFreeUserStack(ProcessHandle, &InitialTeb);
	}
	else
	{
		/* Return thread data */
		if (ThreadHandle)
			*ThreadHandle = Handle;
		else
			HcClose(Handle);
		if (ClientId) *ClientId = ThreadCid;
	}

	/* Return success or the previous failure */
	return Status;
}