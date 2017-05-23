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
	return NT_SUCCESS(HcResumeThread(hThread, NULL));
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