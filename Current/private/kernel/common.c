#include <highcall.h>

#include "../sys/syscall.h"

DECL_EXTERN_API(VOID, Sleep, CONST IN DWORD dwMilliseconds)
{
	LARGE_INTEGER Time;
	PLARGE_INTEGER TimePtr;
	NTSTATUS Status;

	ZERO(&Time);

	/* Convert the timeout */
	TimePtr = HcObjectMillisecondsToNano(&Time, dwMilliseconds);
	if (!TimePtr)
	{
		/* Turn an infinite wait into a really long wait */
		Time.LowPart = 0;
		Time.HighPart = 0x80000000;
		TimePtr = &Time;
	}

	/* Do the delay */
	if (HcGlobal.IsWow64)
	{
		Status = HcDelayExecutionWow64(FALSE, (ULONG64) TimePtr);
	}
	else
	{
		Status = HcDelayExecution(FALSE, TimePtr);
	}

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
	}
}
