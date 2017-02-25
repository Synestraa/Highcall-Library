#include <highcall.h>

#include "../sys/syscall.h"

#define WAIT_IO_COMPLETION 0xC0

HC_EXTERN_API VOID HCAPI HcSleep(CONST IN DWORD dwMilliseconds)
{
	LARGE_INTEGER Time;
	PLARGE_INTEGER TimePtr;
	NTSTATUS Status;

	HcInternalSet(&Time, 0, sizeof(Time));

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
	Status = HcDelayExecution(FALSE, TimePtr);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
	}
}
