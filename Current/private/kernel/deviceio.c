#include <highcall.h>

DECL_EXTERN_API(BOOLEAN, DeviceIoControl,
	IN HANDLE hDevice, 
	IN DWORD dwIoControlCode, 
	IN LPVOID lpInBuffer OPTIONAL, 
	IN DWORD nInBufferSize OPTIONAL,
	OUT LPVOID lpOutBuffer OPTIONAL,
	IN DWORD nOutBufferSize OPTIONAL, 
	OUT PULONG_PTR lpBytesReturned OPTIONAL, 
	IN LPOVERLAPPED lpOverlapped OPTIONAL)
{
	BOOL FsIoCtl;
	NTSTATUS Status;
	PVOID ApcContext;
	IO_STATUS_BLOCK Iosb;

	/* Check what kind of IOCTL to send */
	FsIoCtl = ((dwIoControlCode >> 16) == FILE_DEVICE_FILE_SYSTEM);

	/* CHeck for async */
	if (lpOverlapped != NULL)
	{
		/* Set pending status */
		lpOverlapped->Internal = STATUS_PENDING;

		/* Check if there's an APC context */
		ApcContext = (((ULONG_PTR) lpOverlapped->hEvent & 0x1) ? NULL : lpOverlapped);

		/* Send file system control? */
		if (FsIoCtl)
		{
			/* Send it */
			Status = HcFsControlFile(hDevice,
				lpOverlapped->hEvent,
				NULL,
				ApcContext,
				(PIO_STATUS_BLOCK) lpOverlapped,
				dwIoControlCode,
				lpInBuffer,
				nInBufferSize,
				lpOutBuffer,
				nOutBufferSize);
		}
		else
		{
			/* Otherwise send a device control */
			Status = HcDeviceIoControlFile(hDevice,
				lpOverlapped->hEvent,
				NULL,
				ApcContext,
				(PIO_STATUS_BLOCK) lpOverlapped,
				dwIoControlCode,
				lpInBuffer,
				nInBufferSize,
				lpOutBuffer,
				nOutBufferSize);
		}

		/* Check for or information instead of failure */
		if (!(NT_SUCCESS(Status)) && (lpBytesReturned))
		{
			/* @TODO: Protect with SEH */

			/* Return the bytes */
			*lpBytesReturned = lpOverlapped->InternalHigh;
		}

		/* Now check for any kind of failure except pending*/
		if (!(NT_SUCCESS(Status)) || (Status == STATUS_PENDING))
		{
			/* Fail */
			HcErrorSetNtStatus(Status);
			return FALSE;
		}
	}
	else /* Blocking */
	{
		/* Send file system code? */
		if (FsIoCtl)
		{
			/* Do it */
			Status = HcFsControlFile(hDevice,
				NULL,
				NULL,
				NULL,
				&Iosb,
				dwIoControlCode,
				lpInBuffer,
				nInBufferSize,
				lpOutBuffer,
				nOutBufferSize);
		}
		else
		{
			/* Send device code instead */
			Status = HcDeviceIoControlFile(hDevice,
				NULL,
				NULL,
				NULL,
				&Iosb,
				dwIoControlCode,
				lpInBuffer,
				nInBufferSize,
				lpOutBuffer,
				nOutBufferSize);
		}

		/* Now check if the operation isn't done yet */
		if (Status == STATUS_PENDING)
		{
			/* Wait for it and get the final status */
			Status = HcWaitForSingleObject(hDevice, FALSE, NULL);
			if (NT_SUCCESS(Status)) Status = Iosb.Status;
		}

		/* Check for success */
		if (NT_SUCCESS(Status))
		{
			/* Return the byte count */
			*lpBytesReturned = Iosb.Information;
		}
		else
		{
			/* Check for informational or warning failure */
			if (!NT_SUCCESS(Status))
			{
				*lpBytesReturned = Iosb.Information;
			}

			/* Return a failure */
			HcErrorSetNtStatus(Status);
			return FALSE;
		}
	}

	/* Return success */
	return TRUE;
}