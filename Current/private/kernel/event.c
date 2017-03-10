#include <highcall.h>

DECL_EXTERN_API(HANDLE, EventCreateW,
	IN LPSECURITY_ATTRIBUTES lpEventAttributes OPTIONAL,
	IN BOOL bManualReset,
	IN BOOL bInitialState,
	IN LPCWSTR lpName OPTIONAL)
{                                                                        
	NTSTATUS Status;                                                            
	HANDLE Handle = NULL;                                                              
	UNICODE_STRING ObjectName;                                                  
	OBJECT_ATTRIBUTES LocalAttributes;                                          
	POBJECT_ATTRIBUTES ObjectAttributes = &LocalAttributes;
      
	if (lpName)
	{
		RtlInitUnicodeString(&ObjectName, lpName);
	}
    
	ObjectAttributes = HcUtilFormatObjectAttributes(
		&LocalAttributes,                  
		lpEventAttributes,                                 
		lpName ? &ObjectName : NULL); 

    Status = HcCreateEvent(
		&Handle,
		EVENT_ALL_ACCESS, 		
		ObjectAttributes,	
		bManualReset ? NotificationEvent : SynchronizationEvent, 			
		bInitialState);

    if (NT_SUCCESS(Status))                                                     
    {    
		if (Status == STATUS_OBJECT_NAME_EXISTS)
		{
			SetLastError(ERROR_ALREADY_EXISTS);
		}
		else
		{
			HcErrorSetDosError(ERROR_SUCCESS);
		}
        return Handle;
    }

	HcErrorSetNtStatus(Status);                                                 
    return NULL;          
}


DECL_EXTERN_API(HANDLE, EventCreateA,
	IN LPSECURITY_ATTRIBUTES lpEventAttributes OPTIONAL,
	IN BOOL bManualReset,
	IN BOOL bInitialState,
	IN LPCSTR lpName OPTIONAL)
{
	LPWSTR lpConverted;
	HANDLE hReturn = NULL;

	if (lpName)
	{
		lpConverted = HcStringConvertAtoW(lpName);
		if (lpConverted)
		{
			hReturn = HcEventCreateW(lpEventAttributes, bManualReset, bInitialState, lpConverted);
			HcFree(lpConverted);
		}
	}
	else
	{
		hReturn = HcEventCreateW(lpEventAttributes, bManualReset, bInitialState, NULL);
	}

	return hReturn;
}