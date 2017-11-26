#include <highcall.h>
#include "../sys/syscall.h"

#define STD_INPUT_HANDLE    ((DWORD)-10)
#define STD_OUTPUT_HANDLE   ((DWORD)-11)
#define STD_ERROR_HANDLE    ((DWORD)-12)

#define WAIT_FAILED ((DWORD)0xFFFFFFFF)

typedef struct _ObjectTypePair
{
	LPWSTR Name;
	DWORD Index;
} ObjectTypePair;

static ObjectTypePair** _baseObjectTypePairs;
static DWORD _baseObjectTypeAmount = 0;

static VOID _baseInitObjectTypes(VOID)
{
	ULONG RequiredLength = 0xffff;
	UCHAR  KeyType = 0;
	NTSTATUS Status;
	POBJECT_TYPES_INFORMATION Types;

	_baseObjectTypeAmount = 0;

	Types = (OBJECT_TYPES_INFORMATION*)HcAlloc(RequiredLength);
	while ((Status = HcQueryObject(NULL, ObjectTypesInformation, Types, RequiredLength, &RequiredLength)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		HcFree(Types);
		Types = (OBJECT_TYPES_INFORMATION*)HcAlloc(RequiredLength);
	}

	if (NT_SUCCESS(Status))
	{
		_baseObjectTypeAmount = Types->NumberOfTypes;
		_baseObjectTypePairs = (ObjectTypePair**)HcAlloc(_baseObjectTypeAmount * sizeof(ObjectTypePair*));

		POBJECT_TYPE_INFORMATION type = (POBJECT_TYPE_INFORMATION)((PCHAR)Types + ALIGN_UP(sizeof(*Types), ULONG_PTR));
		for (DWORD i = 0; i < Types->NumberOfTypes; i++)
		{
			_baseObjectTypePairs[i] = (ObjectTypePair*)HcAlloc(sizeof(ObjectTypePair));
			_baseObjectTypePairs[i]->Index = i + 2;
			
			if (type->TypeName.Buffer != NULL)
			{
				_baseObjectTypePairs[i]->Name = HcStringAllocW(type->TypeName.Length);

				HcStringCopyW(_baseObjectTypePairs[i]->Name,
					type->TypeName.Buffer,
					type->TypeName.Length / sizeof(WCHAR));
			}

			type = (POBJECT_TYPE_INFORMATION)((PCHAR)(type + 1) + ALIGN_UP(type->TypeName.MaximumLength, ULONG_PTR));
		}
	}

	HcFree(Types);
}

DECL_EXTERN_API(HANDLE, ObjectTranslateHandle, CONST IN HANDLE Handle)
{
	PRTL_USER_PROCESS_PARAMETERS Ppb = NtCurrentPeb()->ProcessParameters;
	
	switch (HandleToUlong(Handle))
	{
		case STD_INPUT_HANDLE:  return Ppb->StandardInput;
		case STD_OUTPUT_HANDLE: return Ppb->StandardOutput;
		case STD_ERROR_HANDLE:  return Ppb->StandardError;
	}
	
	return Handle;
}

DECL_EXTERN_API(DWORD, ObjectTypeIndexByName, IN LPCWSTR lpObjectName)
{
	DWORD typeIndex = 0;

	/* One time initilization */
	if (_baseObjectTypeAmount == 0)
	{
		_baseInitObjectTypes();
	}

	if (_baseObjectTypeAmount > 0)
	{
		for (; typeIndex < _baseObjectTypeAmount; typeIndex++)
		{
			if (HcStringEqualW(_baseObjectTypePairs[typeIndex]->Name, lpObjectName, TRUE))
			{
				return _baseObjectTypePairs[typeIndex]->Index;
			}
		}
	}

	return OBJECT_TYPE_ANY;
}

DECL_EXTERN_API(PLARGE_INTEGER, ObjectMillisecondsToNano, OUT PLARGE_INTEGER Timeout, CONST IN DWORD dwMiliseconds)
{
	if (dwMiliseconds == INFINITE)
	{
		return NULL;
	}

	/* Convert the time to NT Format */
	Timeout->QuadPart = dwMiliseconds * -10000LL;
	return Timeout;
}

DECL_EXTERN_API(DWORD, ObjectWaitMultiple, IN DWORD nCount,
	IN CONST PHANDLE lpHandles,
	IN BOOL bWaitAll,
	IN DWORD dwMilliseconds)
{
	PLARGE_INTEGER TimePtr;
	LARGE_INTEGER Time;
	PHANDLE HandleBuffer = NULL;
	HANDLE Handles[8];
	DWORD HandleIndex = 0;
	NTSTATUS Status;

	ZERO(&Time);
	ZERO(&Handles);

	/* Check if we have more handles then we locally optimize */
	if (nCount > 8)
	{
		/* Allocate a buffer for them */
		HandleBuffer = HcAlloc(nCount * sizeof(HANDLE));

		if (!HandleBuffer)
		{
			/* No buffer, fail the wait */
			HcErrorSetNtStatus(STATUS_INSUFFICIENT_RESOURCES);
			return WAIT_FAILED;
		}
	}
	else
	{
		/* Otherwise, use our local buffer */
		HandleBuffer = Handles;
	}

	/* Copy the handles into our buffer and loop them all */
	HcInternalCopy(HandleBuffer, (LPVOID)lpHandles, nCount * sizeof(HANDLE));
	for (; HandleIndex < nCount; HandleIndex++)
	{
		/* Check what kind of handle this is */
		HandleBuffer[HandleIndex] = HcObjectTranslateHandle(HandleBuffer[HandleIndex]);
	}

	/* Convert the timeout */
	TimePtr = HcObjectMillisecondsToNano(&Time, dwMilliseconds);

	/* Do the wait */
	Status = HcWaitForMultipleObjects(nCount,
		HandleBuffer,
		bWaitAll ? WaitAll : WaitAny,
		FALSE,
		TimePtr);

	if (!NT_SUCCESS(Status))
	{
		/* Wait failed */
		HcErrorSetNtStatus(Status);
		Status = WAIT_FAILED;
	}

	/* Check if we didn't use our local buffer */
	if (HandleBuffer != Handles)
	{
		/* Free the allocated one */
		HcFree(HandleBuffer);
	}

	/* Return wait status */
	return Status;
}

DECL_EXTERN_API(DWORD, ObjectWait, IN HANDLE hObject, IN DWORD dwMiliseconds)
{
	PLARGE_INTEGER TimePtr;
	LARGE_INTEGER Time;
	NTSTATUS Status;

	ZERO(&Time);

	/* Get the real handle */
	hObject = HcObjectTranslateHandle(hObject);

	/* Convert the timeout */
	TimePtr = HcObjectMillisecondsToNano(&Time, dwMiliseconds);

	/* Do the wait */
	if (HcGlobal.IsWow64)
	{
		Status = HcWaitForSingleObjectWow64((ULONG64) hObject, FALSE, (ULONG64) TimePtr);
	}
	else
	{
		Status = HcWaitForSingleObject(hObject, FALSE, TimePtr);
	}

	HcErrorSetNtStatus(Status);
	return Status;
}

DECL_EXTERN_API(VOID, ObjectClose, IN PHANDLE hObject)
{
	NTSTATUS Status;

	if (hObject == NULL)
	{
		return;
	}

	if (HcGlobal.IsWow64)
	{
		Status = HcCloseWow64((ULONG64) *hObject);
	}
	else
	{
		Status = HcClose(*hObject);
	}

	if (NT_SUCCESS(Status))
	{
		*hObject = INVALID_HANDLE;
	}
}

DECL_EXTERN_API(HANDLE, ObjectCreateEventW,
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
			HcErrorSetDosError(ERROR_ALREADY_EXISTS);
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


DECL_EXTERN_API(HANDLE, ObjectCreateEventA,
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
			hReturn = HcObjectCreateEventW(lpEventAttributes, bManualReset, bInitialState, lpConverted);
			HcFree(lpConverted);
		}
	}
	else
	{
		hReturn = HcObjectCreateEventW(lpEventAttributes, bManualReset, bInitialState, NULL);
	}

	return hReturn;
}

DECL_EXTERN_API(HANDLE, ObjectCreateMutexW, 
	IN LPSECURITY_ATTRIBUTES lpMutexAttributes OPTIONAL, 
	IN BOOLEAN bInitialOwner, 
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

	ObjectAttributes = HcUtilFormatObjectAttributes	(
		&LocalAttributes,
		lpMutexAttributes,
		lpName ? &ObjectName : NULL);

	Status = HcCreateMutant(&Handle, MUTANT_ALL_ACCESS, ObjectAttributes, bInitialOwner);

	if (NT_SUCCESS(Status))
	{
		if (Status == STATUS_OBJECT_NAME_EXISTS)
		{
			HcErrorSetDosError(ERROR_ALREADY_EXISTS);
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

DECL_EXTERN_API(HANDLE, ObjectCreateMutexA,
	IN LPSECURITY_ATTRIBUTES lpMutexAttributes OPTIONAL,
	IN BOOLEAN bInitialOwner,
	IN LPCSTR lpName OPTIONAL)
{
	LPWSTR lpConverted;
	HANDLE hReturn = NULL;

	if (lpName)
	{
		lpConverted = HcStringConvertAtoW(lpName);
		if (lpConverted)
		{
			hReturn = HcObjectCreateMutexW(lpMutexAttributes, bInitialOwner, lpConverted);
			HcFree(lpConverted);
		}
	}
	else
	{
		hReturn = HcObjectCreateMutexW(lpMutexAttributes, bInitialOwner, NULL);
	}

	return hReturn;
}

static NTSTATUS HCAPI GetHandleEntries(PSYSTEM_HANDLE_INFORMATION* handleList)
{
	// @defineme 0xffff USHRT_MAX

	NTSTATUS Status;
	ULONG dataLength = 0xffff;

	for (;;)
	{
		*handleList = (PSYSTEM_HANDLE_INFORMATION) HcAlloc(dataLength);

		Status = HcQuerySystemInformation(SystemHandleInformation, *handleList, dataLength, &dataLength);
		if (!NT_SUCCESS(Status))
		{
			if (Status != STATUS_INFO_LENGTH_MISMATCH)
			{
				return Status;
			}

			HcFree(*handleList);
			dataLength += 0xffff;
		}
		else
		{
			break;
		}
	}

	return Status;
}

DECL_EXTERN_API(BOOLEAN, ObjectEnumHandleEntries, HandleEntryCallback callback, LPARAM lParam)
{
	PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
	NTSTATUS Status;
	BOOLEAN ReturnValue = FALSE;

	Status = GetHandleEntries(&handleInfo);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	for (DWORD i = handleInfo->NumberOfHandles; i > 0; i--)
	{
		SYSTEM_HANDLE_TABLE_ENTRY_INFO curHandle = handleInfo->Handles[i];

		if (callback(&curHandle, lParam))
		{
			ReturnValue = TRUE;
			break;
		}
	}

	HcFree(handleInfo);
	return ReturnValue;
}

DECL_EXTERN_API(BOOLEAN, ObjectEnumHandles, HandleCallback callback, DWORD dwTypeIndex, LPARAM lParam)
{
	PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
	NTSTATUS Status;
	BOOLEAN ReturnValue = FALSE;
	HANDLE hProcess = NULL;
	DWORD dwLastProcess = 0;
	HANDLE hDuplicate;
	DWORD currentProcessId = HcProcessGetCurrentId();

	Status = GetHandleEntries(&handleInfo);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	for (DWORD i = handleInfo->NumberOfHandles; i > 0; i--)
	{
		const SYSTEM_HANDLE_TABLE_ENTRY_INFO curHandle = handleInfo->Handles[i];
		if (curHandle.ObjectTypeIndex != dwTypeIndex && dwTypeIndex != OBJECT_TYPE_ANY)
		{
			continue;
		}

		if (dwLastProcess != curHandle.UniqueProcessId && curHandle.UniqueProcessId != currentProcessId)
		{
			if (hProcess != NULL)
			{
				HcObjectClose(&hProcess);
			}

			hProcess = HcProcessOpen(curHandle.UniqueProcessId, PROCESS_DUP_HANDLE);
			if (!hProcess)
			{
				// report
				continue;
			}

			dwLastProcess = curHandle.UniqueProcessId;
		}

		Status = HcDuplicateObject(hProcess,
			(HANDLE) curHandle.HandleValue,
			NtCurrentProcess(),
			&hDuplicate,
			0,
			FALSE,
			DUPLICATE_SAME_ACCESS);

		if (!NT_SUCCESS(Status))
		{
			// report error
			continue;
		}

		if (callback(hDuplicate, hProcess, lParam))
		{
			ReturnValue = TRUE;
			HcObjectClose(&hDuplicate);
			goto done;
		}

		HcObjectClose(&hDuplicate);
	}

done:
	if (hProcess != NULL)
	{
		HcObjectClose(&hProcess);
	}

	HcFree(handleInfo);
	return ReturnValue;
}