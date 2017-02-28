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

DECL_EXTERN_API(DWORD, ObjectWait, HANDLE hObject, IN DWORD dwMiliseconds)
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
	Status = HcWaitForSingleObject(hObject, FALSE, TimePtr);
	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
	}

	return Status;
}

DECL_EXTERN_API(VOID, ObjectClose, HANDLE hObject)
{
	HcClose(hObject);
}