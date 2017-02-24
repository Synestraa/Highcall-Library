/*
	@File: hcobject.c
	@Purpose: Windows object handling.

	@Author: Synestraa
	@version 9/10/2016
*/

#include "sys/hcsyscall.h"

#include "../public/hcobject.h"
#include "../public/hcdef.h"
#include "../public/hcvirtual.h"
#include "../public/hcerror.h"
#include "../public/hcstring.h"

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
					type->TypeName.Length);
			}

			type = (POBJECT_TYPE_INFORMATION)((PCHAR)(type + 1) + ALIGN_UP(type->TypeName.MaximumLength, ULONG_PTR));
		}
	}

	HcFree(Types);
}

HANDLE HCAPI HcObjectTranslateHandle(CONST IN HANDLE Handle)
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

HC_EXTERN_API DWORD HCAPI HcObjectTypeIndexByName(IN LPCWSTR lpObjectName)
{
	if (_baseObjectTypeAmount == 0)
	{
		_baseInitObjectTypes();
	}

	if (_baseObjectTypeAmount > 0)
	{
		for (DWORD i = 0; i < _baseObjectTypeAmount; i++)
		{
			if (HcStringEqualW(_baseObjectTypePairs[i]->Name, lpObjectName, TRUE))
			{
				return _baseObjectTypePairs[i]->Index;
			}
		}
	}

	return OBJECT_TYPE_ANY;
}

HC_EXTERN_API
PLARGE_INTEGER 
HCAPI 
HcObjectMillisecondsToNano(OUT PLARGE_INTEGER Timeout, CONST IN DWORD dwMiliseconds)
{
	if (dwMiliseconds == INFINITE)
	{
		return NULL;
	}

	/* Convert the time to NT Format */
	Timeout->QuadPart = dwMiliseconds * -10000LL;
	return Timeout;
}

HC_EXTERN_API
DWORD
HCAPI
HcObjectWaitMultiple(IN DWORD nCount,
	IN CONST HANDLE *lpHandles,
	IN BOOL bWaitAll,
	IN DWORD dwMilliseconds)
{
	PLARGE_INTEGER TimePtr = NULL;
	LARGE_INTEGER Time;
	PHANDLE HandleBuffer = NULL;
	HANDLE Handles[8];
	DWORD i = 0;
	NTSTATUS Status = STATUS_SUCCESS;

	HcInternalSet(&Time, 0, sizeof(Time));
	HcInternalSet(&Handles, 0, sizeof(Handles));

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
	for (i = 0; i < nCount; i++)
	{
		/* Check what kind of handle this is */
		HandleBuffer[i] = HcObjectTranslateHandle(HandleBuffer[i]);
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

HC_EXTERN_API
DWORD 
HCAPI 
HcObjectWait(HANDLE hObject, IN DWORD dwMiliseconds)
{
	PLARGE_INTEGER TimePtr = NULL;
	LARGE_INTEGER Time;
	NTSTATUS Status = STATUS_SUCCESS;

	HcInternalSet(&Time, 0, sizeof(Time));

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

HC_EXTERN_API
VOID
HCAPI
HcObjectClose(HANDLE hObject)
{
	HcClose(hObject);
}