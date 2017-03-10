#include <highcall.h>

DECL_EXTERN_API(POBJECT_ATTRIBUTES, UtilFormatObjectAttributes, 
	OUT POBJECT_ATTRIBUTES ObjectAttributes,
	IN PSECURITY_ATTRIBUTES SecurityAttributes OPTIONAL,
	IN PUNICODE_STRING ObjectName)
{
	ULONG Attributes;
	HANDLE RootDirectory;
	PVOID SecurityDescriptor;

	/* Get the attributes if present */
	if (SecurityAttributes)
	{
		Attributes = SecurityAttributes->bInheritHandle ? OBJ_INHERIT : 0;
		SecurityDescriptor = SecurityAttributes->lpSecurityDescriptor;
	}
	else
	{
		if (!ObjectName)
		{
			return NULL;
		}

		Attributes = 0;
		SecurityDescriptor = NULL;
	}

	if (ObjectName)
	{
		Attributes |= OBJ_OPENIF;
		RootDirectory = HcGlobal.BaseNamedObjectDirectory;
	}
	else
	{
		RootDirectory = NULL;
	}

	/* Create the Object Attributes */
	InitializeObjectAttributes(ObjectAttributes,
		ObjectName,
		Attributes,
		RootDirectory,
		SecurityDescriptor);

	return ObjectAttributes;
}