#include <highcall.h>

#include "../../public/imports.h"

DECL_EXTERN_API(BOOLEAN, PathGetFileA, IN LPCSTR lpPath, IN LPSTR lpBuffer)
{
	DWORD LastSlashOccurance;

	LastSlashOccurance = HcStringLastIndexOfA(lpPath, "\\", FALSE);
	if (LastSlashOccurance != -1)
	{
		return HcStringSubtractA(lpPath, lpBuffer, LastSlashOccurance, -1);
	}

	return FALSE;
}

DECL_EXTERN_API(BOOLEAN, PathGetFileW, IN LPCWSTR lpPath, IN LPWSTR lpBuffer)
{
	DWORD LastSlashOccurance;

	LastSlashOccurance = HcStringLastIndexOfW(lpPath, L"\\", FALSE);
	if (LastSlashOccurance != -1)
	{
		return HcStringSubtractW(lpPath, lpBuffer, LastSlashOccurance, -1);
	}

	return FALSE;
}

DECL_EXTERN_API(DWORD, PathGetFullPathNameA, IN LPCSTR lpFileName, OUT LPSTR lpBuffer)
{
	LPWSTR lpTemp = HcStringAllocW(MAX_PATH);
	LPWSTR lpConvertedName;
	DWORD Length;

	lpConvertedName = HcStringConvertAtoW(lpFileName);
	if (!lpConvertedName)
	{
		HcFree(lpTemp);
		return 0;
	}

	Length = HcPathGetFullPathNameW(lpConvertedName, lpTemp);
	if (Length > 0)
	{
		HcStringCopyConvertWtoA(lpTemp, lpBuffer, Length);
	}

	HcFree(lpTemp);
	HcFree(lpConvertedName);
	return Length;
}

UNICODE_STRING DeviceRootString = RTL_CONSTANT_STRING(L"\\\\.\\");

UNICODE_STRING RtlpDosDevicesUncPrefix = RTL_CONSTANT_STRING(L"\\??\\UNC\\");
UNICODE_STRING RtlpWin32NtRootSlash = RTL_CONSTANT_STRING(L"\\\\?\\");
UNICODE_STRING RtlpDosSlashCONDevice = RTL_CONSTANT_STRING(L"\\\\.\\CON");
UNICODE_STRING RtlpDosDevicesPrefix = RTL_CONSTANT_STRING(L"\\??\\");

UNICODE_STRING RtlpDosLPTDevice = RTL_CONSTANT_STRING(L"LPT");
UNICODE_STRING RtlpDosCOMDevice = RTL_CONSTANT_STRING(L"COM");
UNICODE_STRING RtlpDosPRNDevice = RTL_CONSTANT_STRING(L"PRN");
UNICODE_STRING RtlpDosAUXDevice = RTL_CONSTANT_STRING(L"AUX");
UNICODE_STRING RtlpDosCONDevice = RTL_CONSTANT_STRING(L"CON");
UNICODE_STRING RtlpDosNULDevice = RTL_CONSTANT_STRING(L"NUL");

#define IS_PATH_SEPARATOR(x) (((x)==L'\\')||((x)==L'/'))


RTL_PATH_TYPE NTAPI HcDetermineDosPathNameType_U(IN PCWSTR 	Path)
{
	/* Unlike the newer RtlDetermineDosPathNameType_U we assume 4 characters */
	if (IS_PATH_SEPARATOR(Path[0]))
	{
		if (!IS_PATH_SEPARATOR(Path[1])) return RtlPathTypeRooted;                /* \x             */
		if ((Path[2] != L'.') && (Path[2] != L'?')) return RtlPathTypeUncAbsolute;/* \\x            */
		if (IS_PATH_SEPARATOR(Path[3])) return RtlPathTypeLocalDevice;            /* \\.\x or \\?\x */
		if (Path[3]) return RtlPathTypeUncAbsolute;                               /* \\.x or \\?x   */
		return RtlPathTypeRootLocalDevice;                                        /* \\. or \\?     */
	}
	else
	{
		if (!(Path[0]) || (Path[1] != L':')) return RtlPathTypeRelative;          /* x              */
		if (IS_PATH_SEPARATOR(Path[2])) return RtlPathTypeDriveAbsolute;          /* x:\            */
		return RtlPathTypeDriveRelative;                                          /* x:             */
	}
}

RTL_PATH_TYPE NTAPI HcDetermineDosPathNameType_Ustr(IN PUNICODE_STRING 	PathString)
{
	PWCHAR Path;
	ULONG Chars;

	Path = PathString->Buffer;
	Chars = PathString->Length / sizeof(WCHAR);

	/* Return if there are no characters */
	if (!Chars) return RtlPathTypeRelative;

	/*
	* The algorithm is similar to RtlDetermineDosPathNameType_U but here we
	* actually check for the path length before touching the characters
	*/
	if (IS_PATH_SEPARATOR(Path[0]))
	{
		if ((Chars < 2) || !(IS_PATH_SEPARATOR(Path[1]))) return RtlPathTypeRooted;                /* \x             */
		if ((Chars < 3) || ((Path[2] != L'.') && (Path[2] != L'?'))) return RtlPathTypeUncAbsolute;/* \\x            */
		if ((Chars >= 4) && (IS_PATH_SEPARATOR(Path[3]))) return RtlPathTypeLocalDevice;           /* \\.\x or \\?\x */
		if (Chars != 3) return RtlPathTypeUncAbsolute;                                             /* \\.x or \\?x   */
		return RtlPathTypeRootLocalDevice;                                                         /* \\. or \\?     */
	}
	else
	{
		if ((Chars < 2) || (Path[1] != L':')) return RtlPathTypeRelative;                          /* x              */
		if ((Chars < 3) || !(IS_PATH_SEPARATOR(Path[2]))) return RtlPathTypeDriveRelative;         /* x:             */
		return RtlPathTypeDriveAbsolute;                                                           /* x:\            */
	}
}

BOOLEAN NTAPI HcEqualUnicodeString(PUNICODE_STRING 	String1,
	PUNICODE_STRING 	String2,
	BOOLEAN 	CaseInSensitive)
{
	return HcStringEqualW(String1->Buffer, String2->Buffer, CaseInSensitive);
}

#define MAXUSHORT   65535 

NTSTATUS
NTAPI
HcInitUnicodeStringEx(
	OUT PUNICODE_STRING DestinationString,
	IN PCWSTR SourceString)
{
	SIZE_T Size;
	CONST SIZE_T MaxSize = (MAXUSHORT & ~1) - sizeof(WCHAR); // an even number

	if (SourceString)
	{
		Size = HcStringLenW(SourceString) * sizeof(WCHAR);
		if (Size > MaxSize) return STATUS_NAME_TOO_LONG;
		DestinationString->Length = (USHORT) Size;
		DestinationString->MaximumLength = (USHORT) Size + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR) SourceString;
	return STATUS_SUCCESS;
}

WCHAR NTAPI HcpDowncaseUnicodeChar(IN WCHAR 	Source)
{
	USHORT Offset;

	if (Source < L'A')
		return Source;

	if (Source <= L'Z')
		return Source + (L'a' - L'A');

	if (Source < 0x80)
		return Source;

	Offset = ((USHORT) Source >> 8);

	//Offset = NlsUnicodeLowercaseTable[Offset];

	//Offset += (((USHORT) Source & 0x00F0) >> 4);

	//Offset = NlsUnicodeLowercaseTable[Offset];

	//Offset += ((USHORT) Source & 0x000F);

	//Offset = NlsUnicodeLowercaseTable[Offset];

	return Source + (SHORT) Offset;
}

WCHAR NTAPI HcpUpcaseUnicodeChar(IN WCHAR 	Source)
{
	USHORT Offset;

	if (Source < 'a')
		return Source;

	if (Source <= 'z')
		return (Source - ('a' - 'A'));

	Offset = ((USHORT) Source >> 8) & 0xFF;
	//Offset = NlsUnicodeUpcaseTable[Offset];

	//Offset += ((USHORT) Source >> 4) & 0xF;
	//Offset = NlsUnicodeUpcaseTable[Offset];

	//Offset += ((USHORT) Source & 0xF);
	//Offset = NlsUnicodeUpcaseTable[Offset];

	return Source + (SHORT) Offset;
}

ULONG NTAPI HcIsDosDeviceName_Ustr(IN PUNICODE_STRING 	PathString)
{
	UNICODE_STRING PathCopy;
	PWCHAR Start, End;
	USHORT PathChars, ColonCount = 0;
	USHORT ReturnOffset = 0, ReturnLength, OriginalLength;
	WCHAR c;

	/* Validate the input */
	if (!PathString) return 0;

	/* Check what type of path this is */
	switch (HcDetermineDosPathNameType_Ustr(PathString))
	{
		/* Fail for UNC or unknown paths */
		case RtlPathTypeUnknown:
		case RtlPathTypeUncAbsolute:
		return 0;

		/* Make special check for the CON device */
		case RtlPathTypeLocalDevice:
		if (HcEqualUnicodeString(PathString, &RtlpDosSlashCONDevice, TRUE))
		{
			/* This should return 0x80006 */
			return MAKELONG(RtlpDosCONDevice.Length, DeviceRootString.Length);
		}
		return 0;

		default:
		break;
	}

	/* Make a copy of the string */
	PathCopy = *PathString;
	OriginalLength = PathString->Length;

	/* Return if there's no characters */
	PathChars = PathCopy.Length / sizeof(WCHAR);
	if (!PathChars) return 0;

	/* Check for drive path and truncate */
	if (PathCopy.Buffer[PathChars - 1] == L':')
	{
		/* Fixup the lengths */
		PathCopy.Length -= sizeof(WCHAR);
		if (!--PathChars) return 0;

		/* Remember this for later */
		ColonCount = 1;
	}

	/* Check for extension or space, and truncate */
	do
	{
		/* Stop if we hit something else than a space or period */
		c = PathCopy.Buffer[PathChars - 1];
		if ((c != L'.') && (c != L' ')) break;

		/* Fixup the lengths */
		PathCopy.Length -= sizeof(WCHAR);

		/* Remember this for later */
		ColonCount++;
	} while (--PathChars);

	/* Anything still left? */
	if (PathChars)
	{
		/* Loop from the end */
		for (End = &PathCopy.Buffer[PathChars - 1];
			End >= PathCopy.Buffer;
			--End)
		{
			/* Check if the character is a path or drive separator */
			c = *End;
			if (IS_PATH_SEPARATOR(c) || ((c == L':') && (End == PathCopy.Buffer + 1)))
			{
				/* Get the next lower case character */
				End++;
				c = HcpDowncaseUnicodeChar(*End);

				/* Check if it's a DOS device (LPT, COM, PRN, AUX, or NUL) */
				if ((End < &PathCopy.Buffer[OriginalLength / sizeof(WCHAR)]) &&
					((c == L'l') || (c == L'c') || (c == L'p') || (c == L'a') || (c == L'n')))
				{
					/* Calculate the offset */
					ReturnOffset = (USHORT) ((PCHAR) End - (PCHAR) PathCopy.Buffer);

					/* Build the final string */
					PathCopy.Length = OriginalLength - ReturnOffset - (ColonCount * sizeof(WCHAR));
					PathCopy.Buffer = End;

					/* Save new amount of chars in the path */
					PathChars = PathCopy.Length / sizeof(WCHAR);

					break;
				}
				else
				{
					return 0;
				}
			}
		}

		/* Get the next lower case character and check if it's a DOS device */
		c = HcpDowncaseUnicodeChar(*PathCopy.Buffer);
		if ((c != L'l') && (c != L'c') && (c != L'p') && (c != L'a') && (c != L'n'))
		{
			/* Not LPT, COM, PRN, AUX, or NUL */
			return 0;
		}
	}

	/* Now skip past any extra extension or drive letter characters */
	Start = PathCopy.Buffer;
	End = &Start[PathChars];
	while (Start < End)
	{
		c = *Start;
		if ((c == L'.') || (c == L':')) break;
		Start++;
	}

	/* And then go backwards to get rid of spaces */
	while ((Start > PathCopy.Buffer) && (Start[-1] == L' ')) --Start;

	/* Finally see how many characters are left, and that's our size */
	PathChars = (USHORT) (Start - PathCopy.Buffer);
	PathCopy.Length = PathChars * sizeof(WCHAR);

	if ((PathChars == 3) &&
		((HcEqualUnicodeString(&PathCopy, &RtlpDosPRNDevice, TRUE)) ||
		(HcEqualUnicodeString(&PathCopy, &RtlpDosAUXDevice, TRUE)) ||
			(HcEqualUnicodeString(&PathCopy, &RtlpDosNULDevice, TRUE)) ||
			(HcEqualUnicodeString(&PathCopy, &RtlpDosCONDevice, TRUE))))
	{
		/* Otherwise this was something like AUX, NUL, PRN, or CON */
		ReturnLength = sizeof(L"AUX") - sizeof(WCHAR);
		return MAKELONG(ReturnLength, ReturnOffset);
	}

	/* Otherwise, this is not a valid DOS device */
	return 0;
}

NTSTATUS NTAPI HcpCheckDeviceName(IN PUNICODE_STRING 	FileName,
	IN ULONG 	Length,
	OUT PBOOLEAN 	NameInvalid
	)
{
	PWCHAR Buffer;
	NTSTATUS Status;

	/* Allocate a large enough buffer */
	Buffer = HcAlloc(FileName->Length);
	if (Buffer)
	{
		/* Assume failure */
		*NameInvalid = TRUE;

		/* Copy the filename */
		HcInternalCopy(Buffer, FileName->Buffer, FileName->Length);

		/* And add a dot at the end */
		Buffer[Length / sizeof(WCHAR)] = L'.';
		Buffer[(Length / sizeof(WCHAR)) + 1] = UNICODE_NULL;

		/* Check if the file exists or not */
		//*NameInvalid = RtlDoesFileExists_U(Buffer) ? FALSE : TRUE;

		/* Get rid of the buffer now */
		HcFree(Buffer);
	}
	else
	{
		/* Assume the name is ok, but fail the call */
		*NameInvalid = FALSE;
		Status = STATUS_NO_MEMORY;
	}

	/* Return the status */
	return Status;
}

static SIZE_T RtlpSkipUNCPrefix(PCWSTR 	FileNameBuffer)
{
	PCWSTR UncPath = FileNameBuffer + 2;

	while (*UncPath && !IS_PATH_SEPARATOR(*UncPath)) UncPath++;  /* share name */
	while (IS_PATH_SEPARATOR(*UncPath)) UncPath++;
	while (*UncPath && !IS_PATH_SEPARATOR(*UncPath)) UncPath++;  /* dir name */
																 /* while (IS_PATH_SEPARATOR(*UncPath)) UncPath++; */

	return (UncPath - FileNameBuffer);
}

NTSTATUS NTAPI HcQueryEnvironmentVariable_U(PWSTR 	Environment,
	PUNICODE_STRING 	Name,
	PUNICODE_STRING 	Value
)
{
	NTSTATUS Status;
	PWSTR wcs;
	UNICODE_STRING var;
	PWSTR val;
	BOOLEAN SysEnvUsed = FALSE;

	if (Environment == NULL)
	{
		PPEB Peb = NtCurrentPeb();
		if (Peb)
		{
			Environment = Peb->ProcessParameters->Environment;
			SysEnvUsed = TRUE;
		}
	}

	if (Environment == NULL)
	{
		return(STATUS_VARIABLE_NOT_FOUND);
	}

	Value->Length = 0;

	wcs = Environment;
	while (*wcs)
	{
		var.Buffer = wcs++;
		wcs = HcStringWithinStringW(wcs, L"=", TRUE, FALSE);
		if (wcs == NULL)
		{
			wcs = var.Buffer + wcslen(var.Buffer);
		}
		if (*wcs)
		{
			var.Length = var.MaximumLength = (USHORT) (wcs - var.Buffer) * sizeof(WCHAR);
			val = ++wcs;
			wcs += wcslen(wcs);

			if (HcEqualUnicodeString(&var, Name, TRUE))
			{
				Value->Length = (USHORT) (wcs - val) * sizeof(WCHAR);
				if (Value->Length <= Value->MaximumLength)
				{
					HcInternalCopy(Value->Buffer, val,
						min(Value->Length + sizeof(WCHAR), Value->MaximumLength));

					Status = STATUS_SUCCESS;
				}
				else
				{
					Status = STATUS_BUFFER_TOO_SMALL;
				}

				return(Status);
			}
		}
		wcs++;
	}

	return(STATUS_VARIABLE_NOT_FOUND);
}

static ULONG RtlpCollapsePath(PWSTR 	Path,
	ULONG 	mark,
	BOOLEAN 	SkipTrailingPathSeparators
)
{
	PWSTR p, next;

	// FIXME: Do not suppose NULL-terminated strings!!

	ULONG PathLength = HcStringLenW(Path);
	PWSTR EndBuffer = Path + PathLength; // Path + PathBufferSize / sizeof(WCHAR);
	PWSTR EndPath;

	/* Convert slashes into backslashes */
	for (p = Path; *p; p++)
	{
		if (*p == L'/') *p = L'\\';
	}

	/* Collapse duplicate backslashes */
	next = Path + max(1, mark);
	for (p = next; *p; p++)
	{
		if (*p != L'\\' || next[-1] != L'\\') *next++ = *p;
	}
	*next = UNICODE_NULL;
	EndPath = next;

	p = Path + mark;
	while (*p)
	{
		if (*p == L'.')
		{
			switch (p[1])
			{
				case UNICODE_NULL:  /* final . */
				if (p > Path + mark) p--;
				*p = UNICODE_NULL;
				EndPath = p;
				continue;

				case L'\\': /* .\ component */
				next = p + 2;
				// ASSERT(EndPath - next == wcslen(next));
				HcInternalMove(p, next, (EndPath - next + 1) * sizeof(WCHAR));
				EndPath -= (next - p);
				continue;

				case L'.':
				if (p[2] == L'\\')  /* ..\ component */
				{
					next = p + 3;
					if (p > Path + mark)
					{
						p--;
						while (p > Path + mark && p[-1] != L'\\') p--;
					}
					// ASSERT(EndPath - next == wcslen(next));
					HcInternalMove(p, next, (EndPath - next + 1) * sizeof(WCHAR));
					EndPath -= (next - p);
					continue;
				}
				else if (p[2] == UNICODE_NULL)  /* final .. */
				{
					if (p > Path + mark)
					{
						p--;
						while (p > Path + mark && p[-1] != L'\\') p--;
						if (p > Path + mark) p--;
					}
					*p = UNICODE_NULL;
					EndPath = p;
					continue;
				}
				break;
			}
		}

		/* Skip to the next component */
		while (*p && *p != L'\\') p++;
		if (*p == L'\\')
		{
			/* Remove last dot in previous dir name */
			if (p > Path + mark && p[-1] == L'.')
			{
				// ASSERT(EndPath - p == wcslen(p));
				HcInternalMove(p - 1, p, (EndPath - p + 1) * sizeof(WCHAR));
				EndPath--;
			}
			else
			{
				p++;
			}
		}
	}

	/* Remove trailing backslashes if needed (after the UNC part if it exists) */
	if (SkipTrailingPathSeparators)
	{
		while (p > Path + mark && IS_PATH_SEPARATOR(p[-1])) p--;
	}

	/* Remove trailing spaces and dots (for all the path) */
	while (p > Path && (p[-1] == L' ' || p[-1] == L'.')) p--;

	/*
	* Zero-out the discarded buffer zone, starting just after
	* the path string and going up to the end of the buffer.
	* It also NULL-terminate the path string.
	*/

	HcInternalSet(p, 0, (EndBuffer - p + 1) * sizeof(WCHAR));

	/* Return the real path length */
	PathLength = (p - Path);
	// ASSERT(PathLength == wcslen(Path));
	return (PathLength * sizeof(WCHAR));
}

ULONG NTAPI HcGetFullPathName_Ustr(_In_ PUNICODE_STRING 	FileName,
	_In_ ULONG 	Size,
	_Out_z_bytecap_(Size) PWSTR 	Buffer,
	_Out_opt_ PCWSTR * 	ShortName,
	_Out_opt_ PBOOLEAN 	InvalidName,
	_Out_ RTL_PATH_TYPE * 	PathType)
{
	NTSTATUS Status;
	PWCHAR FileNameBuffer;
	ULONG FileNameLength, FileNameChars, DosLength, DosLengthOffset, FullLength;
	BOOLEAN SkipTrailingPathSeparators;
	WCHAR c;

	ULONG               reqsize = 0;
	PCWSTR              ptr;

	PUNICODE_STRING    CurDirName;
	UNICODE_STRING      EnvVarName, EnvVarValue;
	WCHAR EnvVarNameBuffer[4];

	ULONG  PrefixCut = 0;    // Where the path really starts (after the skipped prefix)
	PWCHAR Prefix = NULL; // pointer to the string to be inserted as the new path prefix
	ULONG  PrefixLength = 0;
	PWCHAR Source;
	ULONG  SourceLength;


	/* For now, assume the name is valid */
	if (InvalidName) *InvalidName = FALSE;

	/* Handle initial path type and failure case */
	*PathType = RtlPathTypeUnknown;
	if ((FileName->Length == 0) || (FileName->Buffer[0] == UNICODE_NULL)) return 0;

	/* Break filename into component parts */
	FileNameBuffer = FileName->Buffer;
	FileNameLength = FileName->Length;
	FileNameChars = FileNameLength / sizeof(WCHAR);

	/* Kill trailing spaces */
	c = FileNameBuffer[FileNameChars - 1];
	while ((FileNameLength != 0) && (c == L' '))
	{
		/* Keep going, ignoring the spaces */
		FileNameLength -= sizeof(WCHAR);
		if (FileNameLength != 0) c = FileNameBuffer[FileNameLength / sizeof(WCHAR) - 1];
	}

	/* Check if anything is left */
	if (FileNameLength == 0) return 0;

	/*
	* Check whether we'll need to skip trailing path separators in the
	* computed full path name. If the original file name already contained
	* trailing separators, then we keep them in the full path name. On the
	* other hand, if the original name didn't contain any trailing separators
	* then we'll skip it in the full path name.
	*/
	SkipTrailingPathSeparators = !IS_PATH_SEPARATOR(FileNameBuffer[FileNameChars - 1]);

	/* Check if this is a DOS name */
	DosLength = HcIsDosDeviceName_Ustr(FileName);
	if (DosLength != 0)
	{
		/* Zero out the short name */
		if (ShortName) *ShortName = NULL;

		/* See comment for RtlIsDosDeviceName_Ustr if this is confusing... */
		DosLengthOffset = HIWORD(DosLength);
		DosLength = LOWORD(DosLength);

		/* Do we have a DOS length, and does the caller want validity? */
		if (InvalidName && (DosLengthOffset != 0))
		{
			/* Do the check */
			Status = HcpCheckDeviceName(FileName, DosLengthOffset, InvalidName);

			/* If the check failed, or the name is invalid, fail here */
			if (!NT_SUCCESS(Status)) return 0;
			if (*InvalidName) return 0;
		}

		/* Add the size of the device root and check if it fits in the size */
		FullLength = DosLength + DeviceRootString.Length;
		if (FullLength < Size)
		{
			/* Add the device string */
			HcInternalMove(Buffer, DeviceRootString.Buffer, DeviceRootString.Length);

			/* Now add the DOS device name */
			HcInternalMove((PCHAR) Buffer + DeviceRootString.Length,
				(PCHAR) FileNameBuffer + DosLengthOffset,
				DosLength);

			/* Null terminate */
			*(PWCHAR) ((ULONG_PTR) Buffer + FullLength) = UNICODE_NULL;
			return FullLength;
		}

		/* Otherwise, there's no space, so return the buffer size needed */
		if ((FullLength + sizeof(UNICODE_NULL)) > UNICODE_STRING_MAX_BYTES) return 0;
		return FullLength + sizeof(UNICODE_NULL);
	}

	/* Zero-out the destination buffer. FileName must be different from Buffer */
	HcInternalSet(Buffer, 0, Size);

	/* Get the path type */
	*PathType = HcDetermineDosPathNameType_U(FileNameBuffer);



	/**********************************************
	**    CODE REWRITING IS HAPPENING THERE     **
	**********************************************/
	Source = FileNameBuffer;
	SourceLength = FileNameLength;
	EnvVarValue.Buffer = NULL;

	/* Lock the PEB to get the current directory */
	CurDirName = &NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath;

	switch (*PathType)
	{
		case RtlPathTypeUncAbsolute:        /* \\foo   */
		{
			PrefixCut = RtlpSkipUNCPrefix(FileNameBuffer);
			break;
		}

		case RtlPathTypeLocalDevice:        /* \\.\foo */
		{
			PrefixCut = 4;
			break;
		}

		case RtlPathTypeDriveAbsolute:      /* c:\foo  */
		{
			// FileNameBuffer[0] = RtlpUpcaseUnicodeChar(FileNameBuffer[0]);
			Prefix = FileNameBuffer;
			PrefixLength = 3 * sizeof(WCHAR);
			Source += 3;
			SourceLength -= 3 * sizeof(WCHAR);

			PrefixCut = 3;
			break;
		}

		case RtlPathTypeDriveRelative:      /* c:foo   */
		{
			WCHAR CurDrive, NewDrive;

			Source += 2;
			SourceLength -= 2 * sizeof(WCHAR);

			CurDrive = HcpUpcaseUnicodeChar(CurDirName->Buffer[0]);
			NewDrive = HcpUpcaseUnicodeChar(FileNameBuffer[0]);

			if ((NewDrive != CurDrive) || CurDirName->Buffer[1] != L':')
			{
				EnvVarNameBuffer[0] = L'=';
				EnvVarNameBuffer[1] = NewDrive;
				EnvVarNameBuffer[2] = L':';
				EnvVarNameBuffer[3] = UNICODE_NULL;

				EnvVarName.Length = 3 * sizeof(WCHAR);
				EnvVarName.MaximumLength = EnvVarName.Length + sizeof(WCHAR);
				EnvVarName.Buffer = EnvVarNameBuffer;

				// FIXME: Is it possible to use the user-given buffer ?
				// RtlInitEmptyUnicodeString(&EnvVarValue, NULL, Size);
				EnvVarValue.Length = 0;
				EnvVarValue.MaximumLength = (USHORT) Size;
				EnvVarValue.Buffer = HcAlloc(Size);
				if (EnvVarValue.Buffer == NULL)
				{
					Prefix = NULL;
					PrefixLength = 0;
					goto Quit;
				}

				Status = HcQueryEnvironmentVariable_U(NULL, &EnvVarName, &EnvVarValue);
				switch (Status)
				{
					case STATUS_SUCCESS:
					/*
					* (From Wine)
					* FIXME: Win2k seems to check that the environment
					* variable actually points to an existing directory.
					* If not, root of the drive is used (this seems also
					* to be the only place in RtlGetFullPathName that the
					* existence of a part of a path is checked).
					*/
					EnvVarValue.Buffer[EnvVarValue.Length / sizeof(WCHAR)] = L'\\';
					Prefix = EnvVarValue.Buffer;
					PrefixLength = EnvVarValue.Length + sizeof(WCHAR); /* Append trailing '\\' */
					break;

					case STATUS_BUFFER_TOO_SMALL:
					reqsize = EnvVarValue.Length + SourceLength + sizeof(UNICODE_NULL);
					goto Quit;

					default:
					EnvVarNameBuffer[0] = NewDrive;
					EnvVarNameBuffer[1] = L':';
					EnvVarNameBuffer[2] = L'\\';
					EnvVarNameBuffer[3] = UNICODE_NULL;
					Prefix = EnvVarNameBuffer;
					PrefixLength = 3 * sizeof(WCHAR);

					HcFree(EnvVarValue.Buffer);
					EnvVarValue.Buffer = NULL;
					break;
				}
				PrefixCut = 3;
				break;
			}
		}

		case RtlPathTypeRelative:           /* foo     */
		{
			Prefix = CurDirName->Buffer;
			PrefixLength = CurDirName->Length;
			if (CurDirName->Buffer[1] != L':')
			{
				PrefixCut = RtlpSkipUNCPrefix(CurDirName->Buffer);
			}
			else
			{
				PrefixCut = 3;
			}
			break;
		}

		case RtlPathTypeRooted:             /* \xxx    */
		{
			if (CurDirName->Buffer[1] == L':')
			{
				Prefix = CurDirName->Buffer;
				PrefixLength = 3 * sizeof(WCHAR); // Skip "C:\"

				PrefixCut = 3;      // Source index location incremented of + 3
			}
			else
			{
				PrefixCut = RtlpSkipUNCPrefix(CurDirName->Buffer);
				PrefixLength = PrefixCut * sizeof(WCHAR);
				Prefix = CurDirName->Buffer;
			}
			break;
		}

		case RtlPathTypeRootLocalDevice:    /* \\.     */
		{
			Prefix = DeviceRootString.Buffer;
			PrefixLength = DeviceRootString.Length;
			Source += 3;
			SourceLength -= 3 * sizeof(WCHAR);

			PrefixCut = 4;
			break;
		}

		case RtlPathTypeUnknown:
		goto Quit;
	}

	/* Do we have enough space for storing the full path? */
	reqsize = PrefixLength;
	if (reqsize + SourceLength + sizeof(WCHAR) > Size)
	{
		/* Not enough space, return needed size (including terminating '\0') */
		reqsize += SourceLength + sizeof(WCHAR);
		goto Quit;
	}

	/*
	* Build the full path
	*/
	/* Copy the path's prefix */
	if (PrefixLength) HcInternalMove(Buffer, Prefix, PrefixLength);
	/* Copy the remaining part of the path */
	HcInternalMove(Buffer + PrefixLength / sizeof(WCHAR), Source, SourceLength + sizeof(WCHAR));

	/* Some cleanup */
	Prefix = NULL;
	if (EnvVarValue.Buffer)
	{
		HcFree(EnvVarValue.Buffer);
		EnvVarValue.Buffer = NULL;
	}

	/*
	* Finally, put the path in canonical form (remove redundant . and ..,
	* (back)slashes...) and retrieve the length of the full path name
	* (without its terminating null character) (in chars).
	*/
	reqsize = RtlpCollapsePath(Buffer, /* Size, reqsize, */ PrefixCut, SkipTrailingPathSeparators);

	/* Find the file part, which is present after the last path separator */
	if (ShortName)
	{
		ptr = HcStringWithinStringW(Buffer, L"\\", TRUE, FALSE);
		if (ptr) ++ptr; // Skip it

						/*
						* For UNC paths, the file part is after the \\share\dir part of the path.
						*/
		PrefixCut = (*PathType == RtlPathTypeUncAbsolute ? PrefixCut : 3);

		if (ptr && *ptr && (ptr >= Buffer + PrefixCut))
		{
			*ShortName = ptr;
		}
		else
		{
			/* Zero-out the short name */
			*ShortName = NULL;
		}
	}

Quit:

	return reqsize;
}

ULONG NTAPI HcGetFullPathName_U(_In_ PCWSTR 	FileName,
	_In_ ULONG 	Size,
	_Out_z_bytecap_(Size) PWSTR 	Buffer,
	_Out_opt_ PWSTR * 	ShortName
)
{
	NTSTATUS Status;
	UNICODE_STRING FileNameString;
	RTL_PATH_TYPE PathType;

	/* Build the string */
	Status = HcInitUnicodeStringEx(&FileNameString, FileName);
	if (!NT_SUCCESS(Status)) return 0;

	/* Call the extended function */
	return HcGetFullPathName_Ustr(&FileNameString,
		Size,
		Buffer,
		(PCWSTR*) ShortName,
		NULL,
		&PathType);
}

DECL_EXTERN_API(DWORD, PathGetFullPathNameW, IN LPCWSTR lpFileName, OUT LPWSTR lpBuffer)
{
	return HcGetFullPathName_U(lpFileName,
		MAX_PATH * sizeof(WCHAR),
		lpBuffer,
		NULL) / sizeof(WCHAR);
}

DECL_EXTERN_API(DWORD, PathGetTempFolderW, IN LPWSTR lpBuffer)
/* Rtl is safe to use in this case (there is barely any trace, no system calls) although it's still a @TODO due to import hooking. */
{
	return 0;
}

DECL_EXTERN_API(DWORD, PathGetTempFolderA, IN LPWSTR lpBuffer)
{
	return 0;
}

#define OBJ_NAME_PATH_SEPARATOR ((WCHAR) L'\\')

NTSTATUS NTAPI HcpWin32NTNameToNtPathName_U(IN PUNICODE_STRING 	DosPath,
	OUT PUNICODE_STRING 	NtPath,
	OUT PCWSTR * 	PartName,
	OUT PRTL_RELATIVE_NAME_U 	RelativeName
)
{
	ULONG DosLength;
	PWSTR NewBuffer, p;

	/* Validate the input */
	if (!DosPath) return STATUS_OBJECT_NAME_INVALID;

	/* Validate the DOS length */
	DosLength = DosPath->Length;
	if (DosLength >= UNICODE_STRING_MAX_BYTES) return STATUS_NAME_TOO_LONG;

	/* Make space for the new path */
	NewBuffer = HcAlloc(DosLength + sizeof(UNICODE_NULL));
	if (!NewBuffer) return STATUS_NO_MEMORY;

	/* Copy the prefix, and then the rest of the DOS path, and NULL-terminate */
	HcInternalCopy(NewBuffer, RtlpDosDevicesPrefix.Buffer, RtlpDosDevicesPrefix.Length);
	HcInternalCopy((PCHAR) NewBuffer + RtlpDosDevicesPrefix.Length,
		DosPath->Buffer + RtlpDosDevicesPrefix.Length / sizeof(WCHAR),
		DosPath->Length - RtlpDosDevicesPrefix.Length);
	NewBuffer[DosLength / sizeof(WCHAR)] = UNICODE_NULL;

	/* Did the caller send a relative name? */
	if (RelativeName)
	{
		/* Zero initialize it */
		RelativeName->RelativeName.Buffer = NULL;
		RelativeName->RelativeName.Length = 0;
		RelativeName->RelativeName.MaximumLength = 0;

		RelativeName->ContainingDirectory = NULL;
		RelativeName->CurDirRef = 0;
	}

	/* Did the caller request a partial name? */
	if (PartName)
	{
		/* Loop from the back until we find a path separator */
		p = &NewBuffer[DosLength / sizeof(WCHAR)];
		while (--p > NewBuffer)
		{
			/* We found a path separator, move past it */
			if (*p == OBJ_NAME_PATH_SEPARATOR)
			{
				++p;
				break;
			}
		}

		/* Check whether a separator was found and if something remains */
		if ((p > NewBuffer) && *p)
		{
			/* What follows the path separator is the partial name */
			*PartName = p;
		}
		else
		{
			/* The path ends with a path separator, no partial name */
			*PartName = NULL;
		}
	}

	/* Build the final NT path string */
	NtPath->Buffer = NewBuffer;
	NtPath->Length = (USHORT) DosLength;
	NtPath->MaximumLength = (USHORT) DosLength + sizeof(UNICODE_NULL);
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI HcpDosPathNameToRelativeNtPathName_Ustr(IN BOOLEAN 	HaveRelative,
	IN PUNICODE_STRING 	DosName,
	OUT PUNICODE_STRING 	NtName,
	OUT PCWSTR * 	PartName,
	OUT PRTL_RELATIVE_NAME_U 	RelativeName
)
{
	WCHAR BigBuffer[MAX_PATH + 1];
	PWCHAR PrefixBuffer, NewBuffer, Buffer;
	ULONG MaxLength, PathLength, PrefixLength, PrefixCut, LengthChars, Length;
	UNICODE_STRING CapturedDosName, PartNameString, FullPath;
	BOOLEAN QuickPath;
	RTL_PATH_TYPE InputPathType, BufferPathType;
	NTSTATUS Status;
	BOOLEAN NameInvalid;
	PCURDIR CurrentDirectory;

	MaxLength = sizeof(BigBuffer);
	Buffer = NULL;

	/* Validate the input */
	if (!DosName) return STATUS_OBJECT_NAME_INVALID;

	/* Capture input string */
	CapturedDosName = *DosName;

	/* Check for the presence or absence of the NT prefix "\\?\" form */
	// if (!RtlPrefixUnicodeString(&RtlpWin32NtRootSlash, &CapturedDosName, FALSE))
	if ((CapturedDosName.Length <= RtlpWin32NtRootSlash.Length) ||
		(CapturedDosName.Buffer[0] != RtlpWin32NtRootSlash.Buffer[0]) ||
		(CapturedDosName.Buffer[1] != RtlpWin32NtRootSlash.Buffer[1]) ||
		(CapturedDosName.Buffer[2] != RtlpWin32NtRootSlash.Buffer[2]) ||
		(CapturedDosName.Buffer[3] != RtlpWin32NtRootSlash.Buffer[3]))
	{
		/* NT prefix not present */

		/* Quick path won't be used */
		QuickPath = FALSE;

		/* Use the static buffer */
		Buffer = BigBuffer;
		MaxLength += RtlpDosDevicesUncPrefix.Length;

		/* Allocate a buffer to hold the path */
		NewBuffer = HcAlloc(MaxLength);
		if (!NewBuffer) return STATUS_NO_MEMORY;
	}
	else
	{
		/* NT prefix present */

		/* Use the optimized path after acquiring the lock */
		QuickPath = TRUE;
		NewBuffer = NULL;
	}

	if (QuickPath)
	{
		Status = HcpWin32NTNameToNtPathName_U(&CapturedDosName,
			NtName,
			PartName,
			RelativeName);

		return Status;
	}

	/* Call the main function to get the full path name and length */
	PathLength = HcGetFullPathName_Ustr(&CapturedDosName,
		MAX_PATH * sizeof(WCHAR),
		Buffer,
		PartName,
		&NameInvalid,
		&InputPathType);

	if ((NameInvalid) || !(PathLength) || (PathLength > (MAX_PATH * sizeof(WCHAR))))
	{
		/* Invalid name, fail */
		HcFree(NewBuffer);
		return STATUS_OBJECT_NAME_INVALID;
	}

	/* Start by assuming the path starts with \??\ (DOS Devices Path) */
	PrefixLength = RtlpDosDevicesPrefix.Length;
	PrefixBuffer = RtlpDosDevicesPrefix.Buffer;
	PrefixCut = 0;

	/* Check where it really is */
	BufferPathType = HcDetermineDosPathNameType_U(Buffer);
	switch (BufferPathType)
	{
		/* It's actually a UNC path in \??\UNC\ */
		case RtlPathTypeUncAbsolute:
		PrefixLength = RtlpDosDevicesUncPrefix.Length;
		PrefixBuffer = RtlpDosDevicesUncPrefix.Buffer;
		PrefixCut = 2;
		break;

		case RtlPathTypeLocalDevice:
		/* We made a good guess, go with it but skip the \??\ */
		PrefixCut = 4;
		break;

		case RtlPathTypeDriveAbsolute:
		case RtlPathTypeDriveRelative:
		case RtlPathTypeRooted:
		case RtlPathTypeRelative:
		/* Our guess was good, roll with it */
		break;

		/* Nothing else is expected */
		default:
		ASSERT(FALSE);
	}

	/* Now copy the prefix and the buffer */
	HcInternalCopy(NewBuffer, PrefixBuffer, PrefixLength);
	HcInternalCopy((PCHAR) NewBuffer + PrefixLength,
		Buffer + PrefixCut,
		PathLength - (PrefixCut * sizeof(WCHAR)));

	/* Compute the length */
	Length = PathLength + PrefixLength - PrefixCut * sizeof(WCHAR);
	LengthChars = Length / sizeof(WCHAR);

	/* Setup the actual NT path string and terminate it */
	NtName->Buffer = NewBuffer;
	NtName->Length = (USHORT) Length;
	NtName->MaximumLength = (USHORT) MaxLength;
	NewBuffer[LengthChars] = UNICODE_NULL;

	/* Check if a partial name was requested */
	if ((PartName) && (*PartName))
	{
		/* Convert to Unicode */
		Status = HcInitUnicodeStringEx(&PartNameString, *PartName);
		if (NT_SUCCESS(Status))
		{
			/* Set the partial name */
			*PartName = &NewBuffer[LengthChars - (PartNameString.Length / sizeof(WCHAR))];
		}
		else
		{
			/* Fail */
			HcFree(NewBuffer);
			return Status;
		}
	}

	/* Check if a relative name was asked for */
	if (RelativeName)
	{
		/* Setup the structure */
		RelativeName->RelativeName.Buffer = NULL;
		RelativeName->RelativeName.Length = 0;
		RelativeName->RelativeName.MaximumLength = 0;

		RelativeName->ContainingDirectory = NULL;

		/* Check if the input path itself was relative */
		if (InputPathType == RtlPathTypeRelative)
		{
			/* Get current directory */
			CurrentDirectory = &(NtCurrentPeb()->ProcessParameters->CurrentDirectory);
			if (CurrentDirectory->Handle)
			{
				Status = HcInitUnicodeStringEx(&FullPath, Buffer);
				if (!NT_SUCCESS(Status))
				{
					HcFree(NewBuffer);
					return Status;
				}

				/* If current directory is bigger than full path, there's no way */
				if (CurrentDirectory->DosPath.Length > FullPath.Length)
				{
					return Status;
				}

				/* File is in current directory */
				if (HcEqualUnicodeString(&FullPath, &CurrentDirectory->DosPath, TRUE))
				{
					/* Make relative name string */
					RelativeName->RelativeName.Buffer = (PWSTR) ((ULONG_PTR) NewBuffer + PrefixLength + FullPath.Length - PrefixCut * sizeof(WCHAR));
					RelativeName->RelativeName.Length = (USHORT) (PathLength - FullPath.Length);
					/* If relative name starts with \, skip it */
					if (RelativeName->RelativeName.Buffer[0] == OBJ_NAME_PATH_SEPARATOR)
					{
						RelativeName->RelativeName.Buffer++;
						RelativeName->RelativeName.Length -= sizeof(WCHAR);
					}
					RelativeName->RelativeName.MaximumLength = RelativeName->RelativeName.Length;

					if (!HaveRelative)
					{
						RelativeName->ContainingDirectory = CurrentDirectory->Handle;
						return Status;
					}

					RelativeName->ContainingDirectory = CurrentDirectory->Handle;
				}
			}
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI HcpDosPathNameToRelativeNtPathName_U(IN BOOLEAN 	HaveRelative,
	IN PCWSTR 	DosName,
	OUT PUNICODE_STRING 	NtName,
	OUT PCWSTR * 	PartName,
	OUT PRTL_RELATIVE_NAME_U 	RelativeName
)
{
	NTSTATUS Status;
	UNICODE_STRING NameString;

	/* Create the unicode name */
	Status = HcInitUnicodeStringEx(&NameString, DosName);
	if (NT_SUCCESS(Status))
	{
		/* Call the unicode function */
		Status = HcpDosPathNameToRelativeNtPathName_Ustr(HaveRelative,
			&NameString,
			NtName,
			PartName,
			RelativeName);
	}

	/* Return status */
	return Status;
}

BOOLEAN NTAPI HcDosPathNameToNtPathName_U(IN PCWSTR 	DosName,
	OUT PUNICODE_STRING 	NtName,
	OUT PCWSTR * 	PartName,
	OUT PRTL_RELATIVE_NAME_U 	RelativeName
)
{
	/* Call the internal function */
	return NT_SUCCESS(HcpDosPathNameToRelativeNtPathName_U(FALSE,
		DosName,
		NtName,
		PartName,
		RelativeName));
}