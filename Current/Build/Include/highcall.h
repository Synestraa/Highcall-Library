#ifndef HIGHCALL_H
#define HIGHCALL_H

#include "../../public/base.h"
#include "../../private/sys/syscall.h"
#include "../../public/imports.h"

#define LODWORD(x)  (*((DWORD*)&(x)))  // low dword
#define HIDWORD(x)  (*((DWORD*)&(x)+1))

#pragma region FILE definitions
typedef struct _HC_FILE_INFORMATIONA
{
	DWORD Size;
} HC_FILE_INFORMATIONA, *PHC_FILE_INFORMATIONA;

typedef struct _HC_FILE_INFORMATIONW
{
	DWORD Size;
} HC_FILE_INFORMATIONW, *PHC_FILE_INFORMATIONW;

//
// Define the access check value for any access
//

#define FILE_ANY_ACCESS                 0
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define FILE_WRITE_ACCESS         ( 0x0002 )    // file & pipe

//
// Define access rights to files and directories
//

#define FILE_READ_DATA            ( 0x0001 )    // file & pipe
#define FILE_LIST_DIRECTORY       ( 0x0001 )    // directory

#define FILE_WRITE_DATA           ( 0x0002 )    // file & pipe
#define FILE_ADD_FILE             ( 0x0002 )    // directory

#define FILE_APPEND_DATA          ( 0x0004 )    // file
#define FILE_ADD_SUBDIRECTORY     ( 0x0004 )    // directory
#define FILE_CREATE_PIPE_INSTANCE ( 0x0004 )    // named pipe

#define FILE_READ_EA              ( 0x0008 )    // file & directory

#define FILE_WRITE_EA             ( 0x0010 )    // file & directory

#define FILE_EXECUTE              ( 0x0020 )    // file
#define FILE_TRAVERSE             ( 0x0020 )    // directory

#define FILE_DELETE_CHILD         ( 0x0040 )    // directory

#define FILE_READ_ATTRIBUTES      ( 0x0080 )    // all

#define FILE_WRITE_ATTRIBUTES     ( 0x0100 )    // all

#define FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)

#define FILE_GENERIC_READ         (STANDARD_RIGHTS_READ     |\
                                   FILE_READ_DATA           |\
                                   FILE_READ_ATTRIBUTES     |\
                                   FILE_READ_EA             |\
                                   SYNCHRONIZE)


#define FILE_GENERIC_WRITE        (STANDARD_RIGHTS_WRITE    |\
                                   FILE_WRITE_DATA          |\
                                   FILE_WRITE_ATTRIBUTES    |\
                                   FILE_WRITE_EA            |\
                                   FILE_APPEND_DATA         |\
                                   SYNCHRONIZE)


#define FILE_GENERIC_EXECUTE      (STANDARD_RIGHTS_EXECUTE  |\
                                   FILE_READ_ATTRIBUTES     |\
                                   FILE_EXECUTE             |\
                                   SYNCHRONIZE)


//
// Define share access rights to files and directories
//

#define FILE_SHARE_READ                 0x00000001  // winnt
#define FILE_SHARE_WRITE                0x00000002  // winnt
#define FILE_SHARE_DELETE               0x00000004  // winnt
#define FILE_SHARE_VALID_FLAGS          0x00000007

//
// Define the file attributes values
//

#define FILE_ATTRIBUTE_READONLY         0x00000001  // winnt
#define FILE_ATTRIBUTE_HIDDEN           0x00000002  // winnt
#define FILE_ATTRIBUTE_SYSTEM           0x00000004  // winnt
#define FILE_ATTRIBUTE_DIRECTORY        0x00000010  // winnt
#define FILE_ATTRIBUTE_ARCHIVE          0x00000020  // winnt
#define FILE_ATTRIBUTE_NORMAL           0x00000080  // winnt
#define FILE_ATTRIBUTE_TEMPORARY        0x00000100  // winnt
#define FILE_ATTRIBUTE_RESERVED0        0x00000200
#define FILE_ATTRIBUTE_RESERVED1        0x00000400
#define FILE_ATTRIBUTE_COMPRESSED       0x00000800  // winnt
#define FILE_ATTRIBUTE_OFFLINE          0x00001000  // winnt
#define FILE_ATTRIBUTE_PROPERTY_SET     0x00002000
#define FILE_ATTRIBUTE_VALID_FLAGS      0x00003fb7
#define FILE_ATTRIBUTE_VALID_SET_FLAGS  0x00003fa7

//
// Define the create disposition values
//

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005


//
// Define the create/open option flags
//

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000


#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_TRANSACTED_MODE                    0x00200000
#define FILE_OPEN_OFFLINE_FILE                  0x00400000

#define FILE_VALID_OPTION_FLAGS                 0x007fffff
#define FILE_VALID_PIPE_OPTION_FLAGS            0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS        0x00000032
#define FILE_VALID_SET_FLAGS                    0x00000036

//
// Define the I/O status information return values for NtCreateFile/NtOpenFile
//

#define FILE_SUPERSEDED                 0x00000000
#define FILE_OPENED                     0x00000001
#define FILE_CREATED                    0x00000002
#define FILE_OVERWRITTEN                0x00000003
#define FILE_EXISTS                     0x00000004
#define FILE_DOES_NOT_EXIST             0x00000005

//
// Define special ByteOffset parameters for read and write operations
//

#define FILE_WRITE_TO_END_OF_FILE       0xffffffff
#define FILE_USE_FILE_POINTER_POSITION  0xfffffffe

//
// Define alignment requirement values
//

#define FILE_BYTE_ALIGNMENT             0x00000000
#define FILE_WORD_ALIGNMENT             0x00000001
#define FILE_LONG_ALIGNMENT             0x00000003
#define FILE_QUAD_ALIGNMENT             0x00000007
#define FILE_OCTA_ALIGNMENT             0x0000000f
#define FILE_32_BYTE_ALIGNMENT          0x0000001f
#define FILE_64_BYTE_ALIGNMENT          0x0000003f
#define FILE_128_BYTE_ALIGNMENT         0x0000007f
#define FILE_256_BYTE_ALIGNMENT         0x000000ff
#define FILE_512_BYTE_ALIGNMENT         0x000001ff

#define FILE_FLAG_WRITE_THROUGH         0x80000000
#define FILE_FLAG_OVERLAPPED            0x40000000
#define FILE_FLAG_NO_BUFFERING          0x20000000
#define FILE_FLAG_RANDOM_ACCESS         0x10000000
#define FILE_FLAG_SEQUENTIAL_SCAN       0x08000000
#define FILE_FLAG_DELETE_ON_CLOSE       0x04000000
#define FILE_FLAG_BACKUP_SEMANTICS      0x02000000
#define FILE_FLAG_POSIX_SEMANTICS       0x01000000
#define FILE_FLAG_SESSION_AWARE         0x00800000
#define FILE_FLAG_OPEN_REPARSE_POINT    0x00200000
#define FILE_FLAG_OPEN_NO_RECALL        0x00100000
#define FILE_FLAG_FIRST_PIPE_INSTANCE   0x00080000

#define FILE_OPEN_REMOTE_INSTANCE         0x00000400
#define FILE_RANDOM_ACCESS                0x00000800
#define FILE_DELETE_ON_CLOSE              0x00001000
#define FILE_OPEN_BY_FILE_ID              0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT       0x00004000
#define FILE_NO_COMPRESSION               0x00008000
#define FILE_RESERVE_OPFILTER             0x00100000
#define FILE_OPEN_REPARSE_POINT           0x00200000
#define FILE_OPEN_NO_RECALL               0x00400000

#define CREATE_NEW          1
#define CREATE_ALWAYS       2
#define OPEN_EXISTING       3
#define OPEN_ALWAYS         4
#define TRUNCATE_EXISTING   5

#define FILE_BEGIN           0
#define FILE_CURRENT         1
#define FILE_END             2

typedef struct _FILE_POSITION_INFORMATION {
	LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         NumberOfLinks;
	BOOLEAN       DeletePending;
	BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

/* file.c definitions end */
#pragma endregion

#pragma region HOOK definitions
typedef long HStatus;

#define HOOK_NO_ERR					(HStatus)0x0000
#define HOOK_INVALID_SOURCE			(HStatus)0x0001
#define HOOK_INVALID_DESTINATION	(HStatus)0x0002
#define HOOK_NOT_ENOUGH_SPACE		(HStatus)0x0003
#define HOOK_CAVE_FAILURE			(HStatus)0x0004
#define HOOK_INVALID_SIZE			(HStatus)0x0005
#define HOOK_FAILED_API				(HStatus)0x0006
#define HOOK_PROTECTION_FAILURE		(HStatus)0x0007
#define HOOK_INVALID_RESTORATION	(HStatus)0x0008
#define HOOK_INVALID_CLASS			(HStatus)0x0009

typedef enum _DetourType
{
	Relative	  = 1,
	Absolute	  = 2,
} DetourType;

typedef enum _DetourFlags
{
	Recreate = (1 << 0),
	Single = (1 << 1),
	SaveOriginal = (1 << 2),
	JumpOriginal = (1 << 3),
	Reconstruct = (1 << 4),
	THISCALL = (1 << 5),
	Default = ((int)Recreate | JumpOriginal | SaveOriginal),
} DetourFlags;

typedef struct _DetourContext
{
	/*
	--	*Required IN.
	--	Where it will be originated from.
	*/
	LPVOID lpSource;

	/*
	--	*Required IN.
	--	Where this hook will lead to.
	*/
	LPVOID lpDestination;

	/*
	--	OUT.
	--	Length of the detour.
	*/
	DWORD dwLength;

	/*
	--	OUT.
	--	Original function pointer.
	-- ** Contains relocation fixes.
	*/
	PBYTE pbReconstructed;

	/*
	--	OUT.
	--	Original function bytes;
	*/
	PBYTE pbOriginal;

	/*
	--	IN/OUT.
	--	Hook type. [Relative/Absolute]
	*/
	DetourType Type;

	//
	// IN
	//
	DetourFlags Flags;

	LPVOID lpClass;

} DetourContext, *PDetourContext;

#ifndef _WIN64
#define BitScanForwardT     _BitScanForward
#define BitScanReverseT     _BitScanReverse
#define BitTestAndSetT      _bittestandset
#define BitTestAndResetT    _bittestandreset
#else
#define BitScanForwardT     _BitScanForward64
#define BitScanReverseT     _BitScanReverse64
#define BitTestAndSetT      _bittestandset64
#define BitTestAndResetT    _bittestandreset64
#endif
#pragma endregion

#pragma region MODULE definitions
typedef struct {
	SIZE_T		Size;
	PVOID		Base;
	CHAR		Name[MAX_PATH];
	CHAR		Path[MAX_PATH];
} ModuleInformationA, *PModuleInformationA;

typedef struct {
	SIZE_T		Size;
	PVOID		Base;
	WCHAR		Name[MAX_PATH];
	WCHAR		Path[MAX_PATH];
} ModuleInformationW, *PModuleInformationW;

typedef BOOLEAN(CALLBACK *ModuleCallbackA)(ModuleInformationA, LPARAM);
typedef BOOLEAN(CALLBACK *ModuleCallbackW)(ModuleInformationW, LPARAM);

#ifdef _WIN64
#define HcModuleProcedureA(x, y) ((LPBYTE) HcModuleProcedureAddress64A((ULONG64)(x), y))
#define HcModuleProcedureW(x, y) ((LPBYTE) HcModuleProcedureAddress64W((ULONG64)(x), y))
#else							 
#define HcModuleProcedureA(x, y) ((LPBYTE) HcModuleProcedureAddress32A((ULONG_PTR)(x), y))
#define HcModuleProcedureW(x, y) ((LPBYTE) HcModuleProcedureAddress32W((ULONG_PTR)(x), y))
#endif
#pragma endregion

#pragma region PROCESS definitions
typedef struct {
	DWORD				Id;
	CHAR				Name[MAX_PATH];
	ModuleInformationA	MainModule;
	BOOLEAN				CanAccess;
	DWORD				ParentProcessId;
} PROCESS_INFORMATION_EX_A, *PPROCESS_INFORMATION_EX_A;

typedef struct
{
	DWORD				Id;
	WCHAR				Name[MAX_PATH];
	ModuleInformationW	MainModule;
	BOOLEAN				CanAccess;
	DWORD				ParentProcessId;
} PROCESS_INFORMATION_EX_W, *PPROCESS_INFORMATION_EX_W;

typedef struct {
	DWORD Id;
	CHAR Name[MAX_PATH];
	DWORD ParentProcessId;
} PROCESS_INFORMATION_A, *PPROCESS_INFORMATION_A;

typedef struct 
{
	DWORD Id;
	WCHAR Name[MAX_PATH];
	DWORD ParentProcessId;
} PROCESS_INFORMATION_W, *PPROCESS_INFORMATION_W;

typedef union {
	ULONG_PTR Flags;
	union {
		struct {
			ULONG_PTR Valid : 1;
			ULONG_PTR ShareCount : 3;
			ULONG_PTR Win32Protection : 11;
			ULONG_PTR Shared : 1;
			ULONG_PTR Node : 6;
			ULONG_PTR Locked : 1;
			ULONG_PTR LargePage : 1;
			ULONG_PTR Reserved : 7;
			ULONG_PTR Bad : 1;

#if defined(_WIN64)
			ULONG_PTR ReservedUlong : 32;
#endif
		};
		struct {
			ULONG_PTR Valid : 1;            // Valid = 0 in this format.
			ULONG_PTR Reserved0 : 14;
			ULONG_PTR Shared : 1;
			ULONG_PTR Reserved1 : 15;
			ULONG_PTR Bad : 1;

#if defined(_WIN64)
			ULONG_PTR ReservedUlong : 32;
#endif
		} Invalid;
	};
} WORKING_SET_EX_DATA_BLOCK, *PWORKING_SET_EX_DATA_BLOCK;

typedef struct {
	PVOID VirtualAddress;
	WORKING_SET_EX_DATA_BLOCK VirtualAttributes;
} WORKING_SET_EX_DATA, *PWORKING_SET_EX_DATA;

typedef BOOLEAN(CALLBACK *ProcessCallbackExA)(CONST PROCESS_INFORMATION_EX_A, LPARAM);
typedef BOOLEAN(CALLBACK *ProcessCallbackExW)(CONST PROCESS_INFORMATION_EX_W, LPARAM);
typedef BOOLEAN(CALLBACK *ProcessCallbackA)(CONST PROCESS_INFORMATION_A Entry, LPARAM lParam);
typedef BOOLEAN(CALLBACK *ProcessCallbackW)(CONST PROCESS_INFORMATION_W Entry, LPARAM lParam);
#pragma endregion

#pragma region INTERNAL definitons
#define USER_MAX_ADDRESS_64 0x7fffffffffffffff
#define USER_MAX_ADDRESS_32 0x7FFFFFFF

#ifdef _WIN64
#define USER_MAX_ADDRESS USER_MAX_ADDRESS_64
#else
#define USER_MAX_ADDRESS USER_MAX_ADDRESS_32
#endif

#define USER_MIN_ADDRESS 0x00000000

#define POINTER32_HARDCODED(Type) (Type) (ULONG_PTR)
#define POINTER64_HARDCODED(Type) (Type) (ULONG64)

#define POINTER_32BIT(x) (ULONG) ((ULONG_PTR) (x))

#define HcInternalMainModule(pmi) (HcModuleQueryInformationExW(NtCurrentProcess(), NULL, pmi)) 

#define HcInternalReadInt32(lpcAddress) ((INT)(HcInternalValidate(lpcAddress) ? (*(DWORD*)(lpcAddress)) : 0))
#define HcInternalReadInt64(lpcAddress) ((INT64)(HcInternalValidate(lpcAddress) ? (*(DWORD64*)lpcAddress) : 0))

#define HcInternalReadStringExA(lpcAddress, ptOffsets, tCount) ((LPSTR)HcInternalLocatePointer(lpcAddress, ptOffsets, tCount))
#define HcInternalReadStringExW(lpcAddress, ptOffsets, tCount) ((LPWSTR)HcInternalLocatePointer(lpcAddress, ptOffsets, tCount))

#define ZERO(x) { HcInternalSet(x, 0, sizeof(*(x))); }
#pragma endregion

#pragma region OBJECT definitions

typedef BOOLEAN(CALLBACK *HandleEntryCallback)(CONST PSYSTEM_HANDLE_TABLE_ENTRY_INFO Entry, LPARAM lParam);
typedef BOOLEAN(CALLBACK *HandleCallback)(CONST HANDLE Handle, CONST HANDLE hOwner, LPARAM lParam);

#define OBJECT_TYPE_ANY	-1
#pragma endregion

#pragma region STRING definitions
#define HcStringAnsiLengthToUnicode(size) (size * sizeof(WCHAR))
#define HcStringUnicodeLengthToAnsi(size) (size / sizeof(WCHAR))

#define TERMINATE_A(lpStr, size) (lpStr[size] = ANSI_NULL)
#define TERMINATE_W(lpStr, size) (lpStr[size] = UNICODE_NULL)

//
// Determines whether the pointer is invalid.
//
#define HcStringIsBad(lpcStr) (!HcInternalValidate((LPVOID)lpcStr))

//
// Determines whether the pointer to a string is invalid or empty (""). 
//
#define HcStringIsNullOrEmpty(lpcStr) (HcStringIsBad(lpcStr) || lpcStr[0] == 0)
#pragma endregion

#pragma region VIRTUAL definitions
//
// defines from virtual.h
// 
#define MAP_PROCESS 1
#define MAP_SYSTEM 2

#pragma endregion

#pragma region VOLUME definitions

typedef struct _FILE_FS_VOLUME_INFORMATION {
	LARGE_INTEGER	VolumeCreationTime;
	ULONG		VolumeSerialNumber;
	ULONG		VolumeLabelLength;
	BOOLEAN		SupportsObjects;
	WCHAR		VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION, *PFILE_FS_VOLUME_INFORMATION;

typedef struct _FILE_FS_ATTRIBUTE_INFORMATION {
	ULONG	FileSystemAttribute;
	LONG	MaximumComponentNameLength;
	ULONG	FileSystemNameLength;
	WCHAR	FileSystemName[1];
} FILE_FS_ATTRIBUTE_INFORMATION, *PFILE_FS_ATTRIBUTE_INFORMATION;

#define FS_VOLUME_BUFFER_SIZE (MAX_PATH * sizeof(WCHAR) + sizeof(FILE_FS_VOLUME_INFORMATION))
#define FS_ATTRIBUTE_BUFFER_SIZE (MAX_PATH * sizeof(WCHAR) + sizeof(FILE_FS_ATTRIBUTE_INFORMATION))

#pragma endregion

#pragma region UTILS definitions

typedef struct {
	WCHAR sLanguage[80];
	WCHAR iCountry[80];
	WCHAR sCountry[80];
	WCHAR sList[80];
	WCHAR iMeasure[80];
	WCHAR iPaperSize[80];
	WCHAR sDecimal[80];
	WCHAR sThousand[80];
	WCHAR sGrouping[80];
	WCHAR iDigits[80];
	WCHAR iLZero[80];
	WCHAR iNegNumber[80];
	WCHAR sNativeDigits[80];
	WCHAR NumShape[80];
	WCHAR sCurrency[80];
	WCHAR sMonDecSep[80];
	WCHAR sMonThouSep[80];
	WCHAR sMonGrouping[80];
	WCHAR iCurrDigits[80];
	WCHAR iCurrency[80];
	WCHAR iNegCurr[80];
	WCHAR sPositiveSign[80];
	WCHAR sNegativeSign[80];
	WCHAR sTimeFormat[80];
	WCHAR sTime[80];
	WCHAR iTime[80];
	WCHAR iTLZero[80];
	WCHAR iTimePrefix[80];
	WCHAR s1159[80];
	WCHAR s2359[80];
	WCHAR sShortDate[80];
	WCHAR sDate[80];
	WCHAR iDate[80];
	WCHAR sYearMonth[80];
	WCHAR sLongDate[80];
	WCHAR iCalType[80];
	WCHAR iFirstDayOfWeek[80];
	WCHAR iFirstWeekOfYear[80];
	WCHAR Locale[80];
	LCID UserLocaleId;
	LUID InteractiveUserLuid;
	ULONG ulCacheUpdateCount;
} NLS_USER_INFO, *PNLS_USER_INFO;

// Class 3
typedef struct {
	LARGE_INTEGER BootTime;
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER TimeZoneBias;
	ULONG TimeZoneId;
	ULONG Reserved;
#if (NTDDI_VERSION >= NTDDI_WIN2K)
	ULONGLONG BootTimeBias;
	ULONGLONG SleepTimeBias;
#endif
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

typedef struct {
	ULONG LowPart;
	LONG High1Time;
	LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef struct {
	UNICODE_STRING WindowsDirectory;
	UNICODE_STRING WindowsSystemDirectory;
	UNICODE_STRING NamedObjectDirectory;
	USHORT WindowsMajorVersion;
	USHORT WindowsMinorVersion;
	USHORT BuildNumber;
	USHORT CSDNumber;
	USHORT RCNumber;
	WCHAR CSDVersion[128];
	SYSTEM_BASIC_INFORMATION SysInfo;
	SYSTEM_TIMEOFDAY_INFORMATION TimeOfDay;
	PVOID IniFileMapping;
	NLS_USER_INFO NlsUserInfo;
	BOOLEAN DefaultSeparateVDM;
	BOOLEAN IsWowTaskReady;
	UNICODE_STRING WindowsSys32x86Directory;
	BOOLEAN fTermsrvAppInstallMode;
	TIME_ZONE_INFORMATION tziTermsrvClientTimeZone;
	KSYSTEM_TIME ktTermsrvClientBias;
	ULONG TermsrvClientTimeZoneId;
	BOOLEAN LUIDDeviceMapsEnabled;
	ULONG TermsrvClientTimeZoneChangeNum;
} BASE_STATIC_SERVER_DATA, *PBASE_STATIC_SERVER_DATA;
#pragma endregion

#pragma region IMAGE definitions

#define SWAPD(x) ((((x)&0xff)<<24)|(((x)&0xff00)<<8)|(((x)>>8)&0xff00)|(((x)>>24)&0xff))
#define SWAPW(x) ((((x)&0xff)<<8)|(((x)>>8)&0xff))
#define SUBTRACT_PTR_32(x, y) (ULONG) (ULONG_PTR) ((ULONG_PTR)(x) - (ULONG_PTR)(y));
#define SUBTRACT_PTR_64(x, y) (ULONG64) ((ULONG64)(x) - (ULONG64)(y);)
#define SUBTRACT_PTR(x, y) (ULONG_PTR)(x) - (ULONG_PTR)(y);

#pragma endregion

#pragma region SCAN definitions
#define NT_GLOBAL_FLAG_DEBUGGED (0x70)

typedef VOID(CALLBACK* ScanPageMineTrigger)(LPVOID Page, NTSTATUS Status);

typedef struct {
	ULONG				MineAmount;
	LPVOID*				Pages;
	ULONG				Flags;
} SCAN_PAGE_MINES, *PSCAN_PAGE_MINES;

#pragma endregion

#pragma region Globals

typedef enum {
	undefined = 0,
	x86 = 1,
	x86_x64 = 2
} Architecture_Type;

typedef struct {
	/* Is the process running with administrative privileges? */
	BOOLEAN IsElevated;
	/* highcall defined version. */
	ULONG WindowsVersion;
	Architecture_Type ProcessorArchitecture;
	/* Is the program running in Wow64? */
	BOOLEAN IsWow64;
	/* The base of kernel32.dll */
	HMODULE HandleKernel32;
	/* The base of ntdll.dll */
	HMODULE HandleNtdll;
	/* The base of user32.dll */
	HMODULE HandleUser32;
	/* our HMODULE */
	HMODULE HandleCurrent;

	/* CSRSS */
	PBASE_STATIC_SERVER_DATA BaseStaticServerData;
	HANDLE BaseNamedObjectDirectory; 

	/* User */
	PUSER_HANDLE_TABLE HandleTable;
	PUSER_HANDLE_ENTRY HandleEntries;
	PSERVERINFO psi;
	SHAREDINFO SharedInfo;
	ULONG_PTR ulSharedDelta;
} HcGlobalEnv, *PHcGlobalEnv;

HC_GLOBAL HcGlobalEnv HcGlobal;

#define INITIALIZATION_ROUTINE __stdcall

#pragma endregion

//
// Purpose:
//	Defines a highcall API function signature.
//
// Parameters:
//
//	The return type.
//	The name.
//	The rest of the parameters.
// 
#define DECL_EXTERN_API(ReturnType, Name, ...) HC_EXTERN_API ReturnType HCAPI Hc##Name (##__VA_ARGS__)

#if defined (__cplusplus)
extern "C" {
#endif

	/* implemented in highcall.c */
	NTSTATUS INITIALIZATION_ROUTINE HcInitialize();

	/* implemented in common.c */
	DECL_EXTERN_API(VOID, Sleep, CONST IN DWORD dwMilliseconds);

	/* implemented in error.c */
	DECL_EXTERN_API(VOID, ErrorSetDosError, CONST IN DWORD dwErrCode);
	DECL_EXTERN_API(DWORD, ErrorGetDosError);
	DECL_EXTERN_API(DWORD, ErrorSetNtStatus, CONST IN NTSTATUS Status);
	DECL_EXTERN_API(NTSTATUS, ErrorGetLastStatus);

	/* defined in file.c */
	DECL_EXTERN_API(BOOLEAN, FileExistsA, IN LPCSTR lpFilePath);
	DECL_EXTERN_API(BOOLEAN, FileExistsW, IN LPCWSTR lpFilePath);
	DECL_EXTERN_API(BOOLEAN, FileExists64W, IN LPCWSTR lpFilePath);
	DECL_EXTERN_API(BOOLEAN, FileMove64W, IN LPCWSTR lpFilePath, IN LPCWSTR lpDestinationPath);
	DECL_EXTERN_API(DWORD, FileSize, CONST IN HANDLE hFile);
	DECL_EXTERN_API(DWORD, FileSizeA, IN LPCSTR lpPath);
	DECL_EXTERN_API(DWORD, FileSizeW, IN LPCWSTR lpPath);
	DECL_EXTERN_API(ULONG, FileOffsetByExportNameA, IN HMODULE hModule OPTIONAL, IN LPCSTR lpExportName);
	DECL_EXTERN_API(ULONG, FileOffsetByExportNameW, IN HMODULE hModule OPTIONAL, IN LPCWSTR lpExportName);
	DECL_EXTERN_API(ULONG, FileOffsetByVirtualAddress, IN LPCVOID lpAddress);
	DECL_EXTERN_API(DWORD, FileReadModuleA, CONST IN HMODULE hModule, IN LPCSTR lpExportName, IN OUT PBYTE lpBuffer, CONST IN DWORD dwCount);
	DECL_EXTERN_API(DWORD, FileReadModuleW, CONST IN HMODULE hModule, IN LPCWSTR lpExportName, IN OUT PBYTE lpBuffer, CONST IN DWORD dwCount);
	DECL_EXTERN_API(DWORD, FileReadAddress, IN LPCVOID lpAddress, OUT PBYTE lpBufferOut, CONST IN DWORD dwCountToRead);
	DECL_EXTERN_API(DWORD, FileCurrentDirectoryA, IN LPSTR lpBuffer);
	DECL_EXTERN_API(DWORD, FileCurrentDirectoryW, IN LPWSTR lpBuffer);
	DECL_EXTERN_API(DWORD, FileWrite, CONST IN HANDLE hFile, IN LPCVOID lpBuffer, IN DWORD nNumberOfBytesToWrite);
	DECL_EXTERN_API(DWORD, FileWrite64, CONST IN HANDLE hFile, IN LPCVOID lpBuffer, IN DWORD nNumberOfBytesToWrite);
	DECL_EXTERN_API(DWORD, FileRead, CONST IN HANDLE hFile, IN OUT LPVOID lpBuffer, CONST IN DWORD nNumberOfBytesToRead);
	DECL_EXTERN_API(DWORD, FileSetCurrent, CONST IN HANDLE hFile, CONST IN LONG lDistanceToMove, CONST IN DWORD dwMoveMethod);
	DECL_EXTERN_API(HANDLE, FileOpenW, IN LPCWSTR lpFileName, IN DWORD dwCreationDisposition, IN DWORD dwDesiredAccess);
	DECL_EXTERN_API(HANDLE, FileOpenA, IN LPCSTR lpFileName, IN DWORD dwCreationDisposition, IN DWORD dwDesiredAccess);
	DECL_EXTERN_API(BOOLEAN, FileFlush, IN HANDLE hFile);
	DECL_EXTERN_API(NTSTATUS, OpenDirectoryObjectEx, OUT PHANDLE DirectoryHandle, IN ACCESS_MASK AccessMask, IN POBJECT_ATTRIBUTES ObjectAttributes);
	DECL_EXTERN_API(NTSTATUS, OpenSymbolicLinkObjectEx, OUT PHANDLE LinkHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
	DECL_EXTERN_API(NTSTATUS, QuerySymbolicLinkObjectEx, IN HANDLE LinkHandle, OUT PUNICODE_STRING LinkTarget, OUT PULONG ResultLength OPTIONAL);
	DECL_EXTERN_API(NTSTATUS, QueryDirectoryObjectEx, IN HANDLE DirectoryHandle, OUT PVOID Buffer, IN ULONG BufferLength, IN BOOLEAN ReturnSingleEntry, IN BOOLEAN RestartScan, IN OUT PULONG Context, OUT PULONG ReturnLength OPTIONAL);
	DECL_EXTERN_API(DWORD, QueryDosDeviceW, LPCWSTR lpDeviceName, LPWSTR lpTargetPath, DWORD ucchMax);

	/* defined in hook.c */
	DECL_EXTERN_API(HStatus, HookDetour, CONST IN PDetourContext Context);
	DECL_EXTERN_API(HStatus, HookDetourContextRestore, CONST IN PDetourContext Context);
	DECL_EXTERN_API(HStatus, HookRelocateCode, CONST IN PBYTE Code, IN DWORD Size, CONST IN PBYTE Source);
	DECL_EXTERN_API(PVOID, HookCreateCave32, IN LPVOID lpBaseAddress, CONST IN SIZE_T Size);
	DECL_EXTERN_API(PVOID, HookCreateCave64, IN LPVOID lpBaseAddress, CONST IN SIZE_T Size);
	DECL_EXTERN_API(DWORD, HookAssertLength, IN LPCVOID lpBaseAddress, CONST IN DWORD MinimumLength);
	DECL_EXTERN_API(PVOID, HookRecreateCode, CONST IN PBYTE lpBaseAddress, CONST IN DWORD dwMinimumSize);
	DECL_EXTERN_API(HStatus, HookHWBPRedirect, CONST IN PDetourContext Context);
	DECL_EXTERN_API(HStatus, HookHWBPRestore, CONST IN PDetourContext Context);
	DECL_EXTERN_API(BOOLEAN, HookHWBPToggle, CONST IN PDetourContext Context, BOOL State);

	/* defined in inject.c */
	DECL_EXTERN_API(BOOLEAN, InjectManualMap32W, CONST IN HANDLE hProcess, IN LPCWSTR szcPath);
	DECL_EXTERN_API(ULONG64 , InjectRemoteThreadLdr64W, CONST IN HANDLE hProcess, IN LPCWSTR szcPath);
	DECL_EXTERN_API(ULONG, InjectRemoteThreadLdr32W, CONST IN HANDLE hProcess, IN LPCWSTR szcPath);
	DECL_EXTERN_API(BOOLEAN, InjectRemoteThread64W, CONST IN HANDLE hProcess, IN LPCWSTR szcPath);
	DECL_EXTERN_API(BOOLEAN, InjectRemoteThread32W, CONST IN HANDLE hProcess, IN LPCWSTR szcPath);

	/* defined in process.c */
	DECL_EXTERN_API(BOOLEAN, ProcessCreateNativeW, IN LPWSTR lpPath, IN LPWSTR lpCommandLine);
	DECL_EXTERN_API(NTSTATUS, QuerySystemInformationInternal, IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT LPVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength,
		OUT LPVOID* SystemInformation64);

	DECL_EXTERN_API(NTSTATUS, QueryInformationProcessEx,
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT LPVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	DECL_EXTERN_API(NTSTATUS, ProcessFlushInstructionCache, CONST IN HANDLE ProcessHandle,
		CONST IN LPVOID BaseAddress,
		CONST IN SIZE_T NumberOfBytesToFlush);

	DECL_EXTERN_API(DWORD, ProcessGetCurrentId, VOID);
	DECL_EXTERN_API(DWORD, ProcessGetId, IN HANDLE Process);
	DECL_EXTERN_API(BOOLEAN, ProcessIsWow64Ex, CONST IN HANDLE hProcess);
	DECL_EXTERN_API(BOOLEAN, ProcessIsWow64, CONST IN DWORD dwProcessId);
	DECL_EXTERN_API(BOOLEAN, ProcessExitCode, CONST IN SIZE_T dwProcessId, OUT LPDWORD lpExitCode);
	DECL_EXTERN_API(BOOLEAN, ProcessExitCodeEx, CONST IN HANDLE hProcess, OUT LPDWORD lpExitCode);
	DECL_EXTERN_API(HANDLE, ProcessOpen, CONST IN SIZE_T dwProcessId, CONST IN ACCESS_MASK DesiredAccess);
	DECL_EXTERN_API(BOOLEAN, ProcessWriteMemory, CONST IN HANDLE hProcess, CONST IN LPVOID lpBaseAddress, CONST IN LPVOID lpBuffer, IN SIZE_T nSize, OUT PSIZE_T lpNumberOfBytesWritten);
	DECL_EXTERN_API(BOOLEAN, ProcessWriteMemory64, CONST IN HANDLE hProcess, CONST IN PVOID64 lpBaseAddress, CONST IN PVOID64 lpBuffer, IN ULONG64 nSize, OUT PULONG64 lpNumberOfBytesWritten);
	DECL_EXTERN_API(BOOLEAN, ProcessWriteMemoryWow64, CONST IN HANDLE hProcess, CONST IN PVOID64 lpBaseAddress, CONST IN PVOID64 lpBuffer, IN ULONG64 nSize, OUT PULONG64 lpNumberOfBytesWritten);
	DECL_EXTERN_API(BOOLEAN, ProcessReadMemory, CONST IN HANDLE hProcess, IN LPVOID lpBaseAddress, IN LPVOID lpBuffer, IN SIZE_T nSize, OUT PSIZE_T lpNumberOfBytesRead);
	DECL_EXTERN_API(BOOLEAN, ProcessReadMemoryWow64, CONST IN HANDLE hProcess, IN PVOID64 lpBaseAddress, IN PVOID64 lpBuffer, IN ULONG64 nSize, OUT PULONG64 lpNumberOfBytesRead);
	DECL_EXTERN_API(BOOLEAN, ProcessReadMemory64, CONST IN HANDLE hProcess, IN PVOID64 lpBaseAddress, IN PVOID64 lpBuffer, IN ULONG64 nSize, OUT PULONG64 lpNumberOfBytesRead);
	DECL_EXTERN_API(HANDLE, ProcessCreateThread, CONST IN HANDLE hProcess, CONST IN LPTHREAD_START_ROUTINE lpStartAddress, CONST IN LPVOID lpParamater, CONST IN DWORD dwCreationFlags);
	DECL_EXTERN_API(HANDLE, ProcessCreateThread64, CONST IN HANDLE hProcess, CONST IN DWORD64 lpStartAddress, CONST IN DWORD64 lpParameter, CONST IN DWORD dwCreationFlags);
	DECL_EXTERN_API(BOOLEAN, ProcessReadNullifiedString, CONST IN HANDLE hProcess, CONST IN PUNICODE_STRING usStringIn, OUT LPWSTR lpStringOut, CONST IN SIZE_T lpSize);
	DECL_EXTERN_API(BOOLEAN, ProcessReady, CONST IN SIZE_T dwProcessId);
	DECL_EXTERN_API(BOOLEAN, ProcessReadyEx, CONST IN HANDLE hProcess);
	DECL_EXTERN_API(BOOLEAN, ProcessSuspend, CONST IN SIZE_T dwProcessId);
	DECL_EXTERN_API(BOOLEAN, ProcessSuspendEx, CONST IN HANDLE hProcess);
	DECL_EXTERN_API(BOOLEAN, ProcessResume, CONST IN SIZE_T dwProcessId);
	DECL_EXTERN_API(BOOLEAN, ProcessResumeEx, CONST IN HANDLE hProcess);
	DECL_EXTERN_API(BOOLEAN, ProcessTerminate, CONST IN HANDLE hProcess, CONST IN NTSTATUS Status);
	DECL_EXTERN_API(BOOLEAN, ProcessGetById, CONST IN DWORD dwProcessId, OUT PPROCESS_INFORMATION_W pProcessInfo);
	DECL_EXTERN_API(BOOLEAN, ProcessGetByNameW, IN LPCWSTR lpName, OUT PPROCESS_INFORMATION_W pProcessInfo);
	DECL_EXTERN_API(BOOLEAN, ProcessGetAllByNameW, IN LPCWSTR lpName, OUT PROCESS_INFORMATION_W* ProcessList, OUT PULONG Count);
	DECL_EXTERN_API(BOOLEAN, ProcessEnumByNameW, IN LPCWSTR lpProcessName, IN ProcessCallbackW pCallback, IN LPARAM lParam);
	DECL_EXTERN_API(BOOLEAN, ProcessEnumByNameExW, IN LPCWSTR lpProcessName, IN ProcessCallbackExW pCallback, IN LPARAM lParam);
	DECL_EXTERN_API(BOOLEAN, ProcessSetPrivilegeA, CONST IN HANDLE hProcess, IN LPCSTR Privilege, CONST IN BOOLEAN bEnablePrivilege);
	DECL_EXTERN_API(BOOLEAN, ProcessSetPrivilegeW, CONST IN HANDLE hProcess, IN LPCWSTR Privilege, CONST IN BOOLEAN bEnablePrivilege);
	DECL_EXTERN_API(BOOLEAN, ProcessGetPebWow64, CONST IN HANDLE hProcess, OUT PPEB32 pPeb);
	DECL_EXTERN_API(BOOLEAN, ProcessGetPeb64, CONST IN HANDLE hProcess, OUT PPEB64 pPeb);
	DECL_EXTERN_API(BOOLEAN, ProcessGetPeb32, CONST IN HANDLE hProcess, OUT PPEB32 pPeb);
	DECL_EXTERN_API(BOOLEAN, ProcessGetPeb, CONST IN HANDLE hProcess, OUT PPEB pPeb);
	DECL_EXTERN_API(ULONG_PTR, ProcessGetExportAddressW, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, IN LPCWSTR lpExportSymbolName);
	DECL_EXTERN_API(ULONG_PTR, ProcessGetExportAddressA, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, IN LPCSTR lpExportSymbolName);
	DECL_EXTERN_API(ULONG_PTR, ProcessGetExportAddress32W, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, IN LPCWSTR lpExportSymbolName);
	DECL_EXTERN_API(ULONG_PTR, ProcessGetExportAddress32A, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, IN LPCSTR lpExportSymbolName);
	DECL_EXTERN_API(ULONG64, ProcessGetExportAddress64W, CONST IN HANDLE hProcess, CONST IN ULONG64 hModule, IN LPCWSTR lpExportSymbolName);
	DECL_EXTERN_API(ULONG64, ProcessGetExportAddress64A, CONST IN HANDLE hProcess, CONST IN ULONG64 hModule, IN LPCSTR lpExportSymbolName);
	DECL_EXTERN_API(DWORD, ProcessGetCommandLineA, CONST IN HANDLE hProcess, OUT LPSTR* lpszCommandline, CONST IN BOOLEAN bAlloc);
	DECL_EXTERN_API(DWORD, ProcessGetCommandLineW, CONST IN HANDLE hProcess, OUT LPWSTR* lpszCommandline, CONST IN BOOLEAN bAlloc);
	DECL_EXTERN_API(DWORD, ProcessGetCurrentDirectoryW, CONST IN HANDLE hProcess, OUT LPWSTR szDirectory);
	DECL_EXTERN_API(DWORD, ProcessGetCurrentDirectoryA, CONST IN HANDLE hProcess, OUT LPSTR szDirectory);
	DECL_EXTERN_API(BOOLEAN, ProcessQueryWorkingSetEx, IN HANDLE hProcess, OUT PWORKING_SET_EX_DATA Data);

	/* defined in internal.c */
	DECL_EXTERN_API(BOOLEAN, InternalCompare, IN PBYTE pbFirst, IN PBYTE pbSecond, IN SIZE_T tLength);
	DECL_EXTERN_API(PVOID, InternalCopy, IN PVOID pDst, IN LPCVOID pSrc, CONST IN SIZE_T tCount);
	DECL_EXTERN_API(PVOID, InternalMove, IN PVOID pDst, IN PVOID pSrc, IN SIZE_T tCount);
	DECL_EXTERN_API(PVOID, InternalSet, IN PVOID pDst, CONST IN BYTE bVal, IN SIZE_T tCount);
	DECL_EXTERN_API(PVOID, InternalZero, IN PVOID pDst, IN SIZE_T tCount);
	DECL_EXTERN_API(BOOLEAN, InternalValidate, IN LPCVOID lpcAddress);
	DECL_EXTERN_API(LPVOID, InternalLocatePointer, IN LPCVOID lpcAddress, CONST IN PSIZE_T ptOffsets, CONST IN SIZE_T tCount);
	DECL_EXTERN_API(INT, InternalReadIntEx32, IN LPCVOID lpcAddress, CONST IN PSIZE_T ptOffsets, CONST IN SIZE_T tCount);
	DECL_EXTERN_API(INT64, InternalReadIntEx64, IN LPCVOID lpcAddress, CONST IN PSIZE_T ptOffsets, CONST IN SIZE_T tCount);
	DECL_EXTERN_API(BOOLEAN, InternalMemoryWrite, IN LPVOID lpAddress, IN SIZE_T tLength, CONST IN PBYTE pbNew);
	DECL_EXTERN_API(BOOLEAN, InternalMemoryNopInstruction, IN LPVOID pAddress);
	DECL_EXTERN_API(LPBYTE, InternalPatternFind, IN LPCSTR Pattern, IN LPCSTR szcMask, CONST IN PModuleInformationW pModule);
	DECL_EXTERN_API(LPBYTE, InternalPatternFindInBuffer, IN LPCSTR szcPattern, IN LPBYTE lpBuffer, CONST IN SIZE_T Size);
	DECL_EXTERN_API(LPBYTE, InternalPatternFindCurrent, IN LPCSTR szcPattern);

	/* defined in module.c */
	DECL_EXTERN_API(PLDR_DATA_TABLE_ENTRY, ModuleEntryW, IN LPCWSTR lpModuleName, CONST IN BOOLEAN CaseInSensitive);
	DECL_EXTERN_API(BOOLEAN, ModuleEntryExW, IN HANDLE hProcess, IN HMODULE hModule OPTIONAL, OUT PLDR_DATA_TABLE_ENTRY pEntry);
	DECL_EXTERN_API(PLDR_DATA_TABLE_ENTRY, ModuleEntryBaseW, CONST IN HMODULE hModule);
	DECL_EXTERN_API(ULONG64, ModuleProcedureAddress64A, CONST IN ULONG64 hModule, IN LPCSTR lpProcedureName);
	DECL_EXTERN_API(ULONG64, ModuleProcedureAddress64W, CONST IN ULONG64 hModule, IN LPCWSTR lpProcedureName);
	DECL_EXTERN_API(ULONG_PTR, ModuleProcedureAddress32A, CONST IN ULONG_PTR hModule, IN LPCSTR lpProcedureName);
	DECL_EXTERN_API(ULONG_PTR, ModuleProcedureAddress32W, CONST IN ULONG_PTR hModule, IN LPCWSTR lpProcedureName);
	DECL_EXTERN_API(HMODULE, ModuleHandleA, IN LPCSTR lpModuleName);
	DECL_EXTERN_API(HMODULE, ModuleHandleW, IN LPCWSTR lpModuleName);
	DECL_EXTERN_API(HMODULE, ModuleHandleExW, IN LPCWSTR lpModuleName, CONST IN BOOLEAN CaseInSensitive);
	DECL_EXTERN_API(HMODULE, ModuleHandleWow64W, IN LPCWSTR lpModuleName);
	DECL_EXTERN_API(BOOLEAN, ModuleHide, CONST IN HMODULE hModule);
	DECL_EXTERN_API(HMODULE, ModuleLoadA, IN LPCSTR lpPath);
	DECL_EXTERN_API(HMODULE, ModuleLoadW, IN LPCWSTR lpPath);
	DECL_EXTERN_API(BOOLEAN, ModuleUnload, CONST IN HMODULE hModule);
	DECL_EXTERN_API(ULONG64, ModuleRemoteHandle64W, CONST IN HANDLE hProcess, IN LPCWSTR lpModuleName);
	DECL_EXTERN_API(BOOLEAN, ModuleRemoteEntry64W, CONST IN HANDLE hProcess, IN LPCWSTR lpModuleName, CONST IN BOOLEAN CaseInsensitive, PLDR_DATA_TABLE_ENTRY64 pLdrEntry);
	DECL_EXTERN_API(HMODULE, ModuleHandleAdvancedExW, CONST IN HANDLE ProcessHandle, IN LPCWSTR lpModuleName, IN BOOLEAN Bit32);
	DECL_EXTERN_API(HMODULE, ModuleHandleAdvancedExA, CONST IN HANDLE ProcessHandle, IN LPCSTR lpModuleName, IN BOOLEAN Bit32);
	DECL_EXTERN_API(HMODULE, ModuleHandleAdvancedW, IN LPCWSTR lpModuleName, CONST IN BOOLEAN bBit32);
	DECL_EXTERN_API(HMODULE, ModuleHandleAdvancedA, IN LPCSTR lpModuleName, CONST IN BOOLEAN bBit32);
	DECL_EXTERN_API(DWORD, ModulePathAdvancedExA, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, OUT LPSTR lpPath);
	DECL_EXTERN_API(DWORD, ModulePathAdvancedExW, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, OUT LPWSTR lpPath);
	DECL_EXTERN_API(DWORD, ModuleNameAdvancedExA, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, OUT LPSTR lpName);
	DECL_EXTERN_API(DWORD, ModuleNameAdvancedExW, CONST IN HANDLE hProcess, CONST IN HMODULE hModule, OUT LPWSTR lpName);
	DECL_EXTERN_API(BOOLEAN, ModuleQueryInformationExW, CONST IN HANDLE hProcess, IN HMODULE hModule OPTIONAL, OUT PModuleInformationW phcModuleOut);
	DECL_EXTERN_API(BOOLEAN, ModuleEnumExW, CONST IN HANDLE hProcess, CONST IN ModuleCallbackW pCallback, IN LPARAM lParam);
	DECL_EXTERN_API(BOOLEAN, ModuleEnumW, CONST IN ModuleCallbackW pCallback, IN LPARAM lParam);
	DECL_EXTERN_API(BOOLEAN, ModuleEnumAdvancedExW, CONST IN HANDLE ProcessHandle, CONST IN ModuleCallbackW pCallback, IN LPARAM lParam);
	DECL_EXTERN_API(BOOLEAN, ModuleEnumAdvancedW, CONST IN ModuleCallbackW pCallback, IN LPARAM lParam);
	DECL_EXTERN_API(DWORD, ModulePathA, CONST IN HANDLE hModule, OUT LPSTR lpPath);
	DECL_EXTERN_API(DWORD, ModulePathW, CONST IN HANDLE hModule, OUT LPWSTR lpPath);
	DECL_EXTERN_API(DWORD, ModuleNameA, CONST IN HMODULE hModule, OUT LPSTR lpName);
	DECL_EXTERN_API(DWORD, ModuleNameW, CONST IN HMODULE hModule, OUT LPWSTR lpName);
	DECL_EXTERN_API(DWORD, ModulePathAdvancedA, CONST IN HMODULE hModule, OUT LPSTR lpPath);
	DECL_EXTERN_API(DWORD, ModulePathAdvancedW, CONST IN HMODULE hModule, OUT LPWSTR lpPath);
	DECL_EXTERN_API(DWORD, ModuleNameAdvancedA, CONST IN HMODULE hModule, OUT LPSTR lpName);
	DECL_EXTERN_API(DWORD, ModuleNameAdvancedW, CONST IN HMODULE hModule, OUT LPWSTR lpName);
	DECL_EXTERN_API(ULONG, ModuleChecksum, CONST IN HMODULE hModule);
	DECL_EXTERN_API(PVOID, ModuleEntryPoint, CONST IN HMODULE hModule);
	DECL_EXTERN_API(ULONG, ModuleSize, CONST IN HMODULE hModule);
	DECL_EXTERN_API(SIZE_T, ModuleSizeEx, IN HANDLE ProcessHandle, HMODULE Module);
	DECL_EXTERN_API(BOOLEAN, ModuleConvertLdrEntryExW, CONST IN HANDLE hProcess, CONST IN PLDR_DATA_TABLE_ENTRY Module, OUT PModuleInformationW phcModuleOut);
	DECL_EXTERN_API(BOOLEAN, ModuleConvertLdrEntryW, CONST IN PLDR_DATA_TABLE_ENTRY Module, OUT PModuleInformationW phcModuleOut);
	DECL_EXTERN_API(HMODULE, ModuleRemoteHandle32W, CONST IN HANDLE hProcess, IN LPCWSTR lpModuleName);
	DECL_EXTERN_API(BOOLEAN, ModuleRemoteEntry32W, CONST IN HANDLE hProcess, IN LPCWSTR lpModuleName, CONST IN BOOLEAN CaseInsensitive, PLDR_DATA_TABLE_ENTRY pLdrEntry);
	DECL_EXTERN_API(DWORD, ModuleRemoteSize32, CONST IN HANDLE hProcess, IN HMODULE hModule);
	DECL_EXTERN_API(BOOLEAN, ModuleRemoteEntry32, CONST IN HANDLE hProcess, IN HMODULE hModule, PLDR_DATA_TABLE_ENTRY pLdrEntry);

	NTSTATUS
		NTAPI
		RtlCreateUserProcess(IN PUNICODE_STRING ImageFileName,
			IN ULONG Attributes,
			IN OUT PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
			IN PSECURITY_DESCRIPTOR ProcessSecurityDescriptor OPTIONAL,
			IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
			IN HANDLE ParentProcess OPTIONAL,
			IN BOOLEAN InheritHandles,
			IN HANDLE DebugPort OPTIONAL,
			IN HANDLE ExceptionPort OPTIONAL,
			OUT PRTL_USER_PROCESS_INFORMATION ProcessInfo);
	NTSTATUS
		NTAPI
		RtlpInitEnvironment(HANDLE ProcessHandle,
			PPEB Peb,
			PRTL_USER_PROCESS_PARAMETERS ProcessParameters);
	NTSTATUS
		NTAPI
		RtlpMapFile(PUNICODE_STRING ImageFileName,
			ULONG Attributes,
			PHANDLE Section);

	/*
	* @implemented
	*/
	BOOL
		WINAPI
		CreateProcessInternalW(IN HANDLE hUserToken,
			IN LPCWSTR lpApplicationName,
			IN LPWSTR lpCommandLine,
			IN LPSECURITY_ATTRIBUTES lpProcessAttributes,
			IN LPSECURITY_ATTRIBUTES lpThreadAttributes,
			IN BOOL bInheritHandles,
			IN DWORD dwCreationFlags,
			IN LPVOID lpEnvironment,
			IN LPCWSTR lpCurrentDirectory,
			IN LPSTARTUPINFOW lpStartupInfo,
			IN LPPROCESS_INFORMATION lpProcessInformation,
			OUT PHANDLE hNewToken);

	NTSTATUS NTAPI RtlCreateProcessParameters(PRTL_USER_PROCESS_PARAMETERS *ProcessParameters,
			PUNICODE_STRING ImagePathName,
			PUNICODE_STRING DllPath,
			PUNICODE_STRING CurrentDirectory,
			PUNICODE_STRING CommandLine,
			PWSTR Environment,
			PUNICODE_STRING WindowTitle,
			PUNICODE_STRING DesktopInfo,
			PUNICODE_STRING ShellInfo,
			PUNICODE_STRING RuntimeData); 
	NTSTATUS NTAPI RtlDestroyProcessParameters(IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

	/* defined in object.c */
	DECL_EXTERN_API(HANDLE, ObjectTranslateHandle, CONST IN HANDLE Handle);
	DECL_EXTERN_API(DWORD, ObjectTypeIndexByName, IN LPCWSTR lpObjectName);
	DECL_EXTERN_API(PLARGE_INTEGER, ObjectMillisecondsToNano, OUT PLARGE_INTEGER Timeout, CONST IN DWORD dwMiliseconds);
	DECL_EXTERN_API(DWORD, ObjectWaitMultiple, IN DWORD nCount, IN CONST PHANDLE lpHandles, IN BOOL bWaitAll, IN DWORD dwMilliseconds);
	DECL_EXTERN_API(DWORD, ObjectWait, IN HANDLE hObject, IN DWORD dwMiliseconds);
	DECL_EXTERN_API(VOID, ObjectClose, IN PHANDLE phObject);
	DECL_EXTERN_API(HANDLE, ObjectCreateEventW, IN LPSECURITY_ATTRIBUTES lpEventAttributes OPTIONAL, IN BOOL bManualReset, IN BOOL bInitialState, IN LPCWSTR lpName OPTIONAL);
	DECL_EXTERN_API(HANDLE, ObjectCreateEventA, IN LPSECURITY_ATTRIBUTES lpEventAttributes OPTIONAL, IN BOOL bManualReset, IN BOOL bInitialState, IN LPCSTR lpName OPTIONAL);
	DECL_EXTERN_API(HANDLE, ObjectCreateMutexW, IN LPSECURITY_ATTRIBUTES lpMutexAttributes OPTIONAL, IN BOOLEAN bInitialOwner, IN LPCWSTR lpName OPTIONAL);
	DECL_EXTERN_API(HANDLE, ObjectCreateMutexA, IN LPSECURITY_ATTRIBUTES lpMutexAttributes OPTIONAL, IN BOOLEAN bInitialOwner, IN LPCSTR lpName OPTIONAL);
	DECL_EXTERN_API(BOOLEAN, ObjectEnumHandleEntries, HandleEntryCallback callback, LPARAM lParam);
	DECL_EXTERN_API(BOOLEAN, ObjectEnumHandles, HandleCallback callback, DWORD dwTypeIndex, LPARAM lParam);

	/* defined in image.c */
	DECL_EXTERN_API(BOOLEAN, ImageIsValid, CONST IN HMODULE hModule);
	DECL_EXTERN_API(PIMAGE_DOS_HEADER, ImageGetDosHeader, CONST IN HMODULE hModule);
	DECL_EXTERN_API(PIMAGE_NT_HEADERS32, ImageGetNtHeader32, CONST IN ULONG_PTR hModule);
	DECL_EXTERN_API(PIMAGE_NT_HEADERS64, ImageGetNtHeader64, CONST IN ULONG64 hModule);
	DECL_EXTERN_API(PIMAGE_NT_HEADERS, ImageGetNtHeader, CONST IN HMODULE hModule);
	DECL_EXTERN_API(PIMAGE_EXPORT_DIRECTORY, ImageGetExportDirectory32, CONST IN ULONG_PTR hModule);
	DECL_EXTERN_API(PIMAGE_EXPORT_DIRECTORY, ImageGetExportDirectory64, CONST IN ULONG64 hModule);
	DECL_EXTERN_API(PIMAGE_EXPORT_DIRECTORY, ImageGetExportDirectory, CONST IN HMODULE hModule);
	DECL_EXTERN_API(ULONG, ImageOffsetFromRVA32, IN PIMAGE_NT_HEADERS32 pImageHeader, IN DWORD RVA);
	DECL_EXTERN_API(ULONG, ImageOffsetFromRVA64, IN PIMAGE_NT_HEADERS64 pImageHeader, IN DWORD RVA);
	DECL_EXTERN_API(ULONG, ImageOffsetFromRVA, IN PIMAGE_NT_HEADERS pImageHeader, IN DWORD RVA);
	DECL_EXTERN_API(PIMAGE_SECTION_HEADER, ImageRvaToSection, IN HMODULE hModule, IN ULONG Rva);
	DECL_EXTERN_API(LPVOID, ImageRvaToVa, IN HMODULE hModule, IN ULONG Rva);
	DECL_EXTERN_API(ULONG, ImageVaToRva, IN HMODULE hModule, IN LPCVOID lpAddress);
	DECL_EXTERN_API(BOOLEAN, ImageRemoteDosHeaderFromModule, IN HANDLE hProcess, IN HMODULE hModule, IN PIMAGE_DOS_HEADER pDosHeader);
	DECL_EXTERN_API(BOOLEAN, ImageRemoteDosHeaderFromModule64, IN HANDLE hProcess, IN ULONG64 hModule, IN PIMAGE_DOS_HEADER pDosHeader);
	DECL_EXTERN_API(BOOLEAN, ImageRemoteNtHeadersFromModule64, IN HANDLE hProcess, IN ULONG64 hModule, IN PIMAGE_NT_HEADERS64 pNtHeaders);
	DECL_EXTERN_API(BOOLEAN, ImageRemoteExportDirectoryFromModule64, IN HANDLE hProcess, IN ULONG64 hModule, IN PIMAGE_EXPORT_DIRECTORY pExportDirectory);
	DECL_EXTERN_API(BOOLEAN, ImageRemoteNtHeadersFromModule32, IN HANDLE hProcess, IN HMODULE hModule, IN PIMAGE_NT_HEADERS32 pNtHeaders);
	DECL_EXTERN_API(BOOLEAN, ImageRemoteExportDirectoryFromModule32, IN HANDLE hProcess, IN HMODULE hModule, IN PIMAGE_EXPORT_DIRECTORY pExportDirectory);
	DECL_EXTERN_API(BOOLEAN, ImageRemoteNtHeadersFromModule, IN HANDLE hProcess, IN HMODULE hModule, IN PIMAGE_NT_HEADERS pNtHeaders);
	DECL_EXTERN_API(BOOLEAN, ImageRemoteExportDirectoryFromModule, IN HANDLE hProcess, IN HMODULE hModule, IN PIMAGE_EXPORT_DIRECTORY pExportDirectory);
	DECL_EXTERN_API(BOOLEAN, ImageSectionByNameA, OUT PIMAGE_SECTION_HEADER Section, IN PIMAGE_NT_HEADERS pImageHeader, IN LPSTR lpSection);
	DECL_EXTERN_API(BOOLEAN, ImageSectionByName32A, OUT PIMAGE_SECTION_HEADER Section, IN PIMAGE_NT_HEADERS32 pImageHeader, IN LPSTR lpSection);
	DECL_EXTERN_API(BOOLEAN, ImageSectionByName64A, OUT PIMAGE_SECTION_HEADER Section, IN PIMAGE_NT_HEADERS64 pImageHeader, IN LPSTR lpSection);
	DECL_EXTERN_API(BOOLEAN, ImageRemoteSectionByNameA, IN HANDLE hProcess, OUT PIMAGE_SECTION_HEADER Section, IN HMODULE hModule, IN LPSTR lpSection);
	DECL_EXTERN_API(ULONG, ImageOffset, IN PIMAGE_SECTION_HEADER pSection, IN DWORD RVA);

	/* 
	** defined in string.c 
	** 
	** Use "Size" for when you need to define a strings count in bytes.
	** Use "Length" for when you need to define a string count per character.
	*/
	DECL_EXTERN_API(LPSTR, StringAllocA, CONST IN DWORD dwLength);
	DECL_EXTERN_API(LPWSTR, StringAllocW, CONST IN DWORD dwLength);
	/* OPTIONAL = -1 */
	DECL_EXTERN_API(BOOLEAN, StringSubtractA, IN LPCSTR lpStr, OUT LPSTR lpOutStr, CONST IN DWORD szStartIndex, IN DWORD szEndIndex OPTIONAL);
	/* OPTIONAL = -1 */
	DECL_EXTERN_API(BOOLEAN, StringSubtractW, IN LPCWSTR lpStr, OUT LPWSTR lpOutStr, CONST IN DWORD szStartIndex, IN DWORD szEndIndex OPTIONAL);
	DECL_EXTERN_API(DWORD, StringIndexOfA, IN LPCSTR lpStr, IN LPCSTR lpDelimiter, CONST IN BOOLEAN CaseInsensitive);
	DECL_EXTERN_API(DWORD, StringLastIndexOfA, IN LPCSTR lpStr, IN LPCSTR lpDelimiter, CONST IN BOOLEAN CaseInsensitive);
	DECL_EXTERN_API(DWORD, StringIndexOfW, IN LPCWSTR lpStr, IN LPCWSTR lpDelimiter, CONST IN BOOLEAN CaseInsensitive);
	DECL_EXTERN_API(DWORD, StringLastIndexOfW, IN LPCWSTR lpStr, IN LPCWSTR lpDelimiter, CONST IN BOOLEAN CaseInsensitive);
	DECL_EXTERN_API(DWORD, StringLenA, IN LPCSTR lpString);
	DECL_EXTERN_API(DWORD, StringLenW, IN LPCWSTR lpString);
	DECL_EXTERN_API(DWORD, StringSizeA, IN LPCSTR lpString);
	DECL_EXTERN_API(DWORD, StringSizeW, IN LPCWSTR lpString);
	DECL_EXTERN_API(BOOLEAN, StringToLowerA, IN OUT LPSTR lpStr);
	DECL_EXTERN_API(BOOLEAN, StringToLowerW, IN OUT LPWSTR lpStr);
	DECL_EXTERN_API(BOOLEAN, StringToUpperA, IN OUT LPSTR lpStr);
	DECL_EXTERN_API(BOOLEAN, StringToUpperW, IN OUT LPWSTR lpStr);
	DECL_EXTERN_API(BOOLEAN, StringCompareContent, IN LPCVOID lpStr1, IN LPCVOID lpStr2, CONST IN DWORD dwLen);
	DECL_EXTERN_API(BOOLEAN, StringCompareA, IN LPCSTR lpStr1, IN LPCSTR lpStr2);
	DECL_EXTERN_API(BOOLEAN, StringCompareW, IN LPCWSTR lpStr1, IN LPCWSTR lpStr2);
	DECL_EXTERN_API(BOOLEAN, StringEqualA, IN LPCSTR lpString1, IN LPCSTR lpString2, CONST IN BOOLEAN CaseInSensitive);
	DECL_EXTERN_API(BOOLEAN, StringEqualW, IN LPCWSTR lpString1, IN LPCWSTR lpString2, CONST IN BOOLEAN CaseInSensitive);
	DECL_EXTERN_API(LPSTR, StringWithinStringA, IN LPCSTR szStr, IN LPCSTR szToFind, CONST IN BOOLEAN bStopFirst, CONST IN BOOLEAN CaseInsensitive);
	DECL_EXTERN_API(LPWSTR, StringWithinStringW, IN LPCWSTR szStr, IN LPCWSTR szToFind, CONST IN BOOLEAN bStopFirst, CONST IN BOOLEAN CaseInsensitive);
	DECL_EXTERN_API(BOOLEAN, StringContainsA, IN LPCSTR lpString1, IN LPCSTR lpString2, CONST IN BOOLEAN CaseInSensitive);
	DECL_EXTERN_API(BOOLEAN, StringContainsW, IN LPCWSTR lpString1, IN LPCWSTR lpString2, CONST IN BOOLEAN CaseInSensitive);
	DECL_EXTERN_API(BOOLEAN, StringCopyConvertAtoW, IN LPCSTR lpStringToConvert, OUT LPWSTR lpStringOut, CONST IN DWORD dwStringCount);
	DECL_EXTERN_API(BOOLEAN, StringCopyConvertWtoA, IN LPCWSTR lpStringToConvert, OUT LPSTR lpStringOut, CONST IN DWORD dwStringCount);
	DECL_EXTERN_API(LPWSTR, StringConvertAtoW, IN LPCSTR lpStringConvert);
	DECL_EXTERN_API(LPSTR, StringConvertWtoA, IN LPCWSTR lpStringConvert);
	DECL_EXTERN_API(BOOLEAN, StringCopyA, OUT LPSTR szOut, IN LPCSTR szcIn, CONST IN DWORD dwLen OPTIONAL);
	DECL_EXTERN_API(BOOLEAN, StringCopyW, OUT LPWSTR szOut, IN LPCWSTR szcIn, CONST IN DWORD dwLen OPTIONAL);
	DECL_EXTERN_API(BOOLEAN, StringCopyExW, OUT LPWSTR szOut, IN LPCWSTR szcIn);
	DECL_EXTERN_API(BOOLEAN, StringCopyExA, OUT LPSTR szOut, IN LPCSTR szcIn);
	DECL_EXTERN_API(BOOLEAN, StringAppendA, IN LPSTR* szStream, IN LPCSTR szText, CONST IN DWORD dwLength OPTIONAL);
	DECL_EXTERN_API(BOOLEAN, StringAppendW, IN LPWSTR* szStream, IN LPCWSTR szText, CONST IN DWORD dwLength OPTIONAL);
	DECL_EXTERN_API(BOOLEAN, StringAppendExW, IN LPWSTR szStream, IN LPCWSTR szText);
	DECL_EXTERN_API(BOOLEAN, StringAppendExA, IN LPSTR szStream, IN LPCSTR szText);
	DECL_EXTERN_API(ULONG_PTR, StringConvertIntPtrA, IN LPSTR lpString);
	DECL_EXTERN_API(ULONG_PTR, StringConvertIntPtrW, IN LPWSTR lpString);
	DECL_EXTERN_API(VOID, StringUInt32ToStringW, ULONG value, LPWSTR buffer);
	DECL_EXTERN_API(VOID, StringUInt32ToStringA, ULONG value, LPSTR buffer);
	DECL_EXTERN_API(VOID, StringInt32ToStringW, LONG value, LPWSTR buffer);
	DECL_EXTERN_API(VOID, StringInt32ToStringA, LONG value, LPSTR buffer);
	DECL_EXTERN_API(VOID, StringUInt64ToStringW, ULONG64 value, LPWSTR buffer);
	DECL_EXTERN_API(VOID, StringUInt64ToStringA, ULONG64 value, LPSTR buffer);
	DECL_EXTERN_API(VOID, StringInt64ToStringW, LONG64 value, LPWSTR buffer);
	DECL_EXTERN_API(VOID, StringInt64ToStringA, LONG64 value, LPSTR buffer); 
	DECL_EXTERN_API(VOID, StringUInt32ToHexStringA, ULONG n, LPSTR outbuf);
	DECL_EXTERN_API(VOID, StringUInt32ToHexStringW, ULONG n, LPWSTR outbuf);

	/* defined in privilege.c
	** @unimplemented
	*/
	DECL_EXTERN_API(PLUID, LookupPrivilegeValueW, LPCWSTR Name);
	DECL_EXTERN_API(PLUID, LookupPrivilegeValueA, LPCSTR Name);
	DECL_EXTERN_API(NTSTATUS, TokenIsElevated, _In_ HANDLE TokenHandle, _Out_ PBOOLEAN Elevated);
	DECL_EXTERN_API(NTSTATUS, OpenProcessTokenEx, CONST IN HANDLE hProcess, CONST IN ACCESS_MASK DesiredAccess, OUT PHANDLE TokenHandle);

	/* defined in virtual.c */
	DECL_EXTERN_API(LPVOID, VirtualAllocEx, CONST IN HANDLE hProcess, IN LPVOID lpAddress, IN SIZE_T dwSize, CONST IN DWORD flAllocationType, CONST IN DWORD flProtect);
	DECL_EXTERN_API(ULONG64, VirtualAllocWow64Ex, CONST IN HANDLE hProcess, IN ULONG64 Address, IN ULONG64 Size, CONST IN DWORD flAllocationType, CONST IN DWORD flProtect);
	DECL_EXTERN_API(ULONG64, VirtualAlloc64Ex, CONST IN HANDLE hProcess, IN ULONG64 Address, IN ULONG64 Size ,CONST IN DWORD flAllocationType, CONST IN DWORD flProtect);
	DECL_EXTERN_API(LPVOID, VirtualAlloc, IN LPVOID lpAddress, IN SIZE_T dwSize, CONST IN DWORD flAllocationType, CONST IN DWORD flProtect);
	DECL_EXTERN_API(BOOL, VirtualFreeEx, CONST IN HANDLE hProcess, IN LPVOID lpAddress, IN SIZE_T dwSize, CONST IN DWORD dwFreeType);
	DECL_EXTERN_API(BOOL, VirtualFree, IN LPVOID lpAddress, CONST IN SIZE_T dwSize, CONST IN DWORD dwFreeType);
	DECL_EXTERN_API(BOOL, VirtualProtect, IN LPVOID lpAddress, CONST IN SIZE_T dwSize, CONST IN DWORD flNewProtect, OUT PDWORD lpflOldProtect);
	DECL_EXTERN_API(BOOL, VirtualProtectEx, CONST IN HANDLE hProcess, IN LPVOID lpAddress, IN SIZE_T dwSize, CONST IN DWORD flNewProtect, OUT PDWORD lpflOldProtect);
	DECL_EXTERN_API(BOOL, VirtualLock, IN LPVOID lpAddress, CONST IN SIZE_T dwSize);
	DECL_EXTERN_API(SIZE_T, VirtualQuery, IN LPCVOID lpAddress, OUT PMEMORY_BASIC_INFORMATION lpBuffer, CONST IN SIZE_T dwLength);
	DECL_EXTERN_API(SIZE_T, VirtualQueryEx, CONST IN HANDLE hProcess, IN LPCVOID lpAddress, OUT PMEMORY_BASIC_INFORMATION lpBuffer, CONST IN SIZE_T dwLength);
	DECL_EXTERN_API(NTSTATUS, QueryVirtualMemoryEx, IN HANDLE ProcessHandle, IN LPVOID BaseAddress, IN MEMORY_INFORMATION_CLASS MemoryInformationClass, OUT LPVOID MemoryInformation, IN SIZE_T MemoryInformationLength, OUT PSIZE_T ReturnLength);
	DECL_EXTERN_API(BOOL, VirtualUnlock, IN LPVOID lpAddress, CONST IN SIZE_T dwSize);
	DECL_EXTERN_API(LPVOID, Alloc32, CONST IN SIZE_T Size);
	DECL_EXTERN_API(PVOID, Alloc, CONST IN SIZE_T Size);
	DECL_EXTERN_API(VOID, Free, CONST IN LPVOID lpAddress);
	DECL_EXTERN_API(PVOID, AllocPage, CONST IN SIZE_T Size);
	DECL_EXTERN_API(VOID, FreePage, CONST IN LPVOID lpAddress);
	DECL_EXTERN_API(ULONG64, Alloc64, CONST IN ULONG64 Size); /* can't be freed from a 32bit process. */
	DECL_EXTERN_API(PVOID, Realloc, IN LPVOID lpAddress, CONST IN SIZE_T Size, CONST IN SIZE_T newSize);

	/* defined in volume.c */
	DECL_EXTERN_API(BOOLEAN, VolumeGetInformationA, 
		IN  LPCSTR	lpRootPathName OPTIONAL,
		OUT LPSTR	lpVolumeNameBuffer OPTIONAL,
		IN  DWORD   nVolumeNameSize,
		OUT LPDWORD lpVolumeSerialNumber OPTIONAL,
		OUT LPDWORD lpMaximumComponentLength OPTIONAL,
		OUT LPDWORD lpFileSystemFlags OPTIONAL,
		OUT LPSTR	lpFileSystemNameBuffer OPTIONAL,
		IN  DWORD   nFileSystemNameSize);

	DECL_EXTERN_API(BOOLEAN, VolumeGetInformationW, 
		IN  LPCWSTR lpRootPathName OPTIONAL,
		OUT LPWSTR  lpVolumeNameBuffer OPTIONAL,
		IN  DWORD   nVolumeNameSize,
		OUT LPDWORD lpVolumeSerialNumber OPTIONAL,
		OUT LPDWORD lpMaximumComponentLength OPTIONAL,
		OUT LPDWORD lpFileSystemFlags OPTIONAL,
		OUT LPWSTR  lpFileSystemNameBuffer OPTIONAL,
		IN  DWORD   nFileSystemNameSize);

	DECL_EXTERN_API(DWORD, VolumeLogicalDrives);
	DECL_EXTERN_API(DWORD, VolumeLogicalDriveStringsW, IN DWORD nBufferLength, IN LPWSTR lpBuffer);
	DECL_EXTERN_API(BOOLEAN, VolumePathFromNtPath, IN LPCWSTR szNtPath, OUT LPWSTR DosPath);

	/* defined in path.c, lpBuffer is expected to be allocated with MAX_PATH * sizeof, TCHAR in any function that does not specify a size parameter. */
	DECL_EXTERN_API(BOOLEAN, PathGetFileA, IN LPCSTR lpPath, IN LPSTR lpBuffer);
	DECL_EXTERN_API(BOOLEAN, PathGetFileW, IN LPCWSTR lpPath, IN LPWSTR lpBuffer);
	DECL_EXTERN_API(DWORD, PathGetFullPathNameA, IN LPCSTR lpFileName, OUT LPSTR lpBuffer);
	DECL_EXTERN_API(DWORD, PathGetFullPathNameW, IN LPCWSTR lpFileName, OUT LPWSTR lpBuffer);
	DECL_EXTERN_API(DWORD, PathGetTempFolderW, IN LPWSTR lpBuffer);
	DECL_EXTERN_API(DWORD, PathGetTempFolderA, IN LPWSTR lpBuffer);

	/* defined in thread.c */
	DECL_EXTERN_API(BOOLEAN, ThreadExitCode, IN CONST HANDLE hThread, OUT PULONG lpExitCode);
	DECL_EXTERN_API(HANDLE, ThreadOpen, IN DWORD dwThreadId, IN DWORD dwDesiredAccess);
	DECL_EXTERN_API(DWORD, ThreadCurrentId);
	DECL_EXTERN_API(DWORD, ThreadSuspend, IN HANDLE hThread);
	DECL_EXTERN_API(BOOLEAN, ThreadResume, IN HANDLE hThread);
	DECL_EXTERN_API(BOOLEAN, ThreadGetContext, HANDLE hThread, LPCONTEXT lpContext);
	DECL_EXTERN_API(BOOLEAN, ThreadSetContext, HANDLE hThread, LPCONTEXT lpContext);
	DECL_EXTERN_API(BOOLEAN, ThreadGetAllThreadIds, DWORD ProcessId, DWORD* ThreadList, DWORD* dwThreadListCount);
	NTSTATUS
		NTAPI
		RtlCreateUserThread(IN HANDLE ProcessHandle,
			IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
			IN BOOLEAN CreateSuspended,
			IN ULONG StackZeroBits OPTIONAL,
			IN SIZE_T StackReserve OPTIONAL,
			IN SIZE_T StackCommit OPTIONAL,
			IN PTHREAD_START_ROUTINE StartAddress,
			IN PVOID Parameter OPTIONAL,
			OUT PHANDLE ThreadHandle OPTIONAL,
			OUT PCLIENT_ID ClientId OPTIONAL);
	NTSTATUS
		NTAPI
		RtlpCreateUserStack(IN HANDLE hProcess,
			IN SIZE_T StackReserve OPTIONAL,
			IN SIZE_T StackCommit OPTIONAL,
			IN ULONG StackZeroBits OPTIONAL,
			OUT PINITIAL_TEB InitialTeb);
	VOID
		NTAPI
		RtlInitializeContext(IN HANDLE ProcessHandle,
			OUT PCONTEXT ThreadContext,
			IN PVOID ThreadStartParam  OPTIONAL,
			IN PTHREAD_START_ROUTINE ThreadStartAddress,
			IN PINITIAL_TEB InitialTeb);
	VOID
		WINAPI
		BaseInitializeContext(IN PCONTEXT Context,
			IN PVOID Parameter,
			IN PVOID StartAddress,
			IN PVOID StackAddress,
			IN ULONG ContextType);

	BOOLEAN WINAPI BasePushProcessParameters(IN ULONG 	ParameterFlags,
		IN HANDLE 	ProcessHandle,
		IN PPEB 	RemotePeb,
		IN LPCWSTR 	ApplicationPathName,
		IN LPWSTR 	lpCurrentDirectory,
		IN LPWSTR 	lpCommandLine,
		IN LPVOID 	lpEnvironment,
		IN LPSTARTUPINFOW 	StartupInfo,
		IN DWORD 	CreationFlags,
		IN BOOL 	InheritHandles,
		IN ULONG 	ImageSubsystem,
		IN PVOID 	AppCompatData,
		IN ULONG 	AppCompatDataSize);

	NTSTATUS
		WINAPI
		BaseCreateStack(HANDLE hProcess,
			SIZE_T StackCommit,
			SIZE_T StackReserve,
			PINITIAL_TEB InitialTeb);

	/* defined in deviceio.c */
	DECL_EXTERN_API(BOOLEAN, DeviceIoControl,
		IN HANDLE hDevice,
		IN DWORD dwIoControlCode,
		IN LPVOID lpInBuffer OPTIONAL,
		IN DWORD nInBufferSize OPTIONAL,
		OUT LPVOID lpOutBuffer OPTIONAL,
		IN DWORD nOutBufferSize OPTIONAL,
		OUT PULONG_PTR lpBytesReturned OPTIONAL,
		IN LPOVERLAPPED lpOverlapped OPTIONAL);

	/* defined in util.c */
	DECL_EXTERN_API(POBJECT_ATTRIBUTES, UtilFormatObjectAttributes, OUT POBJECT_ATTRIBUTES ObjectAttributes, IN PSECURITY_ATTRIBUTES SecurityAttributes OPTIONAL, IN PUNICODE_STRING ObjectName);
	DECL_EXTERN_API(POBJECT_ATTRIBUTES_WOW64, UtilFormatObjectAttributesWow64, OUT POBJECT_ATTRIBUTES_WOW64 ObjectAttributes, IN PSECURITY_ATTRIBUTES SecurityAttributes OPTIONAL, IN PUNICODE_STRING ObjectName);

	/* defined in scan.c */
	DECL_EXTERN_API(NTSTATUS, ScanPageMinesCreate, PSCAN_PAGE_MINES ScanInformation);
	DECL_EXTERN_API(NTSTATUS, ScanPageMinesCheck, PSCAN_PAGE_MINES ScanInformation);
	DECL_EXTERN_API(NTSTATUS, ScanCheckDebuggerBasic, BOOLEAN CheckDebuggermines);
	DECL_EXTERN_API(NTSTATUS, ScanHideCurrentThread);
	DECL_EXTERN_API(NTSTATUS, ScanApplyDebuggerMines);
	DECL_EXTERN_API(NTSTATUS, ScanCheckProcessDebuggerFlags);
	DECL_EXTERN_API(NTSTATUS, ScanCheckPebFlags);
	DECL_EXTERN_API(NTSTATUS, ScanCheckDebuggerPort);
	DECL_EXTERN_API(NTSTATUS, ScanCheckKernelFlag);
	DECL_EXTERN_API(NTSTATUS, ScanCheckKernelDebugger);
	DECL_EXTERN_API(NTSTATUS, ScanCheckThreadHook);
	DECL_EXTERN_API(NTSTATUS, ScanCheckHeaderFlags);
	DECL_EXTERN_API(NTSTATUS, ScanCheckDebugHandle);
	DECL_EXTERN_API(NTSTATUS, ScanCheckHardwareBreakpoints);
	DECL_EXTERN_API(NTSTATUS, ScanCheckInvalidDebugObject);
	DECL_EXTERN_API(NTSTATUS, ScanCheckVEH);
	DECL_EXTERN_API(LANGID, GetSystemDefaultLangID);
	DECL_EXTERN_API(BOOLEAN, ScanVirtualMachine);

	/* defined in hash.c */
	typedef struct _SHA_256 {
		BYTE data[64];
		ULONG datalen;
		unsigned long long bitlen;
		ULONG state[8];
	} SHA_256, *PSHA_256;

	DECL_EXTERN_API(LPSTR, HashSha256A, LPVOID pData, SIZE_T Size);
	DECL_EXTERN_API(LPWSTR, HashSha256W, LPVOID pData, SIZE_T Size);
	DECL_EXTERN_API(VOID, HashSha256Transform, SHA_256 *ctx, CONST LPBYTE data);
	DECL_EXTERN_API(VOID, HashSha256Init, SHA_256 *ctx);
	DECL_EXTERN_API(VOID, HashSha256Update, SHA_256 *ctx, CONST LPBYTE data, SIZE_T len);
	DECL_EXTERN_API(VOID, HashSha256Final, SHA_256 *ctx, LPBYTE hash);

	/* unique_id.c */
	DECL_EXTERN_API(LPWSTR, UniqueHardwareId);

	/* input.c */
	DECL_EXTERN_API(SHORT, GetAsyncKeyState, INT vKey);
	DECL_EXTERN_API(BOOL, PostThreadMessageA, DWORD idThread, UINT Msg, WPARAM wParam, LPARAM lParam);
	DECL_EXTERN_API(BOOL, PostThreadMessageW, DWORD idThread, UINT Msg, WPARAM wParam, LPARAM lParam);
	DECL_EXTERN_API(LRESULT, SendMessageW, HWND Wnd, UINT Msg, WPARAM wParam, LPARAM lParam);

	/* window.c */
	DECL_EXTERN_API(BOOL, EnumDesktopWindows, HDESK hDesktop,
		WNDENUMPROC lpfn,
		LPARAM lParam);

	DECL_EXTERN_API(BOOL, EnumWindows, WNDENUMPROC lpEnumFunc,
		LPARAM lParam);

	DECL_EXTERN_API(BOOL, EnumThreadWindows, DWORD dwThreadId,
		WNDENUMPROC lpfn,
		LPARAM lParam);

	DECL_EXTERN_API(BOOL, EnumChildWindows, HWND hWndParent,
		WNDENUMPROC lpEnumFunc,
		LPARAM lParam);

	DECL_EXTERN_API(DWORD, GetWindowThreadProcessId, HWND hWnd, LPDWORD lpdwProcessId);
	DECL_EXTERN_API(PTHREADINFO, GetW32ThreadInfo, VOID);
	DECL_EXTERN_API(PVOID, SharedPtrToUser, PVOID Ptr);
	DECL_EXTERN_API(PUSER_HANDLE_ENTRY, GetUser32Handle, HANDLE handle);
	DECL_EXTERN_API(PVOID, ValidateHandle, HANDLE handle, UINT uType);
	DECL_EXTERN_API(PWND, ValidateHwnd, HWND hwnd);
	DECL_EXTERN_API(HWND, GetTopWindow, HWND hWnd);
	DECL_EXTERN_API(HWND, GetWindow, HWND hWnd, UINT uCmd);
	DECL_EXTERN_API(PVOID, DesktopPtrToUser, PVOID Ptr);

	/* draw.c */
	DECL_EXTERN_API(BOOL, FlashWindow, HWND hWnd, BOOL bInvert);

	/* class.c */
	DECL_EXTERN_API(INT, GetClassNameW, HWND hWnd, LPWSTR lpClassName, int nMaxCount);

	DECL_EXTERN_API(VOID, InitUnicodeString, PUNICODE_STRING DestinationString, PCWSTR SourceString);
	BOOLEAN NTAPI HcDosPathNameToNtPathName_U(IN PCWSTR 	DosName,
		OUT PUNICODE_STRING 	NtName,
		OUT PCWSTR * 	PartName,
		OUT PRTL_RELATIVE_NAME_U 	RelativeName
	);

	HC_EXTERN_API VOID __cdecl Enter64();
	HC_EXTERN_API VOID __cdecl Enter32();

#if defined (__cplusplus)
}
#endif

#endif