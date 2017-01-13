/*++

Module Name:

hcfile.h

Abstract:

This module declares custom file handling functions, as well as
reimplementations of kernel32.dll functions.

Author:

Synestra 10/10/2016, information was gathered from various sources.

Revision History:

--*/

#ifndef HC_FILE_H
#define HC_FILE_H

//
// Standard highcall definition file.
//

#include "hcdef.h"

//
// Contains out information about a file.
// Used by HcFileQueryInformation.
//
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

#if defined (__cplusplus)
extern "C" {
#endif

	//
	// Implemented in hcfile.c
	//

	HC_EXTERN_API BOOLEAN HCAPI HcFileExistsA(LPCSTR lpFilePath);
	HC_EXTERN_API BOOLEAN HCAPI HcFileExistsW(LPCWSTR lpFilePath);

	HC_EXTERN_API SIZE_T HCAPI HcFileSize(LPCSTR lpPath);

	HC_EXTERN_API BOOLEAN HCAPI HcFileQueryInformationW(LPCWSTR lpPath, PHC_FILE_INFORMATIONW fileInformation);
	HC_EXTERN_API BOOLEAN HCAPI HcFileQueryInformationA(LPCSTR lpPath, PHC_FILE_INFORMATIONA fileInformation);

	HC_EXTERN_API DWORD HCAPI HcFileOffsetByExportNameA(HMODULE hModule, LPCSTR lpExportName);
	HC_EXTERN_API DWORD HCAPI HcFileOffsetByExportNameW(HMODULE hModule, LPCWSTR lpExportName);

	HC_EXTERN_API DWORD HCAPI HcFileOffsetByVirtualAddress(LPCVOID lpAddress);

	HC_EXTERN_API SIZE_T HCAPI HcFileReadModuleA(HMODULE hModule, LPCSTR lpExportName, PBYTE lpBuffer, DWORD dwCount);
	HC_EXTERN_API SIZE_T HCAPI HcFileReadModuleW(HMODULE hModule, LPCWSTR lpExportName, PBYTE lpBuffer, DWORD dwCount);
	HC_EXTERN_API SIZE_T HCAPI HcFileReadAddress(LPCVOID lpAddress, PBYTE lpBufferOut, DWORD dwCountToRead);

	HC_EXTERN_API NTSTATUS HCAPI HcFileGetCurrentDirectoryW(ULONG buflen, LPWSTR buf);

#endif

#if defined (__cplusplus)
}
#endif