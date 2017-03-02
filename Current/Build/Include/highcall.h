#ifndef HIGHCALL_H
#define HIGHCALL_H

#include "../../public/base.h"
#include "../../private/sys/syscall.h"
#include "../../public/imports.h"

#pragma comment(lib, "ntdll.lib")

#pragma region FILE definitions
/* file.c definitions */

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

typedef enum _DetourType
{
	Relative = 1,
	Absolute = 2
} DetourType;

typedef enum _DetourFlags
{
	Recreate = (1 << 0),
	Single = (1 << 1),
	SaveOriginal = (1 << 2),
	JumpOriginal = (1 << 3),
	Reconstruct = (1 << 4),
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
	--	OUT.
	--	Hook type. [Relative/Absolute]
	*/
	DetourType Type;

	//
	// IN
	//
	DetourFlags Flags;

} DetourContext, *PDetourContext;
#pragma endregion

#pragma region PROCESS definitions
typedef struct _HC_MODULE_INFORMATIONW
{
	SIZE_T		Size;
	PVOID		Base;
	LPWSTR		Name;
	LPWSTR		Path;
} HC_MODULE_INFORMATIONW, *PHC_MODULE_INFORMATIONW;

typedef BOOLEAN(CALLBACK* HC_MODULE_CALLBACK_EVENTW)(HC_MODULE_INFORMATIONW, LPARAM);

typedef struct _HC_PROCESS_INFORMATION_EXW
{
	DWORD					Id;
	LPWSTR					Name;
	PHC_MODULE_INFORMATIONW	MainModule;
	BOOLEAN					CanAccess;
	DWORD					ParentProcessId;
} HC_PROCESS_INFORMATION_EXW, *PHC_PROCESS_INFORMATION_EXW;

typedef BOOLEAN(CALLBACK* HC_PROCESS_CALLBACK_EXW)(CONST HC_PROCESS_INFORMATION_EXW, LPARAM);

typedef struct _HC_PROCESS_INFORMATIONW
{
	DWORD	Id;
	LPWSTR	Name;
	DWORD   ParentProcessId;
} HC_PROCESS_INFORMATIONW, *PHC_PROCESS_INFORMATIONW;

typedef BOOLEAN(CALLBACK* HC_PROCESS_CALLBACKW)(CONST HC_PROCESS_INFORMATIONW Entry, LPARAM lParam);
typedef BOOLEAN(CALLBACK* HC_HANDLE_ENTRY_CALLBACKW)(CONST PSYSTEM_HANDLE_TABLE_ENTRY_INFO Entry, LPARAM lParam);
typedef BOOLEAN(CALLBACK* HC_HANDLE_CALLBACKW)(CONST HANDLE Handle, CONST HANDLE hOwner, LPARAM lParam);
#pragma endregion

#pragma region INTERNAL definitons
#define USER_MAX_ADDRESS 0x7FFFFFFF
#define USER_MIN_ADDRESS 0x00000000

#define POINTER32_HARDCODED(Type) (Type) (ULONG_PTR)
#define POINTER64_HARDCODED(Type) (Type) (ULONG64)

/* still needs to be allocated.. -_- */
#define HcInternalMainModule(pmi) (HcProcessQueryInformationModule(NtCurrentProcess, NULL, pmi)) 

#define HcInternalReadInt32(lpcAddress) ((INT)(HcInternalValidate(lpcAddress) ? (*(DWORD*)(lpcAddress)) : 0))
#define HcInternalReadInt64(lpcAddress) ((INT64)(HcInternalValidate(lpcAddress) ? (*(DWORD64*)lpcAddress) : 0))

#define HcInternalReadStringExA(lpcAddress, ptOffsets, tCount) ((LPSTR)HcInternalLocatePointer(lpcAddress, ptOffsets, tCount))
#define HcInternalReadStringExW(lpcAddress, ptOffsets, tCount) ((LPWSTR)HcInternalLocatePointer(lpcAddress, ptOffsets, tCount))

#define ZERO(x) { HcInternalSet(x, 0, sizeof(*(x))); }
#pragma endregion

#pragma region MODULE definitions
#ifdef _WIN64
#define HcModuleProcedureA(x, y) ((LPBYTE) HcModuleProcedureAddress64A((ULONG64)(x), y))
#define HcModuleProcedureW(x, y) ((LPBYTE) HcModuleProcedureAddress64W((ULONG64)(x), y))
#else							 
#define HcModuleProcedureA(x, y) ((LPBYTE) HcModuleProcedureAddress32A((ULONG_PTR)(x), y))
#define HcModuleProcedureW(x, y) ((LPBYTE) HcModuleProcedureAddress32W((ULONG_PTR)(x), y))
#endif
#pragma endregion

#pragma region OBJECT definitions
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

//
// defines from heap.h 
//

#define HEAP_LARGE_TAG_MASK 0xFF000000

#define ROUND_UP_TO_POWER2( x, n ) (((ULONG_PTR)(x) + ((n)-1)) & ~((ULONG_PTR)(n)-1))
#define ROUND_DOWN_TO_POWER2( x, n ) ((ULONG_PTR)(x) & ~((ULONG_PTR)(n)-1))

typedef struct _HEAP_ENTRY {

	//
	//  This field gives the size of the current block in allocation
	//  granularity units.  (i.e. Size << HEAP_GRANULARITY_SHIFT
	//  equals the size in bytes).
	//
	//  Except if this is part of a virtual alloc block then this
	//  value is the difference between the commit size in the virtual
	//  alloc entry and the what the user asked for.
	//

	USHORT Size;

	//
	// This field gives the size of the previous block in allocation
	// granularity units. (i.e. PreviousSize << HEAP_GRANULARITY_SHIFT
	// equals the size of the previous block in bytes).
	//

	USHORT PreviousSize;

	//
	// This field contains the index into the segment that controls
	// the memory for this block.
	//

	UCHAR SegmentIndex;

	//
	// This field contains various flag bits associated with this block.
	// Currently these are:
	//
	//  0x01 - HEAP_ENTRY_BUSY
	//  0x02 - HEAP_ENTRY_EXTRA_PRESENT
	//  0x04 - HEAP_ENTRY_FILL_PATTERN
	//  0x08 - HEAP_ENTRY_VIRTUAL_ALLOC
	//  0x10 - HEAP_ENTRY_LAST_ENTRY
	//  0x20 - HEAP_ENTRY_SETTABLE_FLAG1
	//  0x40 - HEAP_ENTRY_SETTABLE_FLAG2
	//  0x80 - HEAP_ENTRY_SETTABLE_FLAG3
	//

	UCHAR Flags;

	//
	// This field contains the number of unused bytes at the end of this
	// block that were not actually allocated.  Used to compute exact
	// size requested prior to rounding requested size to allocation
	// granularity.  Also used for tail checking purposes.
	//

	UCHAR UnusedBytes;

	//
	// Small (8 bit) tag indexes can go here.
	//

	UCHAR SmallTagIndex;

#if defined(_WIN64)
	ULONGLONG Reserved1;
#endif

} HEAP_ENTRY, *PHEAP_ENTRY;


//
// This block describes extra information that might be at the end of a
// busy block.
//

typedef struct _HEAP_ENTRY_EXTRA {
	union {
		struct {
			//
			// This field is for debugging purposes.  It will normally contain a
			// stack back trace index of the allocator for x86 systems.
			//

			USHORT AllocatorBackTraceIndex;

			//
			// This field is currently unused, but is intended for storing
			// any encoded value that will give the that gives the type of object
			// allocated.
			//

			USHORT TagIndex;

			//
			// This field is a 32-bit settable value that a higher level heap package
			// can use.  The Win32 heap manager stores handle values in this field.
			//

			ULONG_PTR Settable;
		};
#if defined(_WIN64)
		struct {
			ULONGLONG ZeroInit;
			ULONGLONG ZeroInit1;
		};
#else
		ULONGLONG ZeroInit;
#endif
	};
} HEAP_ENTRY_EXTRA, *PHEAP_ENTRY_EXTRA;

//
// This structure is present at the end of a free block if HEAP_ENTRY_EXTRA_PRESENT
// is set in the Flags field of a HEAP_FREE_ENTRY structure.  It is used to save the
// tag index that was associated with the allocated block after it has been freed.
// Works best when coalesce on free is disabled, along with decommitment.
//

typedef struct _HEAP_FREE_ENTRY_EXTRA {
	USHORT TagIndex;
	USHORT FreeBackTraceIndex;
} HEAP_FREE_ENTRY_EXTRA, *PHEAP_FREE_ENTRY_EXTRA;

//
// This structure describes a block that lies outside normal heap memory
// as it was allocated with NtAllocateVirtualMemory and has the
// HEAP_ENTRY_VIRTUAL_ALLOC flag set.
//

typedef struct _HEAP_VIRTUAL_ALLOC_ENTRY {
	LIST_ENTRY Entry;
	HEAP_ENTRY_EXTRA ExtraStuff;
	SIZE_T CommitSize;
	SIZE_T ReserveSize;
	HEAP_ENTRY BusyBlock;
} HEAP_VIRTUAL_ALLOC_ENTRY, *PHEAP_VIRTUAL_ALLOC_ENTRY;

typedef struct _HEAP_FREE_ENTRY {
	//
	// This field gives the size of the current block in allocation
	// granularity units.  (i.e. Size << HEAP_GRANULARITY_SHIFT
	// equals the size in bytes).
	//

	USHORT Size;

	//
	// This field gives the size of the previous block in allocation
	// granularity units. (i.e. PreviousSize << HEAP_GRANULARITY_SHIFT
	// equals the size of the previous block in bytes).
	//

	USHORT PreviousSize;

	//
	// This field contains the index into the segment that controls
	// the memory for this block.
	//

	UCHAR SegmentIndex;

	//
	// This field contains various flag bits associated with this block.
	// Currently for free blocks these can be:
	//
	//  0x02 - HEAP_ENTRY_EXTRA_PRESENT
	//  0x04 - HEAP_ENTRY_FILL_PATTERN
	//  0x10 - HEAP_ENTRY_LAST_ENTRY
	//

	UCHAR Flags;

	//
	// Two fields to encode the location of the bit in FreeListsInUse
	// array in HEAP_SEGMENT for blocks of this size.
	//

	UCHAR Index;
	UCHAR Mask;

	//
	// Free blocks use these two words for linking together free blocks
	// of the same size on a doubly linked list.
	//
	LIST_ENTRY FreeList;

#if defined(_WIN64)
	ULONGLONG Reserved1;
#endif

} HEAP_FREE_ENTRY, *PHEAP_FREE_ENTRY;



#define HEAP_GRANULARITY            ((LONG) sizeof( HEAP_ENTRY ))
#if defined(_WIN64)
#define HEAP_GRANULARITY_SHIFT      4   // Log2( HEAP_GRANULARITY )
#else
#define HEAP_GRANULARITY_SHIFT      3   // Log2( HEAP_GRANULARITY )
#endif

#define PAGE_SIZE   (ULONG)0x1000
#define HEAP_MAXIMUM_BLOCK_SIZE     (USHORT)(((0x10000 << HEAP_GRANULARITY_SHIFT) - PAGE_SIZE) >> HEAP_GRANULARITY_SHIFT)

#define HEAP_MAXIMUM_FREELISTS 128
#define HEAP_MAXIMUM_SEGMENTS 64

#define HEAP_ENTRY_BUSY             0x01
#define HEAP_ENTRY_EXTRA_PRESENT    0x02
#define HEAP_ENTRY_FILL_PATTERN     0x04
#define HEAP_ENTRY_VIRTUAL_ALLOC    0x08
#define HEAP_ENTRY_LAST_ENTRY       0x10
#define HEAP_ENTRY_SETTABLE_FLAG1   0x20
#define HEAP_ENTRY_SETTABLE_FLAG2   0x40
#define HEAP_ENTRY_SETTABLE_FLAG3   0x80
#define HEAP_ENTRY_SETTABLE_FLAGS   0xE0

//
// HEAP_SEGMENT defines the structure used to describe a range of
// contiguous virtual memory that has been set aside for use by
// a heap.
//

typedef struct _HEAP_UNCOMMMTTED_RANGE {
	struct _HEAP_UNCOMMMTTED_RANGE *Next;
	ULONG_PTR Address;
	SIZE_T Size;
	ULONG filler;
} HEAP_UNCOMMMTTED_RANGE, *PHEAP_UNCOMMMTTED_RANGE;

typedef struct _HEAP_SEGMENT {
	HEAP_ENTRY Entry;

	ULONG Signature;
	ULONG Flags;
	struct _HEAP *Heap;
	SIZE_T LargestUnCommittedRange;

	PVOID BaseAddress;
	ULONG NumberOfPages;
	PHEAP_ENTRY FirstEntry;
	PHEAP_ENTRY LastValidEntry;

	ULONG NumberOfUnCommittedPages;
	ULONG NumberOfUnCommittedRanges;
	PHEAP_UNCOMMMTTED_RANGE UnCommittedRanges;
	USHORT AllocatorBackTraceIndex;
	USHORT Reserved;
	PHEAP_ENTRY LastEntryInSegment;
} HEAP_SEGMENT, *PHEAP_SEGMENT;

#define HEAP_SEGMENT_SIGNATURE  0xFFEEFFEE
#define HEAP_SEGMENT_USER_ALLOCATED (ULONG)0x00000001

//
// HEAP defines the header for a heap.
//

typedef struct _HEAP_LOCK {
	union {
		RTL_CRITICAL_SECTION CriticalSection;
		PVOID Resource;
	} Lock;
} HEAP_LOCK, *PHEAP_LOCK;

typedef struct _HEAP_UCR_SEGMENT {
	struct _HEAP_UCR_SEGMENT *Next;
	SIZE_T ReservedSize;
	SIZE_T CommittedSize;
	ULONG filler;
} HEAP_UCR_SEGMENT, *PHEAP_UCR_SEGMENT;


typedef struct _HEAP_TAG_ENTRY {
	ULONG Allocs;
	ULONG Frees;
	SIZE_T Size;
	USHORT TagIndex;
	USHORT CreatorBackTraceIndex;
	WCHAR TagName[24];
} HEAP_TAG_ENTRY, *PHEAP_TAG_ENTRY;     // sizeof( HEAP_TAG_ENTRY ) must divide page size evenly

typedef struct _HEAP_PSEUDO_TAG_ENTRY {
	ULONG Allocs;
	ULONG Frees;
	SIZE_T Size;
} HEAP_PSEUDO_TAG_ENTRY, *PHEAP_PSEUDO_TAG_ENTRY;


typedef struct _HEAP {
	HEAP_ENTRY Entry;

	ULONG Signature;
	ULONG Flags;
	ULONG ForceFlags;
	ULONG VirtualMemoryThreshold;

	SIZE_T SegmentReserve;
	SIZE_T SegmentCommit;
	SIZE_T DeCommitFreeBlockThreshold;
	SIZE_T DeCommitTotalFreeThreshold;

	SIZE_T TotalFreeSize;
	SIZE_T MaximumAllocationSize;
	USHORT ProcessHeapsListIndex;
	USHORT HeaderValidateLength;
	PVOID HeaderValidateCopy;

	USHORT NextAvailableTagIndex;
	USHORT MaximumTagIndex;
	PHEAP_TAG_ENTRY TagEntries;
	PHEAP_UCR_SEGMENT UCRSegments;
	PHEAP_UNCOMMMTTED_RANGE UnusedUnCommittedRanges;

	//
	//  The following two fields control the alignment for each new heap entry
	//  allocation.  The round is added to each size and the mask is used to
	//  align it.  The round value includes the heap entry and any tail checking
	//  space
	//

	ULONG AlignRound;
	ULONG AlignMask;

	LIST_ENTRY VirtualAllocdBlocks;

	PHEAP_SEGMENT Segments[HEAP_MAXIMUM_SEGMENTS];

	union {
		ULONG FreeListsInUseUlong[HEAP_MAXIMUM_FREELISTS / 32];
		UCHAR FreeListsInUseBytes[HEAP_MAXIMUM_FREELISTS / 8];
	} u;

	USHORT FreeListsInUseTerminate;
	USHORT AllocatorBackTraceIndex;
	ULONG Reserved1[2];
	PHEAP_PSEUDO_TAG_ENTRY PseudoTagEntries;

	LIST_ENTRY FreeLists[HEAP_MAXIMUM_FREELISTS];

	PHEAP_LOCK LockVariable;
	PVOID CommitRoutine;

	//
	//  The following field is used to manage the heap lookaside list.  The
	//  pointer is used to locate the lookaside list array.  If it is null
	//  then the lookaside list is not active.
	//
	//  The lock count is used to denote if the heap is locked.  A zero value
	//  means the heap is not locked.  Each lock operation increments the
	//  heap count and each unlock decrements the counter
	//

	PVOID Lookaside;
	ULONG LookasideLockCount;

} HEAP, *PHEAP;

#define HEAP_SIGNATURE                      (ULONG)0xEEFFEEFF
#define HEAP_LOCK_USER_ALLOCATED            (ULONG)0x80000000
#define HEAP_VALIDATE_PARAMETERS_ENABLED    (ULONG)0x40000000
#define HEAP_VALIDATE_ALL_ENABLED           (ULONG)0x20000000
#define HEAP_SKIP_VALIDATION_CHECKS         (ULONG)0x10000000
#define HEAP_CAPTURE_STACK_BACKTRACES       (ULONG)0x08000000

#define CHECK_HEAP_TAIL_SIZE HEAP_GRANULARITY
#define CHECK_HEAP_TAIL_FILL 0xAB
#define FREE_HEAP_FILL 0xFEEEFEEE
#define ALLOC_HEAP_FILL 0xBAADF00D

#define HEAP_GLOBAL_TAG                 0x0800
#define HEAP_PSEUDO_TAG_FLAG            0x8000
#define HEAP_TAG_MASK                  (HEAP_MAXIMUM_TAG << HEAP_TAG_SHIFT)
#define HEAP_TAGS_MASK                 (HEAP_TAG_MASK ^ (0xFF << HEAP_TAG_SHIFT))

#define HEAP_MAXIMUM_SMALL_TAG              0xFF
#define HEAP_SMALL_TAG_MASK                 (HEAP_MAXIMUM_SMALL_TAG << HEAP_TAG_SHIFT)
#define HEAP_NEED_EXTRA_FLAGS ((HEAP_TAG_MASK ^ HEAP_SMALL_TAG_MASK)  | \
                               HEAP_CAPTURE_STACK_BACKTRACES          | \
                               HEAP_SETTABLE_USER_VALUE                 \
                              )
#define HEAP_NUMBER_OF_PSEUDO_TAG           (HEAP_MAXIMUM_FREELISTS+1)


#if (HEAP_ENTRY_SETTABLE_FLAG1 ^    \
     HEAP_ENTRY_SETTABLE_FLAG2 ^    \
     HEAP_ENTRY_SETTABLE_FLAG3 ^    \
     HEAP_ENTRY_SETTABLE_FLAGS      \
    )
#error Invalid HEAP_ENTRY_SETTABLE_FLAGS
#endif

#if ((HEAP_ENTRY_BUSY ^             \
      HEAP_ENTRY_EXTRA_PRESENT ^    \
      HEAP_ENTRY_FILL_PATTERN ^     \
      HEAP_ENTRY_VIRTUAL_ALLOC ^    \
      HEAP_ENTRY_LAST_ENTRY ^       \
      HEAP_ENTRY_SETTABLE_FLAGS     \
     ) !=                           \
     (HEAP_ENTRY_BUSY |             \
      HEAP_ENTRY_EXTRA_PRESENT |    \
      HEAP_ENTRY_FILL_PATTERN |     \
      HEAP_ENTRY_VIRTUAL_ALLOC |    \
      HEAP_ENTRY_LAST_ENTRY |       \
      HEAP_ENTRY_SETTABLE_FLAGS     \
     )                              \
    )
#error Conflicting HEAP_ENTRY flags
#endif

//
// Define heap lookaside list allocation functions.
//

typedef struct _HEAP_LOOKASIDE {
	SLIST_HEADER ListHead;

	USHORT Depth;
	USHORT MaximumDepth;

	ULONG TotalAllocates;
	ULONG AllocateMisses;
	ULONG TotalFrees;
	ULONG FreeMisses;

	ULONG LastTotalAllocates;
	ULONG LastAllocateMisses;

	ULONG Future[2];

} HEAP_LOOKASIDE, *PHEAP_LOOKASIDE;


typedef struct _HEAP_STOP_ON_TAG {
	union {
		ULONG HeapAndTagIndex;
		struct {
			USHORT TagIndex;
			USHORT HeapIndex;
		};
	};
} HEAP_STOP_ON_TAG, *PHEAP_STOP_ON_TAG;

typedef struct _HEAP_STOP_ON_VALUES {
	SIZE_T AllocAddress;
	HEAP_STOP_ON_TAG AllocTag;
	SIZE_T ReAllocAddress;
	HEAP_STOP_ON_TAG ReAllocTag;
	SIZE_T FreeAddress;
	HEAP_STOP_ON_TAG FreeTag;
} HEAP_STOP_ON_VALUES, *PHEAP_STOP_ON_VALUES;

#define HEAP_FLAG_PAGE_ALLOCS 0x01000000

// 
// User-Defined Heap Flags and Classes 
// 

#define HEAP_SETTABLE_USER_VALUE                            0x00000100 
#define HEAP_SETTABLE_USER_FLAG1                            0x00000200 
#define HEAP_SETTABLE_USER_FLAG2                            0x00000400 
#define HEAP_SETTABLE_USER_FLAG3                            0x00000800 
#define HEAP_SETTABLE_USER_FLAGS                            0x00000E00 
#define HEAP_CLASS_0                                        0x00000000 
#define HEAP_CLASS_1                                        0x00001000 
#define HEAP_CLASS_2                                        0x00002000 
#define HEAP_CLASS_3                                        0x00003000 
#define HEAP_CLASS_4                                        0x00004000 
#define HEAP_CLASS_5                                        0x00005000 
#define HEAP_CLASS_6                                        0x00006000 
#define HEAP_CLASS_7                                        0x00007000 
#define HEAP_CLASS_8                                        0x00008000 
#define HEAP_CLASS_MASK                                     0x0000F000 

#define HEAP_DEBUG_FLAGS   (HEAP_VALIDATE_PARAMETERS_ENABLED | \
                            HEAP_VALIDATE_ALL_ENABLED        | \
                            HEAP_CAPTURE_STACK_BACKTRACES    | \
                            HEAP_CREATE_ENABLE_TRACING       | \
                            HEAP_FLAG_PAGE_ALLOCS)
//
//  If any of these flags are set, the fast allocator punts
//  to the slow do-everything allocator.
//

#define HEAP_SLOW_FLAGS (HEAP_DEBUG_FLAGS           | \
                         HEAP_SETTABLE_USER_FLAGS   | \
                         HEAP_NEED_EXTRA_FLAGS      | \
                         HEAP_CREATE_ALIGN_16       | \
                         HEAP_FREE_CHECKING_ENABLED | \
                         HEAP_TAIL_CHECKING_ENABLED)
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

#pragma region Globals

typedef enum
{
	undefined = 0,
	x86 = 1,
	x86_x64 = 2
} Architecture_Type;

typedef struct _HcGlobalEnv
{
	/* Is the process running with administrative privileges? */
	BOOLEAN IsElevated;

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

} HcGlobalEnv, *PHcGlobalEnv;

HC_GLOBAL HcGlobalEnv HcGlobal;
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
	HIGHCALL_STATUS HCAPI HcInitialize();

#ifdef _WIN64
	/* implemented in wow64stdcall.asm */
	HC_EXTERN_API DWORD64 Wow64StdCall(LPCVOID lpRoutine, DWORD64 dwArgCount, DWORD64 unused_0, DWORD64 unused_1, ...);
#else
	HC_EXTERN_API DWORD64 FORCEINLINE __declspec(deprecated) Wow64StdCall(LPCVOID lpRoutine, DWORD64 dwArgCount, DWORD64 unused_0, DWORD64 unused_1, ...) { return 0; }
#endif

	/* implemented in common.c */
	DECL_EXTERN_API(VOID, Sleep, CONST IN DWORD dwMilliseconds);

	/* implemented in construct.c */
	DECL_EXTERN_API(PHC_MODULE_INFORMATIONW, InitializeModuleInformationW, CONST IN DWORD NameBufferMax, CONST IN DWORD PathBufferMax);
	DECL_EXTERN_API(VOID, DestroyModuleInformationW, IN PHC_MODULE_INFORMATIONW pObject);
	DECL_EXTERN_API(PHC_PROCESS_INFORMATION_EXW, InitializeProcessInformationExW, CONST IN DWORD NameBufferMax);
	DECL_EXTERN_API(VOID, DestroyProcessInformationExW, IN PHC_PROCESS_INFORMATION_EXW pObject);
	DECL_EXTERN_API(PHC_PROCESS_INFORMATIONW, InitializeProcessInformationW, CONST IN DWORD NameBufferMax);
	DECL_EXTERN_API(VOID, DestroyProcessInformationW, IN PHC_PROCESS_INFORMATIONW pObj);

	/* implemented in error.c */
	DECL_EXTERN_API(VOID, ErrorSetDosError, CONST IN DWORD dwErrCode);
	DECL_EXTERN_API(DWORD, ErrorGetDosError);
	DECL_EXTERN_API(DWORD, ErrorSetNtStatus, CONST IN NTSTATUS Status);
	DECL_EXTERN_API(NTSTATUS, ErrorGetLastStatus);

	/* defined in file.c */
	DECL_EXTERN_API(BOOLEAN, FileExistsA, IN LPCSTR lpFilePath);
	DECL_EXTERN_API(BOOLEAN, FileExistsW, IN LPCWSTR lpFilePath);
	DECL_EXTERN_API(DWORD, FileSize, CONST IN HANDLE hFile);
	DECL_EXTERN_API(DWORD, FileSizeA, IN LPCSTR lpPath);
	DECL_EXTERN_API(DWORD, FileSizeW, IN LPCWSTR lpPath);
	DECL_EXTERN_API(ULONG, FileOffsetByExportNameA, IN HMODULE hModule OPTIONAL, IN LPCSTR lpExportName);
	DECL_EXTERN_API(ULONG, FileOffsetByExportNameW, IN HMODULE hModule OPTIONAL, IN LPCWSTR lpExportName);
	DECL_EXTERN_API(ULONG, FileOffsetByVirtualAddress, IN LPCVOID lpAddress);
	DECL_EXTERN_API(DWORD, FileReadModuleA, CONST IN HMODULE hModule, IN LPCSTR lpExportName, IN OUT PBYTE lpBuffer, CONST IN DWORD dwCount);
	DECL_EXTERN_API(DWORD, FileReadModuleW, CONST IN HMODULE hModule, IN LPCWSTR lpExportName, IN OUT PBYTE lpBuffer, CONST IN DWORD dwCount);
	DECL_EXTERN_API(DWORD, FileReadAddress, IN LPCVOID lpAddress, OUT PBYTE lpBufferOut, CONST IN DWORD dwCountToRead);
	/* @unimplemented: add ANSI */
	DECL_EXTERN_API(SIZE_T, FileGetCurrentDirectoryW, IN LPWSTR buf);
	DECL_EXTERN_API(DWORD, FileWrite, CONST IN HANDLE hFile, IN LPCVOID lpBuffer, IN DWORD nNumberOfBytesToWrite);
	DECL_EXTERN_API(DWORD, FileRead, CONST IN HANDLE hFile, IN OUT LPVOID lpBuffer, CONST IN DWORD nNumberOfBytesToRead);
	DECL_EXTERN_API(DWORD, FileSetCurrent, CONST IN HANDLE hFile, CONST IN LONG lDistanceToMove, CONST IN DWORD dwMoveMethod);
	DECL_EXTERN_API(HANDLE, FileOpenW, IN LPCWSTR lpFileName, IN DWORD dwCreationDisposition, IN DWORD dwDesiredAccess);
	DECL_EXTERN_API(HANDLE, FileOpenA, IN LPCSTR lpFileName, IN DWORD dwCreationDisposition, IN DWORD dwDesiredAccess);

	/* defined in hook.c */
	DECL_EXTERN_API(HStatus, HookDetour, CONST IN PDetourContext Context);
	DECL_EXTERN_API(HStatus, HookDetourContextRestore, CONST IN PDetourContext Context);
	DECL_EXTERN_API(HStatus, HookRelocateCode, CONST IN PBYTE Code, IN DWORD Size, CONST IN PBYTE Source);
	DECL_EXTERN_API(PVOID, HookCreateCave32, IN LPVOID lpBaseAddress, CONST IN SIZE_T Size);
	DECL_EXTERN_API(PVOID, HookCreateCave64, IN LPVOID lpBaseAddress, CONST IN SIZE_T Size);
	DECL_EXTERN_API(DWORD, HookAssertLength, IN LPCVOID lpBaseAddress, CONST IN DWORD MinimumLength);
	DECL_EXTERN_API(PVOID, HookRecreateCode, CONST IN PBYTE lpBaseAddress, CONST IN DWORD dwMinimumSize);

	/* defined in inject.c */
	DECL_EXTERN_API(BOOLEAN, InjectManualMapW, CONST IN HANDLE hProcess, IN LPCWSTR szcPath);
	DECL_EXTERN_API(BOOLEAN, InjectRemoteThreadW, CONST IN HANDLE hProcess, IN LPCWSTR szcPath);

	/* defined in process.c */
	DECL_EXTERN_API(DWORD, ProcessGetCurrentId, VOID);
	DECL_EXTERN_API(DWORD, ProcessGetId, IN HANDLE Process);
	DECL_EXTERN_API(BOOLEAN, ProcessIsWow64Ex, CONST IN HANDLE hProcess);
	DECL_EXTERN_API(BOOLEAN, ProcessIsWow64, CONST IN DWORD dwProcessId);
	DECL_EXTERN_API(BOOLEAN, ProcessExitCode, CONST IN SIZE_T dwProcessId, IN LPDWORD lpExitCode);
	DECL_EXTERN_API(BOOLEAN, ProcessExitCodeEx, CONST IN HANDLE hProcess, IN LPDWORD lpExitCode);
	DECL_EXTERN_API(HANDLE, ProcessOpen, CONST SIZE_T dwProcessId, CONST ACCESS_MASK DesiredAccess);
	DECL_EXTERN_API(BOOLEAN, ProcessWriteMemory, CONST HANDLE hProcess, CONST LPVOID lpBaseAddress, CONST VOID* lpBuffer, SIZE_T nSize, PSIZE_T lpNumberOfBytesWritten);
	DECL_EXTERN_API(BOOLEAN, ProcessReadMemory, CONST IN HANDLE hProcess, IN LPCVOID lpBaseAddress, IN LPVOID lpBuffer, IN SIZE_T nSize, OUT PSIZE_T lpNumberOfBytesRead);
	DECL_EXTERN_API(HANDLE, ProcessCreateThread, CONST IN HANDLE hProcess, CONST IN LPTHREAD_START_ROUTINE lpStartAddress, CONST IN LPVOID lpParamater, CONST IN DWORD dwCreationFlags);
	DECL_EXTERN_API(BOOLEAN, ProcessReadNullifiedString, CONST HANDLE hProcess, CONST PUNICODE_STRING usStringIn, LPWSTR lpStringOut, CONST SIZE_T lpSize);
	DECL_EXTERN_API(BOOLEAN, ProcessLdrModuleToHighCallModule, CONST IN HANDLE hProcess, CONST IN PLDR_DATA_TABLE_ENTRY Module, OUT PHC_MODULE_INFORMATIONW phcModuleOut);
	DECL_EXTERN_API(BOOLEAN, ProcessQueryInformationModule, CONST IN HANDLE hProcess, IN HMODULE hModule OPTIONAL, OUT PHC_MODULE_INFORMATIONW phcModuleOut);
	DECL_EXTERN_API(BOOLEAN, ProcessEnumModulesW, CONST HANDLE hProcess, CONST HC_MODULE_CALLBACK_EVENTW pCallback, LPARAM lParam);
	DECL_EXTERN_API(BOOLEAN, ProcessEnumMappedImagesW, CONST HANDLE ProcessHandle, CONST HC_MODULE_CALLBACK_EVENTW pCallback, LPARAM lParam);
	/* does not handle NULL lpModuleName */
	DECL_EXTERN_API(HMODULE, ProcessGetModuleHandleByNameAdvW, CONST IN HANDLE hProcess, IN LPCWSTR lpModuleName, IN BOOLEAN Bit32);
	DECL_EXTERN_API(BOOLEAN, ProcessReady, CONST SIZE_T dwProcessId);
	DECL_EXTERN_API(BOOLEAN, ProcessReadyEx, CONST HANDLE hProcess);
	DECL_EXTERN_API(BOOLEAN, ProcessSuspend, CONST SIZE_T dwProcessId);
	DECL_EXTERN_API(BOOLEAN, ProcessSuspendEx, CONST HANDLE hProcess);
	DECL_EXTERN_API(BOOLEAN, ProcessResume, CONST SIZE_T dwProcessId);
	DECL_EXTERN_API(BOOLEAN, ProcessResumeEx, CONST HANDLE hProcess);
	DECL_EXTERN_API(SIZE_T, ProcessModuleFileName, CONST HANDLE hProcess, CONST LPVOID lpv, LPWSTR lpFilename, CONST DWORD nSize);
	DECL_EXTERN_API(BOOLEAN, ProcessGetById, CONST IN DWORD dwProcessId, OUT PHC_PROCESS_INFORMATIONW pProcessInfo);
	DECL_EXTERN_API(BOOLEAN, ProcessGetByNameW, CONST IN LPCWSTR lpName, OUT PHC_PROCESS_INFORMATIONW pProcessInfo);
	DECL_EXTERN_API(BOOLEAN, ProcessEnumHandleEntries, HC_HANDLE_ENTRY_CALLBACKW callback, LPARAM lParam);
	DECL_EXTERN_API(BOOLEAN, ProcessEnumHandles, HC_HANDLE_CALLBACKW callback, DWORD dwTypeIndex, LPARAM lParam);
	DECL_EXTERN_API(BOOLEAN, ProcessEnumByNameW, CONST LPCWSTR lpProcessName, HC_PROCESS_CALLBACKW pCallback, LPARAM lParam);
	DECL_EXTERN_API(BOOLEAN, ProcessEnumByNameExW, CONST LPCWSTR lpProcessName, HC_PROCESS_CALLBACK_EXW pCallback, LPARAM lParam);
	DECL_EXTERN_API(BOOLEAN, ProcessSetPrivilegeA, CONST HANDLE hProcess, CONST LPCSTR Privilege, CONST BOOLEAN bEnablePrivilege);
	DECL_EXTERN_API(BOOLEAN, ProcessSetPrivilegeW, CONST HANDLE hProcess, CONST LPCWSTR Privilege, CONST BOOLEAN bEnablePrivilege);
	DECL_EXTERN_API(BOOLEAN, ProcessGetPebWow64, CONST HANDLE hProcess, PPEB32 pPeb);
	DECL_EXTERN_API(BOOLEAN, ProcessGetPeb64, CONST HANDLE hProcess, PPEB64 pPeb);
	DECL_EXTERN_API(BOOLEAN, ProcessGetPeb32, CONST HANDLE hProcess, PPEB32 pPeb);
	DECL_EXTERN_API(BOOLEAN, ProcessGetPeb, CONST HANDLE hProcess, PPEB pPeb);
	DECL_EXTERN_API(DWORD, ProcessGetCommandLineA, CONST HANDLE hProcess, LPSTR* lpszCommandline, CONST BOOLEAN bAlloc);
	DECL_EXTERN_API(DWORD, ProcessGetCommandLineW, CONST HANDLE hProcess, LPWSTR* lpszCommandline, CONST BOOLEAN bAlloc);
	DECL_EXTERN_API(DWORD, ProcessGetCurrentDirectoryW, CONST HANDLE hProcess, LPWSTR* szDirectory);
	DECL_EXTERN_API(DWORD, ProcessGetCurrentDirectoryA, CONST HANDLE hProcess, LPSTR* szDirectory);

	/* defined in internal.c */
	DECL_EXTERN_API(BOOLEAN, InternalCompare, IN PBYTE pbFirst, IN PBYTE pbSecond, IN SIZE_T tLength);
	DECL_EXTERN_API(PVOID, InternalCopy, IN PVOID pDst, CONST IN LPCVOID pSrc, CONST IN SIZE_T tCount);
	DECL_EXTERN_API(PVOID, InternalMove, IN PVOID pDst, IN PVOID pSrc, IN SIZE_T tCount);
	DECL_EXTERN_API(PVOID, InternalSet, IN PVOID pDst, CONST IN BYTE bVal, IN SIZE_T tCount);
	DECL_EXTERN_API(BOOLEAN, InternalValidate, IN LPCVOID lpcAddress);
	DECL_EXTERN_API(LPVOID, InternalLocatePointer, IN LPCVOID lpcAddress, CONST IN PSIZE_T ptOffsets, CONST IN SIZE_T tCount);
	DECL_EXTERN_API(INT, InternalReadIntEx32, IN LPCVOID lpcAddress, CONST IN PSIZE_T ptOffsets, CONST IN SIZE_T tCount);
	DECL_EXTERN_API(INT64, InternalReadIntEx64, IN LPCVOID lpcAddress, CONST IN PSIZE_T ptOffsets, CONST IN SIZE_T tCount);
	DECL_EXTERN_API(BOOLEAN, InternalMemoryWrite, IN LPVOID lpAddress, IN SIZE_T tLength, CONST IN PBYTE pbNew);
	DECL_EXTERN_API(BOOLEAN, InternalMemoryNopInstruction, IN LPVOID pAddress);
	DECL_EXTERN_API(LPBYTE, InternalPatternFind, IN LPCSTR szcPattern, IN LPCSTR szcMask, CONST IN PHC_MODULE_INFORMATIONW pmInfo);
	DECL_EXTERN_API(LPBYTE, InternalPatternFindInBuffer, IN LPCSTR szcPattern, IN LPCSTR szcMask, IN LPBYTE lpBuffer, CONST IN SIZE_T Size);

	/* defined in module.c */
	DECL_EXTERN_API(PLDR_DATA_TABLE_ENTRY, ModuleEntryW, IN LPCWSTR lpModuleName, CONST IN BOOLEAN CaseInSensitive);
	DECL_EXTERN_API(PLDR_DATA_TABLE_ENTRY, ModuleEntryBaseW, CONST IN HMODULE hModule);
	DECL_EXTERN_API(DWORD, ModuleFileNameA, CONST IN HANDLE hModule, OUT LPSTR lpModuleFileName);
	DECL_EXTERN_API(DWORD, ModuleFileNameW, CONST IN HANDLE hModule, OUT LPWSTR lpModuleFileName);
	DECL_EXTERN_API(DWORD, ModuleNameA, CONST IN HMODULE hModule, OUT LPSTR lpModuleFileName);
	DECL_EXTERN_API(DWORD, ModuleNameW, CONST IN HMODULE hModule, OUT LPWSTR lpModuleFileName);
	DECL_EXTERN_API(ULONG_PTR, ModuleChecksum, CONST IN HMODULE hModule);
	DECL_EXTERN_API(ULONG_PTR, ModuleEntryPoint, CONST IN HMODULE hModule);
	DECL_EXTERN_API(ULONG_PTR, ModuleSize, CONST IN HMODULE hModule);
	DECL_EXTERN_API(HMODULE, ModuleHandleA, IN LPCSTR lpModuleName);
	DECL_EXTERN_API(HMODULE, ModuleHandleW, IN LPCWSTR lpModuleName);
	DECL_EXTERN_API(HMODULE, ModuleHandleExW, IN LPCWSTR lpModuleName, CONST IN BOOLEAN CaseInSensitive);
	DECL_EXTERN_API(HMODULE, ModuleHandleWow64W, IN LPCWSTR lpModuleName);
	DECL_EXTERN_API(ULONG_PTR, ModuleProcedureAddress32A, CONST IN ULONG_PTR hModule, IN LPCSTR lpProcedureName);
	DECL_EXTERN_API(ULONG64, ModuleProcedureAddress64A, CONST IN ULONG64 hModule, IN LPCSTR lpProcedureName);
	DECL_EXTERN_API(ULONG_PTR, ModuleProcedureAddress32W, CONST IN ULONG_PTR hModule, IN LPCWSTR lpProcedureName);
	DECL_EXTERN_API(ULONG64, ModuleProcedureAddress64W, CONST IN ULONG64 hModule, IN LPCWSTR lpProcedureName);
	DECL_EXTERN_API(BOOLEAN, ModuleHide, CONST IN HMODULE hModule);
	DECL_EXTERN_API(HMODULE, ModuleLoadA, IN LPCSTR lpPath);
	DECL_EXTERN_API(HMODULE, ModuleLoadW, IN LPCWSTR lpPath);
	DECL_EXTERN_API(BOOLEAN, ModuleUnload, CONST IN HMODULE hModule);
	DECL_EXTERN_API(HMODULE, ModuleHandleAdvW, IN LPCWSTR lpModuleName, CONST IN BOOLEAN bBit32);
	DECL_EXTERN_API(HMODULE, ModuleHandleAdvA, IN LPCSTR lpModuleName, CONST IN BOOLEAN bBit32);

	/* defined in object.c */
	DECL_EXTERN_API(HANDLE, ObjectTranslateHandle, CONST IN HANDLE Handle);
	DECL_EXTERN_API(DWORD, ObjectTypeIndexByName, IN LPCWSTR lpObjectName);
	DECL_EXTERN_API(PLARGE_INTEGER, ObjectMillisecondsToNano, OUT PLARGE_INTEGER Timeout, CONST IN DWORD dwMiliseconds);
	DECL_EXTERN_API(DWORD, ObjectWaitMultiple, IN DWORD nCount, IN CONST PHANDLE lpHandles, IN BOOL bWaitAll, IN DWORD dwMilliseconds);
	DECL_EXTERN_API(DWORD, ObjectWait, IN HANDLE hObject, IN DWORD dwMiliseconds);
	DECL_EXTERN_API(VOID, ObjectClose, IN PHANDLE phObject);

	/* defined in pexec.c */
	DECL_EXTERN_API(BOOLEAN, PEIsValid, CONST IN HMODULE hModule);
	DECL_EXTERN_API(PIMAGE_DOS_HEADER, PEGetDosHeader, CONST IN HMODULE hModule);
	DECL_EXTERN_API(PIMAGE_NT_HEADERS32, PEGetNtHeader32, CONST IN ULONG_PTR hModule);
	DECL_EXTERN_API(PIMAGE_NT_HEADERS64, PEGetNtHeader64, CONST IN ULONG64 hModule);
	DECL_EXTERN_API(PIMAGE_NT_HEADERS, PEGetNtHeader, CONST IN HMODULE hModule);
	DECL_EXTERN_API(PIMAGE_EXPORT_DIRECTORY, PEGetExportDirectory32, CONST IN ULONG_PTR hModule);
	DECL_EXTERN_API(PIMAGE_EXPORT_DIRECTORY, PEGetExportDirectory64, CONST IN ULONG64 hModule);
	DECL_EXTERN_API(PIMAGE_EXPORT_DIRECTORY, PEGetExportDirectory, CONST IN HMODULE hModule);
	DECL_EXTERN_API(ULONG, PEOffsetFromRVA32, CONST IN PIMAGE_NT_HEADERS32 pImageHeader, IN DWORD RVA);
	DECL_EXTERN_API(ULONG, PEOffsetFromRVA64, CONST IN PIMAGE_NT_HEADERS64 pImageHeader, IN DWORD RVA);
	DECL_EXTERN_API(ULONG, PEOffsetFromRVA, CONST IN PIMAGE_NT_HEADERS pImageHeader, IN DWORD RVA);

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
	DECL_EXTERN_API(DWORD, StringEndOfA, IN LPCSTR lpStr, IN LPCSTR lpDelimiter, CONST IN BOOLEAN CaseInsensitive);
	DECL_EXTERN_API(DWORD, StringEndOfW, IN LPCWSTR lpStr, IN LPCWSTR lpDelimiter, CONST IN BOOLEAN CaseInsensitive);
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
	DECL_EXTERN_API(LPSTR, StringWithinStringA, IN LPCSTR szStr, IN LPCSTR szToFind, CONST IN BOOLEAN CaseInsensitive);
	DECL_EXTERN_API(LPWSTR, StringWithinStringW, IN LPCWSTR szStr, IN LPCWSTR szToFind, CONST IN BOOLEAN CaseInsensitive);
	DECL_EXTERN_API(LPSTR, StringWithinStringLastA, IN LPCSTR szStr, IN LPCSTR szToFind, CONST IN BOOLEAN CaseInsensitive);
	DECL_EXTERN_API(LPWSTR, StringWithinStringLastW, IN LPCWSTR szStr, IN LPCWSTR szToFind, CONST IN BOOLEAN CaseInsensitive);
	DECL_EXTERN_API(BOOLEAN, StringContainsA, IN LPCSTR lpString1, IN LPCSTR lpString2, CONST IN BOOLEAN CaseInSensitive);
	DECL_EXTERN_API(BOOLEAN, StringContainsW, IN LPCWSTR lpString1, IN LPCWSTR lpString2, CONST IN BOOLEAN CaseInSensitive);
	DECL_EXTERN_API(BOOLEAN, StringCopyConvertAtoW, IN LPCSTR lpStringToConvert, OUT LPWSTR lpStringOut, CONST IN DWORD dwStringCount);
	DECL_EXTERN_API(BOOLEAN, StringCopyConvertWtoA, IN LPCWSTR lpStringToConvert, OUT LPSTR lpStringOut, CONST IN DWORD dwStringCount);
	DECL_EXTERN_API(LPWSTR, StringConvertAtoW, IN LPCSTR lpStringConvert);
	DECL_EXTERN_API(LPSTR, StringConvertWtoA, IN LPCWSTR lpStringConvert);
	DECL_EXTERN_API(BOOLEAN, StringCopyA, OUT LPSTR szOut, IN LPCSTR szcIn, CONST IN DWORD dwLen OPTIONAL);
	DECL_EXTERN_API(BOOLEAN, StringCopyW, OUT LPWSTR szOut, IN LPCWSTR szcIn, CONST IN DWORD dwLen OPTIONAL);

	/* defined in privilege.c
	** @unimplemented
	*/
	DECL_EXTERN_API(PLUID, LookupPrivilegeValueW, LPCWSTR Name);
	DECL_EXTERN_API(PLUID, LookupPrivilegeValueA, LPCSTR Name);
	DECL_EXTERN_API(NTSTATUS, TokenIsElevated, _In_ HANDLE TokenHandle, _Out_ PBOOLEAN Elevated);

	/* defined in virtual.c */
	DECL_EXTERN_API(LPVOID, VirtualAllocEx, CONST IN HANDLE hProcess, IN LPVOID lpAddress, IN SIZE_T dwSize, CONST IN DWORD flAllocationType, CONST IN DWORD flProtect);
	DECL_EXTERN_API(LPVOID, VirtualAlloc, IN LPVOID lpAddress, IN SIZE_T dwSize, CONST IN DWORD flAllocationType, CONST IN DWORD flProtect);
	DECL_EXTERN_API(BOOL, VirtualFreeEx, CONST IN HANDLE hProcess, IN LPVOID lpAddress, IN SIZE_T dwSize, CONST IN DWORD dwFreeType);
	DECL_EXTERN_API(BOOL, VirtualFree, IN LPVOID lpAddress, CONST IN SIZE_T dwSize, CONST IN DWORD dwFreeType);
	DECL_EXTERN_API(BOOL, VirtualProtect, IN LPVOID lpAddress, CONST IN SIZE_T dwSize, CONST IN DWORD flNewProtect, OUT PDWORD lpflOldProtect);
	DECL_EXTERN_API(BOOL, VirtualProtectEx, CONST IN HANDLE hProcess, IN LPVOID lpAddress, IN SIZE_T dwSize, CONST IN DWORD flNewProtect, OUT PDWORD lpflOldProtect);
	DECL_EXTERN_API(BOOL, VirtualLock, IN LPVOID lpAddress, CONST IN SIZE_T dwSize);
	DECL_EXTERN_API(SIZE_T, VirtualQuery, IN LPCVOID lpAddress, OUT PMEMORY_BASIC_INFORMATION lpBuffer, CONST IN SIZE_T dwLength);
	DECL_EXTERN_API(SIZE_T, VirtualQueryEx, CONST IN HANDLE hProcess, IN LPCVOID lpAddress, OUT PMEMORY_BASIC_INFORMATION lpBuffer, CONST IN SIZE_T dwLength);
	DECL_EXTERN_API(BOOL, VirtualUnlock, IN LPVOID lpAddress, CONST IN SIZE_T dwSize);
	DECL_EXTERN_API(LPVOID, Alloc32, CONST IN SIZE_T Size);
	DECL_EXTERN_API(PVOID, Alloc, CONST IN SIZE_T Size);
	DECL_EXTERN_API(VOID, Free, CONST IN LPVOID lpAddress);

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

	/* defined in path.c, lpBuffer is expected to be allocated with MAX_PATH * sizeof, TCHAR) in any function that does not specify a size parameter. */
	DECL_EXTERN_API(DWORD, PathGetFullPathNameA, IN LPCSTR lpFileName, OUT LPSTR lpBuffer);
	DECL_EXTERN_API(DWORD, PathGetFullPathNameW, IN LPCWSTR lpFileName, OUT LPWSTR lpBuffer);
	DECL_EXTERN_API(DWORD, PathGetTempFolderW, IN LPWSTR lpBuffer);
	DECL_EXTERN_API(DWORD, PathGetTempFolderA, IN LPWSTR lpBuffer);

#if defined (__cplusplus)
}
#endif

#endif