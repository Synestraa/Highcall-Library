/*++

Module Name:

hcvirtual.h

Abstract:

This module declares virtual memory handling functions from kernel32.dll.

Author:

Synestra 10/10/2016, information was gathered from various sources.

Revision History:

--*/

#ifndef HC_MEM_H
#define HC_MEM_H

#include "../public/wintype.h"

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

#if defined (__cplusplus)
extern "C" {
#endif

	HC_EXTERN_API LPVOID HCAPI HcVirtualAllocEx(IN HANDLE hProcess, IN LPVOID lpAddress, IN SIZE_T dwSize, IN DWORD flAllocationType, IN DWORD flProtect);
	HC_EXTERN_API LPVOID HCAPI HcVirtualAlloc(IN LPVOID lpAddress, IN SIZE_T dwSize, IN DWORD flAllocationType, IN DWORD flProtect);
	HC_EXTERN_API BOOL HCAPI HcVirtualFreeEx(IN HANDLE hProcess, IN LPVOID lpAddress, IN SIZE_T dwSize, IN DWORD dwFreeType);
	HC_EXTERN_API BOOL HCAPI HcVirtualFree(IN LPVOID lpAddress, IN SIZE_T dwSize, IN DWORD dwFreeType);
	HC_EXTERN_API BOOL HCAPI HcVirtualProtect(IN LPVOID lpAddress, IN SIZE_T dwSize, IN DWORD flNewProtect, OUT PDWORD lpflOldProtect);
	HC_EXTERN_API BOOL HCAPI HcVirtualProtectEx(IN HANDLE hProcess, IN LPVOID lpAddress, IN SIZE_T dwSize, IN DWORD flNewProtect, OUT PDWORD lpflOldProtect);
	HC_EXTERN_API BOOL HCAPI HcVirtualLock(IN LPVOID lpAddress, IN SIZE_T dwSize);
	HC_EXTERN_API SIZE_T HCAPI HcVirtualQuery(IN LPCVOID lpAddress, OUT PMEMORY_BASIC_INFORMATION lpBuffer, IN SIZE_T dwLength);
	HC_EXTERN_API SIZE_T HCAPI HcVirtualQueryEx(IN HANDLE hProcess, IN LPCVOID lpAddress, OUT PMEMORY_BASIC_INFORMATION lpBuffer, IN SIZE_T dwLength);
	HC_EXTERN_API BOOL HCAPI HcVirtualUnlock(IN LPVOID lpAddress, IN SIZE_T dwSize);

	//
	// @TODO: The function does not allocate on heap when it should, this should be changed.
	// Currently the function will use malloc() instead, as a temporary and possibly
	// long time replacement.
	//
	HC_EXTERN_API PVOID HCAPI HcAlloc(IN SIZE_T Size);

	//
	// @TODO: Reflecting HcAlloc @TODO, this function should free the heap.
	// Currently the function will use free() i nstead, as a temporary and possibly
	// long time replacement.
	//
	HC_EXTERN_API VOID HCAPI HcFree(IN LPVOID lpAddress);

#if defined (__cplusplus)
}
#endif

#endif