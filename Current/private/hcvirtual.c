/*++

Module Name:

hcvirtual.c

Abstract:

This module implements virtual memory handling functions from kernel32.dll

Author:

Synestra 7/9/2016, information was gathered from various sources.

Revision History:

Synestra 10/10/2016 revised HcAlloc and HcFree.

--*/

#include "sys/hcsyscall.h"

#include "../public/hcvirtual.h"
#include "../public/hcerror.h"
#include "../public/hcinternal.h"
#include "../public/imports.h"

//
// Unimplemented, in progress for a later replacement of malloc and free.
//

#ifdef NOT_IMPLEMENTED

PVOID
HcAllocateHeap(
	IN PVOID HeapHandle,
	IN ULONG Flags,
	IN SIZE_T Size
)

/*++

Routine Description:

This routine allocates a memory of the specified size from the specified
heap.

Arguments:

HeapHandle - Supplies a pointer to an initialized heap structure

Flags - Specifies the set of flags to use to control the allocation

Size - Specifies the size, in bytes, of the allocation

Return Value:

PVOID - returns a pointer to the newly allocated block

--*/

{
	PHEAP Heap = (PHEAP)HeapHandle;
	PULONG FreeListsInUse;
	ULONG FreeListsInUseUlong;
	SIZE_T AllocationSize;
	SIZE_T FreeSize, AllocationIndex;
	PLIST_ENTRY FreeListHead, Next;
	PHEAP_ENTRY BusyBlock;
	PHEAP_FREE_ENTRY FreeBlock, SplitBlock, SplitBlock2;
	ULONG InUseIndex;
	UCHAR FreeFlags;
	NTSTATUS Status;
	EXCEPTION_RECORD ExceptionRecord;
	PVOID ReturnValue;
	BOOLEAN LockAcquired = FALSE;

	//
	//  Take the callers flags and add in the flags that we must forcibly set
	//  in the heap
	//

	Flags |= Heap->ForceFlags;

	//
	//  Check for special features that force us to call the slow, do-everything
	//  version.  We do everything slow for any of the following flags.
	//
	//      HEAP_SLOW_FLAGS defined as          0x6f030f60
	//
	//      HEAP_DEBUG_FLAGS, defined as		0x69020000
	//
	//      HEAP_VALIDATE_PARAMETERS_ENABLED	0x40000000
	//
	//      HEAP_VALIDATE_ALL_ENABLED			0x20000000
	//
	//      HEAP_CAPTURE_STACK_BACKTRACES		0x08000000
	//
	//      HEAP_CREATE_ENABLE_TRACING			0x00020000 
	//
	//      HEAP_FLAG_PAGE_ALLOCS				0x01000000
	//
	//      HEAP_SETTABLE_USER_FLAGS			0x00000E00
	//
	//      HEAP_NEED_EXTRA_FLAGS				0x0f000100
	//
	//      HEAP_CREATE_ALIGN_16				0x00010000
	//
	//      HEAP_FREE_CHECKING_ENABLED			0x00000040
	//
	//      HEAP_TAIL_CHECKING_ENABLED			0x00000020
	//
	//  We also do everything slow if the size is greater than max long
	//

	if ((Flags & HEAP_SLOW_FLAGS) || (Size >= 0x80000000)) 
	{
		return RtlAllocateHeapSlowly(HeapHandle, Flags, Size);
	}

	//
	//  At this point we know we are doing everything in this routine
	//  and not taking the slow route.
	//
	//  Round the requested size up to the allocation granularity.  Note
	//  that if the request is for 0 bytes, we still allocate memory, because
	//  we add in an extra 1 byte to protect ourselves from idiots.
	//
	//      Allocation size will be either 16, 24, 32, ...
	//      Allocation index will be 2, 3, 4, ...
	//
	//  Note that allocation size 8 is skipped and are indices 0 and 1
	//

	AllocationSize = ((Size ? Size : 1) + HEAP_GRANULARITY - 1 + sizeof(HEAP_ENTRY))
		& ~(HEAP_GRANULARITY - 1);

	AllocationIndex = AllocationSize >> HEAP_GRANULARITY_SHIFT;

	//
	//  If there is a lookaside list and the index is within limits then
	//  try and allocate from the lookaside list.  We'll actually capture
	//  the lookaside pointer from the heap and only use the captured pointer.
	//  This will take care of the condition where a walk or lock heap can
	//  cause us to check for a non null pointer and then have it become null
	//  when we read it again.  If it is non null to start with then even if
	//  the user walks or locks the heap via another thread the pointer to
	//  still valid here so we can still try and do a lookaside list pop.
	//
	PHEAP_LOOKASIDE Lookaside = (PHEAP_LOOKASIDE)Heap->Lookaside;

	if ((Lookaside != NULL) &&
		(Heap->LookasideLockCount == 0) &&
		(AllocationIndex < HEAP_MAXIMUM_FREELISTS)) 
	{
		//
		//  If the number of operation elapsed operations is 128 times the
		//  lookaside depth then it is time to adjust the depth
		//

		if ((LONG)(Lookaside[AllocationIndex].TotalAllocates - Lookaside[AllocationIndex].LastTotalAllocates) >=
			(Lookaside[AllocationIndex].Depth * 128)) 
		{

			RtlpAdjustHeapLookasideDepth(&(Lookaside[AllocationIndex]));
		}

		ReturnValue = RtlpAllocateFromHeapLookaside(&(Lookaside[AllocationIndex]));

		if (ReturnValue != NULL) 
		{
			PHEAP_ENTRY BusyBlock;

			BusyBlock = ((PHEAP_ENTRY)ReturnValue) - 1;
			BusyBlock->UnusedBytes = (UCHAR)(AllocationSize - Size);
			BusyBlock->SmallTagIndex = 0;

			if (Flags & HEAP_ZERO_MEMORY) {

				RtlZeroMemory(ReturnValue, Size);
			}

			return ReturnValue;
		}
	}

	__try 
	{
		//
		//  Check if we need to serialize our access to the heap
		//

		if (!(Flags & HEAP_NO_SERIALIZE)) 
		{
			//
			//  Lock the free list.
			//

			RtlAcquireLockRoutine(Heap->LockVariable);

			LockAcquired = TRUE;
		}

		//
		//  If the allocation index is less than the maximum free list size
		//  then we can use the index to check the free list otherwise we have
		//  to either pull the entry off of the [0] index list or allocate
		//  memory directly for this request.
		//

		if (AllocationIndex < HEAP_MAXIMUM_FREELISTS) 
		{
			//
			//  With a size that matches a free list size grab the head
			//  of the list and check if there is an available entry
			//

			FreeListHead = &Heap->FreeLists[AllocationIndex];

			if (!IsListEmpty(FreeListHead)) 
			{
				//
				//  We're in luck the list has an entry so now get the free
				//  entry,  copy its flags, remove it from the free list
				//

				FreeBlock = CONTAINING_RECORD(FreeListHead->Blink,
					HEAP_FREE_ENTRY,
					FreeList);

				FreeFlags = FreeBlock->Flags;

				RtlpFastRemoveDedicatedFreeBlock(Heap, FreeBlock);

				//
				//  Adjust the total number of bytes free in the heap
				//

				Heap->TotalFreeSize -= AllocationIndex;

				//
				//  Mark the block as busy and and set the number of bytes
				//  unused and tag index.  Also if it is the last entry
				//  then keep that flag.
				//

				BusyBlock = (PHEAP_ENTRY)FreeBlock;
				BusyBlock->Flags = HEAP_ENTRY_BUSY | (FreeFlags & HEAP_ENTRY_LAST_ENTRY);
				BusyBlock->UnusedBytes = (UCHAR)(AllocationSize - Size);
				BusyBlock->SmallTagIndex = 0;

			}
			else 
			{
				//
				//  The free list that matches our request is empty
				//
				//  Scan the free list in use vector to find the smallest
				//  available free block large enough for our allocations.
				//

				//
				//  Compute the index of the ULONG where the scan should begin
				//

				InUseIndex = (ULONG)(AllocationIndex >> 5);
				FreeListsInUse = &Heap->u.FreeListsInUseUlong[InUseIndex];

				//
				//  Mask off the bits in the first ULONG that represent allocations
				//  smaller than we need.
				//

				FreeListsInUseUlong = *FreeListsInUse++ & ~((1 << ((ULONG)AllocationIndex & 0x1f)) - 1);

				//
				//  Begin unrolled loop to scan bit vector.
				//

				switch (InUseIndex) 
				{
				case 0:

					if (FreeListsInUseUlong) 
					{
						FreeListHead = &Heap->FreeLists[0];
						break;
					}

					FreeListsInUseUlong = *FreeListsInUse++;

					//
					//  deliberate fallthrough to next ULONG
					//

				case 1:

					if (FreeListsInUseUlong) 
					{
						FreeListHead = &Heap->FreeLists[32];
						break;
					}

					FreeListsInUseUlong = *FreeListsInUse++;

					//
					//  deliberate fallthrough to next ULONG
					//

				case 2:

					if (FreeListsInUseUlong) 
					{
						FreeListHead = &Heap->FreeLists[64];
						break;
					}

					FreeListsInUseUlong = *FreeListsInUse++;

					//
					//  deliberate fallthrough to next ULONG
					//

				case 3:

					if (FreeListsInUseUlong) 
					{
						FreeListHead = &Heap->FreeLists[96];
						break;
					}

					//
					//  deliberate fallthrough to non dedicated list
					//

				default:

					//
					//  No suitable entry on the free list was found.
					//

					goto LookInNonDedicatedList;
				}

				//
				//  A free list has been found with a large enough allocation.
				//  FreeListHead contains the base of the vector it was found in.
				//  FreeListsInUseUlong contains the vector.
				//

				FreeListHead += RtlFindFirstSetRightMember(FreeListsInUseUlong);

				//
				//  Grab the free block and remove it from the free list
				//

				FreeBlock = CONTAINING_RECORD(FreeListHead->Blink,
					HEAP_FREE_ENTRY,
					FreeList);

				RtlpFastRemoveDedicatedFreeBlock(Heap, FreeBlock);

			SplitFreeBlock:

				//
				//  Save the blocks flags and decrement the amount of
				//  free space left in the heap
				//

				FreeFlags = FreeBlock->Flags;
				Heap->TotalFreeSize -= FreeBlock->Size;

				//
				//  Mark the block busy
				//

				BusyBlock = (PHEAP_ENTRY)FreeBlock;
				BusyBlock->Flags = HEAP_ENTRY_BUSY;

				//
				//  Compute the size (i.e., index) of the amount from this block
				//  that we don't need and can return to the free list
				//

				FreeSize = BusyBlock->Size - AllocationIndex;

				//
				//  Finish setting up the rest of the new busy block
				//

				BusyBlock->Size = (USHORT)AllocationIndex;
				BusyBlock->UnusedBytes = (UCHAR)(AllocationSize - Size);
				BusyBlock->SmallTagIndex = 0;

				//
				//  Now if the size that we are going to free up is not zero
				//  then lets get to work and to the split.
				//

				if (FreeSize != 0) 
				{
					//
					//  But first we won't ever bother doing a split that only
					//  gives us 8 bytes back.  So if free size is one then just
					//  bump up the size of the new busy block
					//

					if (FreeSize == 1) 
					{

						BusyBlock->Size += 1;
						BusyBlock->UnusedBytes += sizeof(HEAP_ENTRY);

					}
					else 
					{
						//
						//  Get a pointer to where the new free block will be.
						//  When we split a block the first part goes to the new
						//  busy block and the second part goes back to the free
						//  list
						//

						SplitBlock = (PHEAP_FREE_ENTRY)(BusyBlock + AllocationIndex);

						//
						//  Reset the flags that we copied from the original free list
						//  header, and set it other size fields.
						//

						SplitBlock->Flags = FreeFlags;
						SplitBlock->PreviousSize = (USHORT)AllocationIndex;
						SplitBlock->SegmentIndex = BusyBlock->SegmentIndex;
						SplitBlock->Size = (USHORT)FreeSize;

						//
						//  If nothing else follows this entry then we will insert
						//  this into the corresponding free list (and update
						//  Segment->LastEntryInSegment)
						//

						if (FreeFlags & HEAP_ENTRY_LAST_ENTRY) 
						{
							RtlpFastInsertFreeBlockDirect(Heap, SplitBlock, (USHORT)FreeSize);
							Heap->TotalFreeSize += FreeSize;
						}
						else 
						{
							//
							//  Otherwise we need to check the following block
							//  and if it is busy then update its previous size
							//  before inserting our new free block into the
							//  free list
							//

							SplitBlock2 = (PHEAP_FREE_ENTRY)((PHEAP_ENTRY)SplitBlock + FreeSize);

							if (SplitBlock2->Flags & HEAP_ENTRY_BUSY) 
							{

								SplitBlock2->PreviousSize = (USHORT)FreeSize;

								RtlpFastInsertFreeBlockDirect(Heap, SplitBlock, (USHORT)FreeSize);
								Heap->TotalFreeSize += FreeSize;

							}
							else 
							{

								//
								//  The following block is free so we'll merge
								//  these to blocks. by first merging the flags
								//

								SplitBlock->Flags = SplitBlock2->Flags;

								//
								//  Removing the second block from its free list
								//

								RtlpFastRemoveFreeBlock(Heap, SplitBlock2);

								//
								//  Updating the free total number of free bytes
								//  in the heap and updating the size of the new
								//  free block
								//

								Heap->TotalFreeSize -= SplitBlock2->Size;
								FreeSize += SplitBlock2->Size;

								//
								//  If the new free block is still less than the
								//  maximum heap block size then we'll simply
								//  insert it back in the free list
								//

								if (FreeSize <= HEAP_MAXIMUM_BLOCK_SIZE) 
								{

									SplitBlock->Size = (USHORT)FreeSize;

									//
									//  Again check if the new following block
									//  exists and if so then updsate is previous
									//  size
									//

									if (!(SplitBlock->Flags & HEAP_ENTRY_LAST_ENTRY)) 
									{

										((PHEAP_FREE_ENTRY)((PHEAP_ENTRY)SplitBlock + FreeSize))->PreviousSize = (USHORT)FreeSize;
									}

									//
									//  Insert the new free block into the free
									//  list and update the free heap size
									//

									RtlpFastInsertFreeBlockDirect(Heap, SplitBlock, (USHORT)FreeSize);
									Heap->TotalFreeSize += FreeSize;

								}
								else 
								{

									//
									//  The new free block is pretty large so we
									//  need to call a private routine to do the
									//  insert
									//

									RtlpInsertFreeBlock(Heap, SplitBlock, FreeSize);
								}
							}
						}

						//
						//  Now that free flags made it back into a free block
						//  we can zero out what we saved.
						//

						FreeFlags = 0;

						//
						//  If splitblock now last, update LastEntryInSegment
						//

						if (SplitBlock->Flags & HEAP_ENTRY_LAST_ENTRY) 
						{
							PHEAP_SEGMENT Segment;

							Segment = Heap->Segments[SplitBlock->SegmentIndex];
							Segment->LastEntryInSegment = (PHEAP_ENTRY)SplitBlock;
						}
					}
				}

				//
				//  If there are no following entries then mark the new block as
				//  such
				//

				if (FreeFlags & HEAP_ENTRY_LAST_ENTRY) 
				{
					BusyBlock->Flags |= HEAP_ENTRY_LAST_ENTRY;
				}
			}

			//
			//  Return the address of the user portion of the allocated block.
			//  This is the byte following the header.
			//

			ReturnValue = BusyBlock + 1;

			//
			//  **** Release the lock before the zero memory call
			//

			if (LockAcquired) 
			{
				RtlReleaseLockRoutine(Heap->LockVariable);

				LockAcquired = FALSE;
			}

			//
			//  If the flags indicate that we should zero memory then do it now
			//

			if (Flags & HEAP_ZERO_MEMORY) 
			{
				RtlZeroMemory(ReturnValue, Size);
			}

			//
			//  And return the allocated block to our caller
			//

			goto leave;

			//
			//  Otherwise the allocation request is bigger than the last dedicated
			//  free list size.  Now check if the size is within our threshold.
			//  Meaning that it could be in the [0] free list
			//

		}
		else if (AllocationIndex <= Heap->VirtualMemoryThreshold) 
		{

		LookInNonDedicatedList:

			//
			//  The following code cycles through the [0] free list until
			//  it finds a block that satisfies the request.  The list
			//  is sorted so the search is can be terminated early on success
			//

			FreeListHead = &Heap->FreeLists[0];

			//
			//  Check if the largest block in the list is smaller than the request
			//

			Next = FreeListHead->Blink;

			if (FreeListHead != Next) {

				FreeBlock = CONTAINING_RECORD(Next, HEAP_FREE_ENTRY, FreeList);

				if (FreeBlock->Size >= AllocationIndex) {

					//
					//  Here we are sure there is at least a block here larger than
					//  the requested size. Start searching from the first block
					//

					Next = FreeListHead->Flink;

					while (FreeListHead != Next) {

						FreeBlock = CONTAINING_RECORD(Next, HEAP_FREE_ENTRY, FreeList);

						if (FreeBlock->Size >= AllocationIndex) {

							//
							//  We've found something that we can use so now remove
							//  it from the free list and go to where we treat spliting
							//  a free block.  Note that the block we found here might
							//  actually be the exact size we need and that is why
							//  in the split free block case we have to consider having
							//  nothing free after the split
							//

							RtlpFastRemoveNonDedicatedFreeBlock(Heap, FreeBlock);

							goto SplitFreeBlock;
						}

						Next = Next->Flink;
					}
				}
			}

			//
			//  The [0] list is either empty or everything is too small
			//  so now extend the heap which should get us something less
			//  than or equal to the virtual memory threshold
			//

			FreeBlock = RtlpExtendHeap(Heap, AllocationSize);

			//
			//  And provided we got something we'll treat it just like the previous
			//  split free block cases
			//

			if (FreeBlock != NULL) 
			{
				RtlpFastRemoveNonDedicatedFreeBlock(Heap, FreeBlock);

				goto SplitFreeBlock;
			}

			//
			//  We weren't able to extend the heap so we must be out of memory
			//

			Status = STATUS_NO_MEMORY;

			//
			//  At this point the allocation is way too big for any of the free lists
			//  and we can only satisfy this request if the heap is growable
			//

		}
		else if (Heap->Flags & HEAP_GROWABLE) 
		{

			PHEAP_VIRTUAL_ALLOC_ENTRY VirtualAllocBlock;

			VirtualAllocBlock = NULL;

			//
			//  Compute how much memory we will need for this allocation which
			//  will include the allocation size plus a header, and then go
			//  get the committed memory
			//

			AllocationSize += FIELD_OFFSET(HEAP_VIRTUAL_ALLOC_ENTRY, BusyBlock);

			Status = HcAllocateVirtualMemory(NtCurrentProcess,
				(PVOID *)&VirtualAllocBlock,
				0,
				&AllocationSize,
				MEM_COMMIT,
				PAGE_READWRITE);

			if (NT_SUCCESS(Status)) {

				//
				//  Just committed, already zero.  Fill in the new block
				//  and insert it in the list of big allocation
				//

				VirtualAllocBlock->BusyBlock.Size = (USHORT)(AllocationSize - Size);
				VirtualAllocBlock->BusyBlock.Flags = HEAP_ENTRY_VIRTUAL_ALLOC | HEAP_ENTRY_EXTRA_PRESENT | HEAP_ENTRY_BUSY;
				VirtualAllocBlock->CommitSize = AllocationSize;
				VirtualAllocBlock->ReserveSize = AllocationSize;

				InsertTailList(&Heap->VirtualAllocdBlocks, (PLIST_ENTRY)VirtualAllocBlock);

				//
				//  Return the address of the user portion of the allocated block.
				//  This is the byte following the header.
				//

				ReturnValue = (PHEAP_ENTRY)(VirtualAllocBlock + 1);

				goto leave;
			}

		}
		else 
		{
			Status = STATUS_BUFFER_TOO_SMALL;
		}

		//
		//  This is the error return.
		//

		if (Flags & HEAP_GENERATE_EXCEPTIONS) 
		{
			//
			//  Construct an exception record.
			//

			ExceptionRecord.ExceptionCode = STATUS_NO_MEMORY;
			ExceptionRecord.ExceptionRecord = (PEXCEPTION_RECORD)NULL;
			ExceptionRecord.NumberParameters = 1;
			ExceptionRecord.ExceptionFlags = 0;
			ExceptionRecord.ExceptionInformation[0] = AllocationSize;

			RtlRaiseException(&ExceptionRecord);
		}

		HcErrorSetNtStatus(Status);

		ReturnValue = NULL;

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = GetExceptionCode();
		HcErrorSetNtStatus(Status);
	}

leave:;
	if (LockAcquired) 
	{
		RtlReleaseLockRoutine(Heap->LockVariable);
	}

	return ReturnValue;
}

#endif

HC_EXTERN_API
LPVOID
HCAPI
HcVirtualAllocEx(IN HANDLE hProcess,
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN DWORD flAllocationType,
	IN DWORD flProtect)
{
	NTSTATUS Status;

	/* Allocate the memory */
	Status = HcAllocateVirtualMemory(hProcess,
		&lpAddress,
		0,
		&dwSize,
		flAllocationType,
		flProtect);

	/* Check for status */
	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		HcErrorSetNtStatus(Status);
		return NULL;
	}

	/* Return the allocated address */
	return lpAddress;
}

//
// kernel32.dll VirtualAlloc
//
HC_EXTERN_API
LPVOID
HCAPI
HcVirtualAlloc(IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN DWORD flAllocationType,
	IN DWORD flProtect)
{
	/* Call the extended API */
	return HcVirtualAllocEx(NtCurrentProcess,
		lpAddress,
		dwSize,
		flAllocationType,
		flProtect);
}

HC_EXTERN_API
BOOL
HCAPI
HcVirtualFreeEx(IN HANDLE hProcess,
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN DWORD dwFreeType)
{
	NTSTATUS Status;

	/* Validate size and flags */
	if (!dwSize || !(dwFreeType & MEM_RELEASE))
	{
		/* Free the memory */
		Status = HcFreeVirtualMemory(hProcess,
			&lpAddress,
			&dwSize,
			dwFreeType);

		if (!NT_SUCCESS(Status))
		{
			/* We failed */
			HcErrorSetNtStatus(Status);
			return FALSE;
		}

		/* Return success */
		return TRUE;
	}

	/* Invalid combo */
	HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
	return FALSE;
}


HC_EXTERN_API
BOOL
HCAPI
HcVirtualFree(IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN DWORD dwFreeType)
{
	/* Call the extended API */
	return HcVirtualFreeEx(NtCurrentProcess,
		lpAddress,
		dwSize,
		dwFreeType);
}

HC_EXTERN_API
BOOL
HCAPI
HcVirtualProtect(IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN DWORD flNewProtect,
	OUT PDWORD lpflOldProtect)
{
	/* Call the extended API */
	return HcVirtualProtectEx(NtCurrentProcess,
		lpAddress,
		dwSize,
		flNewProtect,
		lpflOldProtect);
}

HC_EXTERN_API
BOOL
HCAPI
HcVirtualProtectEx(IN HANDLE hProcess,
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN DWORD flNewProtect,
	OUT PDWORD lpflOldProtect)
{
	NTSTATUS Status;

	/* Make the call. */
	Status = HcProtectVirtualMemory(hProcess,
		&lpAddress,
		&dwSize,
		flNewProtect,
		(PULONG)lpflOldProtect);

	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	/* Return success */
	return TRUE;
}

HC_EXTERN_API
BOOL
HCAPI
HcVirtualLock(IN LPVOID lpAddress,
	IN SIZE_T dwSize)
{
	NTSTATUS Status;
	SIZE_T RegionSize = dwSize;
	PVOID BaseAddress = lpAddress;

	/* Make the call. */
	Status = HcLockVirtualMemory(NtCurrentProcess,
		&BaseAddress,
		&RegionSize,
		MAP_PROCESS);

	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	/* Return success */
	return TRUE;
}

HC_EXTERN_API
SIZE_T
HCAPI
HcVirtualQuery(IN LPCVOID lpAddress,
	OUT PMEMORY_BASIC_INFORMATION lpBuffer,
	IN SIZE_T dwLength)
{
	/* Call the extended API */
	return HcVirtualQueryEx(NtCurrentProcess,
		lpAddress,
		lpBuffer,
		dwLength);
}

HC_EXTERN_API
SIZE_T
HCAPI
HcVirtualQueryEx(IN HANDLE hProcess,
	IN LPCVOID lpAddress,
	OUT PMEMORY_BASIC_INFORMATION lpBuffer,
	IN SIZE_T dwLength)
{
	NTSTATUS Status; 
	SIZE_T ResultLength = 0;

	/* Make the call. */
	Status = HcQueryVirtualMemory(hProcess,
		(LPVOID)lpAddress,
		MemoryBasicInformation,
		lpBuffer,
		dwLength,
		&ResultLength);

	if (!NT_SUCCESS(Status))
	{
		HcErrorSetNtStatus(Status);
		return ResultLength;
	}

	/* Return the length returned */
	return ResultLength;
}

HC_EXTERN_API
BOOL
HCAPI
HcVirtualUnlock(IN LPVOID lpAddress,
	IN SIZE_T dwSize)
{
	NTSTATUS Status;
	SIZE_T RegionSize = dwSize;
	PVOID BaseAddress = lpAddress;

	/* Make the call. */
	Status = HcUnlockVirtualMemory(NtCurrentProcess,
		&BaseAddress,
		&RegionSize,
		MAP_PROCESS);

	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		HcErrorSetNtStatus(Status);
		return FALSE;
	}

	/* Return success */
	return TRUE;
}

HC_EXTERN_API
PVOID
HCAPI 
HcAlloc(IN SIZE_T Size)
{
	return RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

HC_EXTERN_API
VOID 
HCAPI 
HcFree(IN LPVOID lpAddress)
{
	RtlFreeHeap(RtlGetProcessHeap(), 0, lpAddress);
}