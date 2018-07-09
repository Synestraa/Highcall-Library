#include <highcall.h>

#include "../sys/syscall.h"
#include "../distorm/include/distorm.h"

#define MAX_INSTRUCTIONS 0x100
#define OPCODE_INSTRUCTION_NOP (0x90)

#ifndef _WIN64
#define JMPSIZE 5
#else
#define JMPSIZE 16
#endif

static
BOOLEAN
IsConditionalJump(const PBYTE InstructionBytes, const SHORT Size)
{
	if (Size < 1)
	{
		return FALSE;
	}

	if (InstructionBytes[0] == 0x0F)
	{
		if (InstructionBytes[1] >= 0x80 && InstructionBytes[1] <= 0x8F)
		{
			return TRUE;
		}
	}

	if (InstructionBytes[0] >= 0x70 && InstructionBytes[0] <= 0x7F)
	{
		return TRUE;
	}

	if (InstructionBytes[0] == 0xE3)
	{
		return TRUE;
	}

	return FALSE;
}

static
PBYTE GetRelativeDestination(PBYTE Source, PBYTE Destination, SIZE_T Size)
{
	return (Source < Destination) ? (PBYTE) (0 - (Source - Destination) - Size) : (PBYTE) (Destination - (Source + Size));
}

static
PBYTE GetClosestFreeSpace(PBYTE lpAddress, SIZE_T Size, SIZE_T MinimumSize, SIZE_T MaxLength)
{
	PBYTE FreeSpace = NULL;
	MEMORY_BASIC_INFORMATION mbi;
	ZERO(&mbi);

	for (PBYTE Addr = lpAddress + Size; Addr < (PBYTE)lpAddress + MaxLength + Size; Addr = Addr++)
	{
		/* Check the block */
		if (!HcVirtualQuery((LPCVOID)Addr, &mbi, sizeof(mbi)))
		{
			break;
		}

		if (mbi.State == MEM_FREE)
		{
			/* Try and allocate on this spot. */
			FreeSpace = (PBYTE)HcVirtualAlloc((LPVOID)Addr,
				MinimumSize,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_EXECUTE_READWRITE);

			if (FreeSpace)
			{
				break;
			}
		}
	}

	return FreeSpace;
}

static
BOOLEAN SetJump(PBYTE Source, PBYTE Destination)
{
	DWORD Protection = PAGE_EXECUTE;
	//
	// Set the protection to something we can use. 
	//
	if (HcVirtualProtect((LPVOID)Source, JMPSIZE, PAGE_EXECUTE_READWRITE, &Protection))
	{
#ifdef _WIN64
		//
		// push rax
		// mov rax [address]
		// xchg qword ptr ss:[rsp], rax
		// ret
		//
		BYTE detour[] = { 0x50, 0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x87, 0x04, 0x24, 0xC3 };
		HcInternalCopy((PBYTE)Source, detour, sizeof(detour));
		*(PBYTE*)(Source + 3) = Destination;
#else
		/* jmp dword ptr [address] */
		*(BYTE*)Source = 0xE9;
		*(PBYTE*)(Source + 1) = GetRelativeDestination(Source, Destination, 5);
#endif

		//
		// Reset the protection //
		//
		if (HcVirtualProtect((LPVOID)Source, JMPSIZE, Protection, &Protection))
		{
			return TRUE;
		}
	}
	return FALSE;
}

static
BOOLEAN SetRelativeJump64(PBYTE Source, PBYTE Destination)
{
	DWORD Protection = PAGE_EXECUTE;

	/* Set the protection to something we can use. */
	if (HcVirtualProtect((LPVOID)Source, 6, PAGE_EXECUTE_READWRITE, &Protection))
	{
		*(WORD*)(Source) = 0x25ff;
		*(PBYTE*)(Source + 2) = GetRelativeDestination(Source, Destination, 6);

		/* Reset the protection */
		if (HcVirtualProtect((LPVOID)Source, 6, Protection, &Protection))
		{
			return TRUE;
		}
	}
	return FALSE;
}

static
VOID
RelocateExistingRelative(PBYTE InstructionAddress,
	PBYTE				Source,
	PBYTE				Destination,
	SIZE_T				Displacement,
	BYTE				Type,
	BYTE				Index)
{
	if (Type == 8)
	{
		*(BYTE*)(InstructionAddress + Index) = (BYTE)((BYTE)Displacement - (Destination - Source));
	}
	else if (Type == 16)
	{
		*(WORD*)(InstructionAddress + Index) = (WORD)((WORD)Displacement - (Destination - Source));
	}
	else if (Type == 32)
	{
		*(DWORD*)(InstructionAddress + Index) = (DWORD)((DWORD)Displacement - (Destination - Source));
	}
}

static 
VOID RelocateConditional(PBYTE lpAddress,
	BYTE						InstSize,
	DWORD						CodeSize, 
	PBYTE						Source,
	PBYTE						Destination,
	const BYTE					Type, 
	const BYTE					Index, 
	PBYTE						Offset)
{
	ULONG_PTR estimatedOffset;
	PBYTE AbsoluteDestination = lpAddress + ((ULONG_PTR)Offset - (Destination - Source)) + InstSize;
	PBYTE FreeSpace = GetClosestFreeSpace(Destination, CodeSize, JMPSIZE, 0x1000);

	if (!FreeSpace)
	{
		return;
	}

	/* This will be accessed by our new conditional if the flags are met. 
		It will lead to the original destination.
	*/
	if (!SetJump(FreeSpace, AbsoluteDestination))
	{
		return;
	}

	/* Calculate the new offset of our conditional, this time to the location of our direct jump. */
	estimatedOffset = (ULONG_PTR) GetRelativeDestination(lpAddress, FreeSpace, InstSize);

	/* Its assumed that the conditional offset is never in a place other than 1 

		Example:
				
		jne 0x2e

		This would jump to the address coming after the jne instruction (jne 0x2e) + the offset of 0x2e.

		so lets say jne 0x2e is located at 0x4000
		we would jump to 0x4000 + 0x2 (size of the instruction) + 0x2e (the offset)
	*/
	if (Type == 8 && estimatedOffset <= 0xff)
	{
		*(BYTE*)(lpAddress + Index) = (BYTE)estimatedOffset;
	}
	else if (Type == 16 && estimatedOffset <= 0xffff)
	{
		*(WORD*)(lpAddress + Index) = (WORD)estimatedOffset;
	}
	else if (Type == 32 && estimatedOffset <= 0xffffffff)
	{
		*(DWORD*)(lpAddress + Index) = (DWORD)estimatedOffset;
	}
	else
	{
		HcFree((LPVOID)FreeSpace);
	}
}

DECL_EXTERN_API(DWORD, HookAssertLength, IN LPCVOID lpBaseAddress, CONST IN DWORD MinimumLength)
{
	_CodeInfo Info;
	_DInst* Instructions = NULL;
	DWORD Size = 0;
	DWORD InstructionIndex = 0;
	DWORD InstructionCount = 0;

	HcInternalSet(&Info, 0, sizeof(Info));

	Info.code = (unsigned char*)lpBaseAddress;
	Info.codeLen = MAX_INSTRUCTIONS * 10;
	Info.codeOffset = 0;
	Info.features = DF_NONE;
	Info.dt = DISASM_TYPE;

	/* Assume that each instruction is 10 bytes at least */
	Instructions = HcAlloc(sizeof(_DecodedInst) * MAX_INSTRUCTIONS);
	if (!Instructions)
	{
		return 0;
	}

	/* Decode the instructions */
	if (distorm_decompose(&Info, Instructions, MAX_INSTRUCTIONS, &InstructionCount) == DECRES_INPUTERR
		|| InstructionCount == 0)
	{
		HcFree(Instructions);
		return 0;
	}

	/* Loop through all the instructions. */
	for (InstructionIndex = 0; InstructionIndex < InstructionCount && Size < MinimumLength; InstructionIndex++)
	{
		Size += Instructions[InstructionIndex].size;
	}

	if (Size < MinimumLength)
	{
		HcFree(Instructions);
		return 0;
	}

	HcFree(Instructions);
	return Size;
}

DECL_EXTERN_API(HStatus, HookRelocateCode, CONST IN PBYTE Code, IN DWORD Size, CONST IN PBYTE Source)
{
	_CodeInfo Info;
	_DInst Instruction;
	_DecodedInst InstructionEx;
	_DInst* Instructions;
	DWORD InstructionIndex;
	DWORD InstructionCount = 0;
	PBYTE InstructionAddress;
	BYTE InstructionDispIndex;
	BYTE InstructionOffsetIndex;
	LPSTR InstructionMnemonic;
	DWORD Protection = PAGE_EXECUTE;

	ZERO(&Info);
	ZERO(&Instruction);
	ZERO(&InstructionEx);

	Info.code = (LPBYTE) Code;
	Info.codeLen = Size * 10;
	Info.features = DF_NONE;
	Info.dt = DISASM_TYPE;

	/* Check if the code the user requested is large enough to hold all the instructions we need. */
	Size = HcHookAssertLength(Code, Size);
	if (!Size)
	{
		return HOOK_INVALID_SIZE;
	}

	/* Assume that each instruction is 10 bytes at least */
	Instructions = HcAlloc(sizeof(_DecodedInst) * (Size * 10));
	if (!Instructions)
	{
		return HOOK_NOT_ENOUGH_SPACE;
	}

	/* Decode the instructions */
	if (distorm_decompose(&Info, Instructions, Size, &InstructionCount) == DECRES_INPUTERR
		|| Size == 0 || InstructionCount == 0)
	{
		HcFree(Instructions);
		return HOOK_FAILED_API;
	}

	if (!HcVirtualProtect((LPVOID) Code, Size, PAGE_EXECUTE_READWRITE, &Protection))
	{
		HcFree(Instructions);
		return HOOK_FAILED_API;
	}

	/* Loop through all the instructions. */
	for (InstructionIndex = 0; InstructionIndex < InstructionCount; InstructionIndex++)
	{
		Instruction = Instructions[InstructionIndex];

		/* Invalid instruction */
		if (Instruction.flags == FLAG_NOT_DECODABLE)
		{
			continue;
		}

		/* Parse the instruction for detailed information */
		distorm_format(&Info, &Instruction, &InstructionEx);

		InstructionMnemonic = InstructionEx.mnemonic.p;

		/* The address of this instruction */
		InstructionAddress = Code + InstructionEx.offset;

		/* Start of the disp (example: [rip + 0xbeef] where the 0xbeef is our disp) 
		-- dispSize is the size of our disp represented in bits, to get the index we take the size of our instruction, and take out the dispSize in bytes from it,
		-- leaving us with the start of the disp.
		*/
		InstructionDispIndex = InstructionEx.size - Instruction.dispSize / 8;

		/* We're going to check for 2 types of necessary relocations.
		-- Relatives rip addresses, and general 32bit relative addresses.
		*/
		for (int j = 0; j < OPERANDS_NO; j++)
		{
			_Operand op = Instruction.ops[j];
			if (op.size == 0)
			{
				/* Next instruction. */
				break;
			}

			/* The logic behind this is that the instruction always starts with the mnemonic, and ends with the offset. */
			InstructionOffsetIndex = Instruction.size - op.size / 8;

			/* O_SMEM: simple memory dereference with optional displacement (a single register memory dereference). */
			if (op.type == O_SMEM || op.type == O_MEM)
			{
				/* Examples: call qword ptr [rip + 0xbeef] */
				if (!(Instruction.flags & FLAG_RIP_RELATIVE))
					continue;

				RelocateExistingRelative(InstructionAddress, 
					Source,
					Code, 
					(SIZE_T)Instruction.disp,
					Instruction.dispSize,
					InstructionDispIndex);
			}
			/* O_PC: the relative address of a branch instruction (instruction.imm.addr). */
			else if (op.type == O_PC)
			{
				/* Is it a conditional jump? */
				if (IsConditionalJump((PBYTE)InstructionAddress, InstructionEx.size))
				{
					/* Does the relative jump go beyond our copied code? */
					if ((DWORD) Instruction.imm.addr > Size)
					{
						RelocateConditional(InstructionAddress,
							InstructionEx.size,
							Size,
							Source,
							Code,
							(BYTE)op.size,
							InstructionOffsetIndex,
							(PBYTE)Instruction.imm.addr);
					}
				}
				else if (HcStringEqualA(InstructionMnemonic, "call", TRUE) || HcStringEqualA(InstructionMnemonic, "jmp", TRUE))
				{
					RelocateExistingRelative(InstructionAddress,
						Source,
						Code,
						(SIZE_T)Instruction.imm.addr,
						(BYTE)op.size,
						InstructionOffsetIndex);
				}
			}
		}
	}

	HcVirtualProtect((LPVOID) Code, Size, Protection, &Protection);
	HcFree(Instructions);
	
	return HOOK_NO_ERR;
}

DECL_EXTERN_API(PVOID, HookCreateCave32, IN LPVOID lpBaseAddress, CONST IN SIZE_T Size)
{
	return HcVirtualAlloc(lpBaseAddress, Size,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);
}

DECL_EXTERN_API(PVOID, HookCreateCave64, IN LPVOID lpBaseAddress, CONST IN SIZE_T Size)
{
	LPVOID lpAddress = NULL;
	MEMORY_BASIC_INFORMATION mbi;
	ZERO(&mbi);

	for (PBYTE Addr = (PBYTE)lpBaseAddress; Addr > (PBYTE)lpBaseAddress - 0xffffffff / 2; Addr = (PBYTE)mbi.BaseAddress - 1)
	{
		if (!HcVirtualQuery((LPCVOID)Addr, &mbi, sizeof(mbi)))
		{
			break;
		}

		if (mbi.State != MEM_FREE)
		{
			continue;
		}

		lpAddress = HcVirtualAlloc(
			mbi.BaseAddress,
			Size,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE);

		if (lpAddress)
		{
			break;
		}
	}

	return lpAddress;
}

#ifndef _WIN64
#define HcHookCreateCave(x, y) HcHookCreateCave32(0, y);
#else
#define HcHookCreateCave(x, y) HcHookCreateCave64(x, y);
#endif

DECL_EXTERN_API(PVOID, HookRecreateCode, CONST IN PBYTE lpBaseAddress, CONST IN DWORD dwMinimumSize)
{
	PVOID Recreated;
	PBYTE Original;
	DWORD SizeOfFunction;
	DWORD dwRequiredSize;

	if (!lpBaseAddress)
	{
		/* Invalid parameter */
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
		return NULL;
	}

	dwRequiredSize = HcHookAssertLength(lpBaseAddress, dwMinimumSize);
	if (!dwRequiredSize)
	{
		/* Invalid function */
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
		return NULL;
	}

	/* Try obtaining the original bytecode. */
	Original = (PBYTE)HcAlloc(dwRequiredSize);
	if (!Original)
	{
		return NULL;
	}

	if (!HcFileReadAddress(lpBaseAddress, Original, dwRequiredSize))
	{
		/* Leave the error to this function */
		HcFree(Original);
		return NULL;
	}

	/* The size of our new function (block) */
	SizeOfFunction = dwRequiredSize + JMPSIZE;

	/* Allocate executable memory for our new function.
		In x86_64 its better to allocate near the original address, for rip relative jumps.
	*/
	Recreated = HcHookCreateCave(lpBaseAddress, SizeOfFunction);
	if (!Recreated)
	{
		/* We failed, the error is set by HcVirtualAlloc. */
		HcFree(Original);
		return NULL;
	}

	/* Copy original block of function to our new function */
	HcInternalCopy(Recreated, Original, dwRequiredSize);

	/* Relocate the block we found. */
	if (HcHookRelocateCode(Recreated, dwRequiredSize, lpBaseAddress) != HOOK_NO_ERR)
	{
		HcFree(Original);
		return FALSE;
	}

	/* Free originally stored function bytes */
	HcFree(Original);

	/* Write the jump. */
	if (!SetJump((PBYTE)Recreated + dwRequiredSize, (PBYTE)lpBaseAddress + dwRequiredSize))
	{
		return NULL;
	}
	return Recreated;
}

DECL_EXTERN_API(HStatus, HookDetour, CONST IN PDetourContext Context)
{
	DWORD ContinuedJumpSize;
	DWORD DetourMethodSize;
	HStatus Status = HOOK_NO_ERR;

	if (!Context->lpSource)
	{
		return HOOK_INVALID_SOURCE;
	}

	if (!Context->lpDestination)
	{
		return HOOK_INVALID_DESTINATION;
	}

	if (Context->Flags == 0)
	{
		Context->Flags = Default;
	}

	if (Context->Flags & Reconstruct)
	{
		PBYTE originalData = (PBYTE)HcHookRecreateCode(Context->lpSource, 16);

#ifndef _WIN64
		DWORD instructionSize = HcHookAssertLength(originalData, 5);
#else
		DWORD instructionSize = HcHookAssertLength(originalData, 16);
#endif
		if (!instructionSize)
		{
			return HOOK_INVALID_SOURCE;
		}

		if (instructionSize)
		{
			HcProcessWriteMemory(NtCurrentProcess(),
				Context->lpSource,
				originalData,
				instructionSize,
				NULL);

			HcHookRelocateCode(Context->lpSource, instructionSize, Context->lpSource);
		}
	}
	
#ifndef _WIN64

	DetourMethodSize = 5;
	ContinuedJumpSize = 5;

	Context->dwLength = HcHookAssertLength(Context->lpSource, 5);
	Context->Type = Relative;

#else

	ContinuedJumpSize = 16;
	Context->dwLength = HcHookAssertLength(Context->lpSource, 16);

	/* Check if the code area is not large enough to contain an absolute 16 byte jump. */
	if (!Context->dwLength)
	{
		/* Try a relative jump instead. */
		Context->dwLength = HcHookAssertLength(Context->lpSource, 6);
		if (Context->dwLength)
		{
			DetourMethodSize = 6;
			Context->Type = Relative;
		}
	}
	else
	{
		/* The code was large enough. */
		DetourMethodSize = 16;
		Context->Type = Absolute;
	}

#endif

	if (!Context->dwLength)
	{
		/* Invalid size. */
		return HOOK_NOT_ENOUGH_SPACE;
	}

	/* Recreate the original, and a jump back to the continued code. */
	if (Context->Flags & Recreate)
	{
		Context->pbReconstructed = (PBYTE)HcHookCreateCave(Context->lpSource, Context->dwLength + ContinuedJumpSize);
		if (!Context->pbReconstructed)
		{
			/* We failed creating the cave. */
			return HOOK_CAVE_FAILURE;
		}

		/* This is the chunk we took off from the source, 
			we have to relocate it somewhere in case the caller wants to call this function. */

		/* Move the raw chunk. */
		HcInternalCopy(Context->pbReconstructed, Context->lpSource, Context->dwLength);
	}

	/* Check if user wanted a copy. */
	if (Context->Flags & SaveOriginal)
	{
		HcInternalCopy(Context->pbOriginal, Context->lpSource, Context->dwLength);
	}

	if (Context->Flags & Recreate)
	{
		/* Fix relocs in the chunk. */
		if ((Status = HcHookRelocateCode(Context->pbReconstructed, Context->dwLength, Context->lpSource)) != HOOK_NO_ERR)
		{
			return Status;
		}

		if (Context->Flags & JumpOriginal)
		{
			/* Set the jump back to the continued code. */
			if (!SetJump((Context->pbReconstructed + Context->dwLength), (PBYTE)Context->lpSource + Context->dwLength))
			{
				return HOOK_PROTECTION_FAILURE;
			}
		}
	}

#ifdef _WIN64
	if (Context->Type == Relative)
	{
		/* Set a rip relative 6 byte jump. */
		if (!SetRelativeJump64((PBYTE)Context->lpSource, (PBYTE)Context->lpDestination))
		{
			return HOOK_PROTECTION_FAILURE;
		}
	}
	else
#endif
	{
		if (!SetJump((PBYTE)Context->lpSource, (PBYTE)Context->lpDestination))
		{
			return HOOK_PROTECTION_FAILURE;
		}

		
		DWORD Protection;
		if (HcVirtualProtect(Context->lpSource, Context->dwLength, PAGE_EXECUTE_READWRITE, &Protection))
		{
			for (DWORD i = DetourMethodSize; i < Context->dwLength; i++)
			{
				((PBYTE)(Context->lpSource))[i] = OPCODE_INSTRUCTION_NOP;
			}

			HcVirtualProtect(Context->lpSource, Context->dwLength, Protection, &Protection);
		}
	}

	/* Update the instruction cache. */
	HcProcessFlushInstructionCache(NtCurrentProcess(), Context->lpSource, Context->dwLength);

	return HOOK_NO_ERR;
}

DECL_EXTERN_API(HStatus, HookDetourContextRestore, CONST IN PDetourContext Context)
{
	DWORD dwProtection = PAGE_EXECUTE;
	SIZE_T NumberofBytesToProtect;
	PVOID Base = NULL;

	if (!Context->lpSource)
	{
		return HOOK_INVALID_SOURCE;
	}

	if (!Context->lpDestination)
	{
		return HOOK_INVALID_SOURCE;
	}

	if (!Context->dwLength)
	{
		return HOOK_INVALID_SIZE;
	}

	if (!Context->pbOriginal)
	{
		return HOOK_INVALID_RESTORATION;
	}

	Base = Context->lpSource;
	NumberofBytesToProtect = (SIZE_T)Context->dwLength;

	/* Give us access to the page. */
	if (!HcVirtualProtect(Context->lpSource, (SIZE_T)Context->dwLength, PAGE_EXECUTE_READWRITE, &dwProtection))
	{
		return HOOK_FAILED_API;
	}

	/* Do the restore. */
	HcInternalCopy(Context->lpSource, Context->pbOriginal, Context->dwLength);

	/* Restore access to the page. */
	HcVirtualProtect(Context->lpSource,
		(SIZE_T)Context->dwLength,
		dwProtection,
		&dwProtection);

	return HOOK_NO_ERR;
}

#define THREAD_COUNT 200

#ifndef _WIN64
#define XIP Eip
#else
#define XIP Rip
#endif

typedef struct _HWBPHook {
	LPVOID Class;
	LPVOID Callback;
	DWORD Index;
	DWORD Threads[THREAD_COUNT];
} HWBPHOOK;

HWBPHOOK* HWBPHooks = NULL;
LPVOID ExceptionHandler = NULL;

inline int HookHWBPGetFreeIndex(DWORD regval)
{
	if (!(regval & 1))
		return 0;
	else if (!(regval & 4))
		return 1;
	else if (!(regval & 16))
		return 2;

	return -1;
}

HWBPHOOK* HookHWBPGetFreeHook()
{
	if (HWBPHooks == NULL)
	{
		HWBPHooks = (HWBPHOOK*) HcAlloc(sizeof(HWBPHOOK) * 4);
		return &HWBPHooks[0];
	}
	else
	{
		for (DWORD i = 0; i < 4; i++)
		{
			if (HWBPHooks[i].Callback == NULL)
			{
				return &HWBPHooks[i];
			}
		}
	}

	return NULL;
}

HWBPHOOK* HookHWBPGetHook(DWORD threadId)
{
	for (DWORD i = 0; i < 4; i++)
	{
		for (DWORD y = 0; y < THREAD_COUNT; y++)
		{
			if (HWBPHooks[i].Threads[y] == threadId)
			{
				return &HWBPHooks[i];
			}
		}
	}

	return NULL;
}

HWBPHOOK* HookHWBPGetHookByDestination(LPVOID lpDestination)
{
	for (DWORD i = 0; i < 4; i++)
	{
		if (HWBPHooks[i].Callback == lpDestination)
		{
			return &HWBPHooks[i];
		}
	}

	return NULL;
}

void HookHWBPFreeHook(HWBPHOOK* hook)
{
	hook->Class = NULL;
	hook->Callback = NULL;
	hook->Index = 0;

	HcInternalSet(hook->Threads, 0, sizeof(hook->Threads));
}
LONG CALLBACK HWBPHookHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	// check, that it was our debug exception
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		ExceptionInfo->ContextRecord->Dr6 = 0;

		HWBPHOOK* hwbp = HookHWBPGetHook(HcThreadCurrentId());
		if (hwbp == NULL)
		{
			// we're fucked or
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		ExceptionInfo->ContextRecord->Dr6 = 0;							// clear info
		ExceptionInfo->ContextRecord->Dr3 = (ULONG_PTR) hwbp->Class;	// dr3 holds hook class pointer
		ExceptionInfo->ContextRecord->XIP = (ULONG_PTR) hwbp->Callback; // execute the hook

		// continue execution of thread  
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	// unknown exception, search next handler
	return EXCEPTION_CONTINUE_SEARCH;
}

DECL_EXTERN_API(BOOLEAN, HookHWBPToggle, CONST IN PDetourContext Context, BOOL State)
{
	if (Context == NULL)
	{
		return FALSE;
	}

	HWBPHOOK* HookEntry = HookHWBPGetHookByDestination(Context->lpDestination);
	if (HookEntry == NULL)
	{
		return FALSE;
	}
	
	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (HcThreadGetContext(NtCurrentThread(), &context) != TRUE)
		return FALSE;

	if (State)
	{
		BitTestAndSetT((LONG_PTR*) &context.Dr7, 2 * HookEntry->Index);
	}
	else
	{
		BitTestAndResetT((LONG_PTR*) &context.Dr7, 2 * HookEntry->Index);
	}

	return HcThreadSetContext(NtCurrentThread(), &context);
}

DECL_EXTERN_API(HStatus, HookHWBPRestore, CONST IN PDetourContext Context)
{
	HStatus Status = HOOK_NO_ERR;
	DWORD Threads[THREAD_COUNT];
	DWORD dwThreadCount = THREAD_COUNT;

	if (!Context->lpSource)
	{
		return HOOK_INVALID_SOURCE;
	}

	if (!Context->lpDestination)
	{
		return HOOK_INVALID_DESTINATION;
	}

	if (Context->Flags == 0)
	{
		Context->Flags = Default;
	}

	if (!HcThreadGetAllThreadIds(HcProcessGetCurrentId(), Threads, &dwThreadCount))
	{
		return HOOK_INVALID_SOURCE;
	}

	HWBPHOOK* HookEntry = HookHWBPGetHookByDestination(Context->lpDestination);
	if (HookEntry == NULL)
	{
		return HOOK_INVALID_SIZE;
	}

	for (DWORD i = 0; i < dwThreadCount; i++)
	{
		DWORD threadId = Threads[i];
		HANDLE hThread = (threadId != HcThreadCurrentId()) ?
			HcThreadOpen(threadId, THREAD_ALL_ACCESS) :
			NtCurrentThread();

		if (hThread != NULL)
		{
			CONTEXT debugContext;
			HcInternalSet(&debugContext, 0, sizeof(debugContext));

			debugContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;

			if (!HcThreadGetContext(hThread, &debugContext))
			{
				HcObjectClose(&hThread);
				Status = HcErrorGetLastStatus();
				break;
			}

			// Remove BP presence flag
			_bittestandreset((long*) &debugContext.Dr7, 2 * HookEntry->Index);

			// Reset hook address
			*((DWORD*) &debugContext.Dr0 + HookEntry->Index) = 0;

			if (!HcThreadSetContext(hThread, &debugContext))
			{
				HcObjectClose(&hThread);
				Status = HcErrorGetLastStatus();
				break;
			}

			HcObjectClose(&hThread);
		}
	}

	HookHWBPFreeHook(HookEntry);
	return Status;
}

DECL_EXTERN_API(HStatus, HookHWBPRedirect, CONST IN PDetourContext Context)
{
	HStatus Status = HOOK_NO_ERR;
	DWORD Threads[THREAD_COUNT];
	DWORD dwThreadCount = THREAD_COUNT;

	if (!Context->lpSource)
	{
		return HOOK_INVALID_SOURCE;
	}

	if (!Context->lpDestination)
	{
		return HOOK_INVALID_DESTINATION;
	}

	if (Context->Flags == 0)
	{
		Context->Flags = Default;
	}

	if (!HcThreadGetAllThreadIds(HcProcessGetCurrentId(), Threads, &dwThreadCount))
	{
		return HOOK_INVALID_SOURCE;
	}

	HWBPHOOK* HookEntry = HookHWBPGetFreeHook();
	if (HookEntry == NULL)
	{
		return HOOK_INVALID_SIZE;
	}

	if ((Context->Flags & THISCALL) > 0 && Context->lpClass == NULL)
	{
		return HOOK_INVALID_CLASS;
	}

	HookEntry->Callback = Context->lpDestination;
	HookEntry->Class = Context->lpClass;

	for (DWORD i = 0; i < dwThreadCount; i++)
	{
		DWORD threadId = Threads[i];
		HANDLE hThread = (threadId != HcThreadCurrentId()) ?
			HcThreadOpen(threadId, THREAD_ALL_ACCESS) :
			NtCurrentThread();

		if (hThread != NULL)
		{
			CONTEXT debugContext;
			HcInternalSet(&debugContext, 0, sizeof(debugContext));

			debugContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;

			if (!HcThreadGetContext(hThread, &debugContext))
			{
				HcObjectClose(&hThread);
				Status = HcErrorGetLastStatus();
				goto done;
			}

			DWORD Index = HookHWBPGetFreeIndex(debugContext.Dr7);
			if (Index < 0)
			{
				HcObjectClose(&hThread);
				Status = STATUS_INSUFFICIENT_RESOURCES;
				goto done;
			}

			debugContext.Dr7 |= 1 << (2 * Index) | 0x100;	// enable corresponding HWBP and local BP flag
			debugContext.Dr7 &= ~0x80000;					// disable ICE (just to be sure...)

			switch (Index)
			{
			case 0:
				debugContext.Dr0 = (DWORD_PTR) Context->lpSource;
				break;
			case 1:
				debugContext.Dr1 = (DWORD_PTR) Context->lpSource;
				break;
			case 2:
				debugContext.Dr2 = (DWORD_PTR) Context->lpSource;
				break;
			case 3:
				debugContext.Dr3 = (DWORD_PTR) Context->lpSource;
				break;
			}

			HookEntry->Threads[i] = threadId;

			if (!HcThreadSetContext(hThread, &debugContext))
			{
				HcObjectClose(&hThread);
				Status = HcErrorGetLastStatus();
				goto done;
			}

			if (ExceptionHandler == NULL)
				ExceptionHandler = AddVectoredExceptionHandler(1, HWBPHookHandler);

			HcObjectClose(&hThread);
		}
	}

done:
	if (Status != HOOK_NO_ERR)
	{
		HookHWBPFreeHook(HookEntry);
	}

	Context->pbReconstructed = Context->lpSource;
	return Status;
}