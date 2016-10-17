/*
	@File: hchook.c
	@Purpose: Userspace function detouring, detour reconstruction, detour assembly code relocation. 
		As of @version 9/11/2016 it provides a stable "midfunction" detour with relocation fixes, allowing much more stable and secure interceptions.

	@Author: Synestraa
	@version 9/11/2016
*/

#include <windows.h>

#include "../sys/hcsyscall.h"

#include "../headers/hchook.h"
#include "../headers/hcfile.h"
#include "../headers/hcvirtual.h"
#include "../headers/hcstring.h"
#include "../headers/hcerror.h"

#include "../../../distorm/include/distorm.h"

#define MAX_INSTRUCTIONS 0x100

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
		return FALSE;

	if (InstructionBytes[0] == 0x0F)
	{
		if (InstructionBytes[1] >= 0x80 && InstructionBytes[1] <= 0x8F)
			return TRUE;
	}

	if (InstructionBytes[0] >= 0x70 && InstructionBytes[0] <= 0x7F)
		return TRUE;

	if (InstructionBytes[0] == 0xE3)
		return TRUE;

	return FALSE;
}

static
SIZE_T CalculateRelative(SIZE_T Source, SIZE_T Destination, SIZE_T Size)
{
	return (Source < Destination) ? 0 - (Source - Destination) - Size : Destination - (Source + Size);
}

static
SIZE_T FindFreeSpace(LPVOID lpAddress, SIZE_T Size, SIZE_T MinimumSize, SIZE_T MaxLength)
{
	SIZE_T FreeSpace = 0;
	MEMORY_BASIC_INFORMATION mbi;
	for (SIZE_T Addr = (SIZE_T)lpAddress + Size; Addr < (SIZE_T)lpAddress + MaxLength + Size; Addr = Addr++)
	{
		__try
		{
			DWORD Length;
			for (Length = 0; Length < MinimumSize; Length++)
			{
				if ((*(BYTE*)(Length + Addr)) != 0)
				{
					break;
				}
			}

			if (Length == MinimumSize)
			{
				FreeSpace = Length + Addr;
				break;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			/* Check the block */
			if (!HcVirtualQuery((LPCVOID)Addr, &mbi, sizeof(mbi)))
			{
				break;
			}

			if (mbi.State == MEM_FREE)
			{
				/* Try and allocate on this spot. */
				if ((FreeSpace = (SIZE_T)HcVirtualAlloc((LPVOID)Addr,
					MinimumSize,
					MEM_RESERVE | MEM_COMMIT,
					PAGE_EXECUTE_READWRITE)))
				{
					break;
				}
			}
		}
	}

	return FreeSpace;
}

static
BOOLEAN SetJump(SIZE_T Source, SIZE_T Destination)
{
	DWORD Protection;
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
		*(SIZE_T*)&((PBYTE)Source)[3] = Destination;
#else
		/* jmp dword ptr [address] */
		*(BYTE*)Source = 0xE9;
		*(DWORD*)(Source + 1) = CalculateRelative(Source, Destination, 5);
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
BOOLEAN SetRelativeJump64(SIZE_T Source, SIZE_T Destination)
{
	DWORD Protection;

	/* Set the protection to something we can use. */
	if (HcVirtualProtect((LPVOID)Source, 6, PAGE_EXECUTE_READWRITE, &Protection))
	{
		*(WORD*)(Source) = 0x25ff;
		*(DWORD*)(Source + 2) = (DWORD)CalculateRelative((SIZE_T)Source, (SIZE_T)Destination, 6);

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
RelocateExistingRelative(SIZE_T InstructionAddress,
	SIZE_T				Source,
	SIZE_T				Destination,
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
VOID RelocateConditional(SIZE_T lpAddress, 
	BYTE						InstSize,
	DWORD						CodeSize, 
	SIZE_T						Source, 
	SIZE_T						Destination, 
	const BYTE					Type, 
	const BYTE					Index, 
	SIZE_T						Offset)
{
	SIZE_T AbsoluteDestination = lpAddress + (Offset - (Destination - Source)) + InstSize;
	SIZE_T FreeSpace;

	FreeSpace = FindFreeSpace((LPVOID)Destination, CodeSize, JMPSIZE, 0x1000);
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
	Offset = CalculateRelative(lpAddress, (SIZE_T)FreeSpace, InstSize);

	/* Its assumed that the conditional offset is never in a place other than 1 

		Example:
				
		jne 0x2e

		This would jump to the address coming after the jne instruction (jne 0x2e) + the offset of 0x2e.

		so lets say jne 0x2e is located at 0x4000
		we would jump to 0x4000 + 0x2 (size of the instruction) + 0x2e (the offset)
	*/

	if (Type == 8 && Offset <= UCHAR_MAX)
	{
		*(BYTE*)(lpAddress + Index) = (BYTE)Offset;
	}
	else if (Type == 16 && Offset <= USHRT_MAX) 
	{
		*(WORD*)(lpAddress + Index) = (WORD)Offset;
	}
	else if (Type == 32 && Offset <= UINT_MAX) 
	{
		*(DWORD*)(lpAddress + Index) = (DWORD)Offset;
	}
	else
	{
		HcFree((LPVOID)FreeSpace);
	}
}

/*
	CODER: Synestra

	PURPOSE: Determine whether parameter MinimumLength is large enough to cover an instruction

	PARAMETERS: lpBaseAddress start address
	MinimumLength: the length to test

	RETURN: Determined size for given minimum length

	HISTORY: 8/29/2016 Created
*/

DWORD
HCAPI 
HcHookAssertLength(LPVOID lpBaseAddress, DWORD MinimumLength)
{
	_CodeInfo Info;
	_DInst* Instructions;
	DWORD Size;
	DWORD InstructionIndex;
	DWORD InstructionCount;

	Info.code = (unsigned char*)lpBaseAddress;
	Info.codeLen = MAX_INSTRUCTIONS * 10;
	Info.codeOffset = 0;
	Info.features = DF_NONE;
	Info.dt = DISASM_TYPE;

	Size = 0;

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
		return 0;
	}

	HcFree(Instructions);
	return Size;
}

/*
	CODER: Synestra

	PURPOSE: Relocates destinations of calls and jumps to their respective module addresses

	PARAMETERS: Buffer, start of the instructions
				Size, length of the relocation
				Source, the original module that contained the code

	RETURN: 

	HISTORY: 8/29/2016 Created
*/

HStatus 
HCAPI 
HcHookRelocateCode(PBYTE Code,
	DWORD Size, 
	SIZE_T Source)
{
	_CodeInfo Info;
	_DInst Instruction;
	_DecodedInst InstructionEx;

	_DInst* Instructions;

	DWORD InstructionIndex;
	DWORD InstructionCount;
	SIZE_T InstructionAddress;
	BYTE InstructionDispIndex;
	BYTE InstructionOffsetIndex;
	LPSTR InstructionMnemonic;

	HcInternalSet(&Info, 0, sizeof(Info));
	HcInternalSet(&Instruction, 0, sizeof(Instruction));
	HcInternalSet(&InstructionEx, 0, sizeof(InstructionEx));

	Info.code = (unsigned char*) Code;
	Info.codeLen = (Size * 10);
	Info.codeOffset = 0;
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

	/* Loop through all the instructions. */
	for (InstructionIndex = 0; InstructionIndex < InstructionCount; InstructionIndex++)
	{
		Instruction = Instructions[InstructionIndex];

		/* Invalid instruction */
		if (Instruction.flags == FLAG_NOT_DECODABLE)
		{
			continue;
		}

		InstructionMnemonic = InstructionEx.mnemonic.p;

		/* Parse the instruction for detailed information */
		distorm_format(&Info, &Instruction, &InstructionEx);

		/* The address of this instruction */
		InstructionAddress = (SIZE_T)Code + (SIZE_T)InstructionEx.offset;

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
					(SIZE_T)Code, 
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
					if ((SIZE_T)Instruction.imm.addr > Size)
					{
						RelocateConditional(InstructionAddress,
							InstructionEx.size,
							Size,
							Source,
							(SIZE_T)Code,
							(BYTE)op.size,
							InstructionOffsetIndex,
							(SIZE_T)Instruction.imm.addr);
					}
				}
				else if (HcStringEqualA(InstructionMnemonic, "call", TRUE) || HcStringEqualA(InstructionMnemonic, "jmp", TRUE))
				{
					RelocateExistingRelative(InstructionAddress,
						Source,
						(SIZE_T)Code,
						(SIZE_T)Instruction.imm.addr,
						(BYTE)op.size,
						InstructionOffsetIndex);
				}
			}
		}
	}

	HcFree(Instructions);
	return HOOK_NO_ERR;
}

PVOID
HCAPI
HcHookCreateCave32(LPVOID lpBaseAddress, SIZE_T Size)
{
	return HcVirtualAlloc(lpBaseAddress, Size,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);
}

PVOID
HCAPI
HcHookCreateCave64(LPVOID lpBaseAddress, SIZE_T Size)
{
	LPVOID lpAddress = 0;
	MEMORY_BASIC_INFORMATION mbi;

	for (SIZE_T Addr = (SIZE_T)lpBaseAddress; Addr > (SIZE_T)lpBaseAddress - INT_MAX; Addr = (SIZE_T)mbi.BaseAddress - 1)
	{
		/* Check the block */
		if (!HcVirtualQuery((LPCVOID)Addr, &mbi, sizeof(mbi)))
		{
			break;
		}

		/* Ask her out on a date. */
		if (mbi.State != MEM_FREE)
		{
			/* She told us she has a boyfriend, tell her to fuck off. */
			continue;
		}

		/* Try and allocate on this spot. */
		if ((lpAddress = HcVirtualAlloc(mbi.BaseAddress,
			Size,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE)))
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

/*
	CODER: Synestra

	PURPOSE: Restore a function in a new codecave, regardless of previous type of hook.

	PARAMETERS: lpBaseAddress, start point of our restoration
				dwMinimumSize, minimum amount of bytes that should be taken over from the function.

	RETURN: address to the restored function, any restored functions should proceed to call this restored address instead of the original.

	HISTORY: unknown date created
			 documented
*/
PVOID
HCAPI
HcHookRecreateCode(PBYTE lpBaseAddress, DWORD dwMinimumSize)
{
	PVOID Recreated;
	PBYTE Original;
	DWORD SizeOfFunction;
	DWORD dwRequiredSize;

	if (!lpBaseAddress)
	{
		/* Invalid parameter */
		HcErrorSetDosError(ERROR_INVALID_PARAMETER);
		return NULL;
	}

	dwRequiredSize = HcHookAssertLength(lpBaseAddress, dwMinimumSize);
	if (!dwRequiredSize)
	{
		/* Invalid function */
		HcErrorSetDosError(ERROR_INVALID_PARAMETER);
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
	HcInternalCopy(Recreated, Original, SizeOfFunction);

	/* Relocate the block we found. */
	if (HcHookRelocateCode(Recreated, SizeOfFunction, (SIZE_T)lpBaseAddress) != HOOK_NO_ERR)
	{
		HcFree(Original);
		return FALSE;
	}

	/* Free originally stored function bytes */
	HcFree(Original);

	/* Write the jump. */
	if (!SetJump((SIZE_T)Recreated + dwRequiredSize, (SIZE_T)lpBaseAddress + dwRequiredSize))
	{
		return NULL;
	}
	return Recreated;
}

HStatus
HCAPI
HcHookDetour(PDetourContext Context)
{
	DWORD ContinuedJumpSize;
	DWORD DetourMethodSize;
	HStatus Status;

	if (!Context->lpSource)
	{
		return HOOK_INVALID_SOURCE;
	}

	if (!Context->lpDestination)
	{
		return HOOK_INVALID_SOURCE;
	}

	Status = HOOK_NO_ERR;
	
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

	/* Check if user wanted a copy. */
	if (HcInternalValidate(Context->pbOriginal))
	{
		/* Save a copy of the original. */
		HcInternalCopy(Context->pbOriginal, Context->lpSource, Context->dwLength);
	}

	/* Fix relocs in the chunk. */
	if ((Status = HcHookRelocateCode(Context->pbReconstructed, Context->dwLength, (SIZE_T)Context->lpSource)) != HOOK_NO_ERR)
	{
		return Status;
	}
	
	/* Set the jump back to the continued code. */
	if (!SetJump((SIZE_T)(Context->pbReconstructed + Context->dwLength), (SIZE_T)Context->lpSource + Context->dwLength))
	{
		return HOOK_PROTECTION_FAILURE;
	}

#ifdef _WIN64
	if (Context->Type == Relative)
	{
		/* Set a rip relative 6 byte jump. */
		if (!SetRelativeJump64((SIZE_T)Context->lpSource, (SIZE_T)Context->lpDestination))
		{
			return HOOK_PROTECTION_FAILURE;
		}
	}
	else
#endif
	{
		/* Absolute 32/64 jump. */
		if (!SetJump((SIZE_T)Context->lpSource, (SIZE_T)Context->lpDestination))
		{
			return HOOK_PROTECTION_FAILURE;
		}
	}

	/* Update the instruction cache. */
	HcFlushInstructionCache(NtCurrentProcess, Context->lpSource, Context->dwLength);

	return HOOK_NO_ERR;
}

HStatus
HCAPI
HcHookDetourContextRestore(PDetourContext Context)
{
	DWORD dwProtection;
	SIZE_T NumberofBytesToProtect;
	PVOID Base;

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