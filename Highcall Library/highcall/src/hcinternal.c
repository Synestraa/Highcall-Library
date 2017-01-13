/*++

Module Name:

hcinternal.c

Abstract:

This module implements internal memory handling functions. i.e. memcpy, memmove, memset... as well as other functions used in gamehacking.

Author:

Synestra 9/11/2016

Revision History:

Synestra 10/15/2016

--*/

#include "../headers/hcinternal.h"

//
// For HcStringSecureLength
//
#include "../headers/hcstring.h"

//
// For HcVirtualQuery, HcVirtualProtect
//
#include "../headers/hcvirtual.h"

//
// Used disassembler engine: https://github.com/gdabah/distorm
//
#include "../../../distorm/include/distorm.h"

HC_EXTERN_API 
BOOLEAN
HCAPI 
HcInternalCompare(PBYTE pbFirst, PBYTE pbSecond, SIZE_T tLength)
{
	for (; tLength--; pbFirst++, pbSecond++)
	{
		if ((*(BYTE*)pbFirst) != (*(BYTE*)pbSecond))
		{
			return FALSE;
		}
	}
	return TRUE;
}

HC_EXTERN_API 
PVOID
HCAPI 
HcInternalCopy(PVOID pDst, PVOID pSrc, SIZE_T tCount)
{
	PVOID ret = pDst;

	//
	// copy from lower addresses to higher addresses
	//
	while (tCount--)
		*((PBYTE)pDst)++ = *((PBYTE)pSrc)++;
	
	return (ret);
}

HC_EXTERN_API
PVOID 
HCAPI 
HcInternalMove(PVOID pDst, PVOID pSrc, SIZE_T tCount)
{
	PVOID ret = pDst;

	if (pDst <= pSrc || (PBYTE)pDst >= ((PBYTE)pSrc + tCount)) 
	{
		//
		// Non-Overlapping Buffers
		// copy from lower addresses to higher addresses
		//
		while (tCount--)
			*((PBYTE)pDst)++ = *((PBYTE)pSrc)++;
	
	}
	else 
	{
		//
		// Overlapping Buffers
		// copy from higher addresses to lower addresses
		//
		(PBYTE)pDst += tCount - 1;
		(PBYTE)pSrc += tCount - 1;
	
		while (tCount--)
			*((PBYTE)pDst)-- = *((PBYTE)pSrc)--;
	}

	return(ret);
}

HC_EXTERN_API
PVOID
HCAPI 
HcInternalSet(PVOID pDst, BYTE bVal, SIZE_T tCount)
{
	PVOID start = pDst;

	while (tCount--)
		*((PBYTE)pDst)++ = bVal;

	return (start);
}

//
// Fixme, crahes sometimes.
//
HC_EXTERN_API
BOOLEAN
HCAPI
HcInternalValidate(LPCVOID lpcAddress)
{
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	SIZE_T ReturnedSize = 0;

	if (!lpcAddress)
		return FALSE;

	ReturnedSize = HcVirtualQuery(lpcAddress, &mbi, sizeof(mbi));

	return !(!ReturnedSize || (mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD));
}

HC_EXTERN_API
LPVOID
HCAPI
HcInternalLocatePointer(LPCVOID lpcAddress, PSIZE_T ptOffsets, SIZE_T tCount)
{
	LPVOID CurrentAddress = NULL;
	SIZE_T Index = 0;

	if (!HcInternalValidate(lpcAddress))
		return NULL;

	CurrentAddress = *(LPVOID*)lpcAddress;
	if (!HcInternalValidate(CurrentAddress))
	{
		return NULL;
	}

	for (Index = 0; Index < tCount - 1; Index++)
	{
		if (!HcInternalValidate((LPVOID)((SIZE_T)CurrentAddress + ptOffsets[Index])))
			return NULL;

		CurrentAddress = *(LPVOID*)((SIZE_T)CurrentAddress + ptOffsets[Index]);
	}

	return HcInternalValidate(CurrentAddress) ? (LPVOID)((SIZE_T)CurrentAddress + ptOffsets[tCount - 1]) : NULL;
}

HC_EXTERN_API
INT
HCAPI
HcInternalReadIntEx32(LPCVOID lpcAddress, PSIZE_T ptOffsets, SIZE_T tCount)
{
	LPVOID lpPtr = HcInternalLocatePointer(lpcAddress, ptOffsets, tCount);
	return HcInternalValidate(lpPtr) ? *(DWORD*)lpPtr : 0;
}

HC_EXTERN_API
INT64
HCAPI
HcInternalReadIntEx64(LPCVOID lpcAddress, PSIZE_T ptOffsets, SIZE_T tCount)
{
	LPVOID lpPtr = HcInternalLocatePointer(lpcAddress, ptOffsets, tCount);
	return HcInternalValidate(lpPtr) ? *(DWORD64*)lpPtr : 0;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcInternalMemoryWrite(LPVOID lpAddress, SIZE_T tLength, PBYTE pbNew)
{
	DWORD dwProtection = 0;

	//
	// Change the protection to something we can write to.
	//
	if (HcVirtualProtect(lpAddress, tLength, PAGE_EXECUTE_READWRITE, &dwProtection))
	{
		HcInternalCopy(lpAddress, pbNew, tLength);

		// 
		// Restore the old protection.
		//
		if (HcVirtualProtect(lpAddress, tLength, dwProtection, &dwProtection))
		{
			return TRUE;
		}
	}

	return FALSE;
}

HC_EXTERN_API
BOOLEAN
HCAPI
HcInternalMemoryNopInstruction(PVOID pAddress)
{
	DWORD dwProtection = 0;

	_CodeInfo ci = { 0 };
	_DInst di = { 0 };
	_DecodedInst inst = { 0 };

	ci.code = (unsigned char*)pAddress;
	ci.codeLen = 0x100;
	ci.codeOffset = 0;
	ci.features = DF_NONE;
	ci.dt = DISASM_TYPE;

	HcInternalSet(&di, 0, sizeof(di));
	HcInternalSet(&inst, 0, sizeof(inst));

	//
	// Attempt to disassemble the block.
	//
	if (distorm_decompose(&ci, &di, 1, NULL) != DECRES_INPUTERR)
	{
		//
		// Set writable protection to the instruction.
		//
		if (HcVirtualProtect(pAddress, inst.size, PAGE_EXECUTE_READWRITE, &dwProtection))
		{
			//
			// Nop the instruction. 0x90 opcode == intel NOP instruction.
			//
			HcInternalSet(pAddress, 0x90, inst.size);

			//
			// Restore it and report success. 
			//
			if (HcVirtualProtect(pAddress, inst.size, dwProtection, &dwProtection))
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}

HC_EXTERN_API
SIZE_T
HCAPI
HcInternalPatternFind(LPCSTR szcPattern, LPCSTR szcMask, PHC_MODULE_INFORMATIONW pmInfo)
{
	SIZE_T CurrentAddress = 0;
	SIZE_T ProbeAddress = 0;
	SIZE_T MaskSize = 0; 

	MaskSize = HcStringSecureLengthA(szcMask);
	if (!MaskSize || !HcStringSecureLengthA(szcPattern))
		return 0;

	/* Loop through the entire module .text/code area. */
	for (CurrentAddress = (SIZE_T)pmInfo->Base; CurrentAddress < (SIZE_T)pmInfo->Base + pmInfo->Size - MaskSize; CurrentAddress++)
	{
		/* Check for an initial match to start our larger pattern. */
		if (*(BYTE*)CurrentAddress == (szcPattern[0] & 0xff) || szcMask[0] == '?')
		{
			ProbeAddress = CurrentAddress;

			/* Loop through the address that contained our first byte. */
			for (int i = 0; szcMask[i] != '\0'; i++, ProbeAddress++)
			{
				/* This is not our pattern. */
				if ((szcPattern[i] & 0xff) != *(BYTE*)ProbeAddress && szcMask[i] != '?')
					break;

				/* This is a match. */
				if (((szcPattern[i] & 0xff) == *(BYTE*)ProbeAddress || szcMask[i] == '?') && szcMask[i + 1] == '\0')
					return CurrentAddress;
			}
		}
	}

	/* We found nothing. */
	return 0;
}
