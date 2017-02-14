#include "hcsyscall.h"

#include "../../public/hcmodule.h"
#include "../../public/hcfile.h"
#include "../../public/hcglobal.h"

BOOLEAN
HCAPI
HcIsSyscallExport(LPVOID lpAddress)
{
	__try
	{
#ifdef _WIN64
		return *(BYTE*)(lpAddress) == 0x4c && *(BYTE*)((SIZE_T)lpAddress + 3) == 0xb8;
#else
		return *(BYTE*)lpAddress == 0xb8;
#endif
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}
}

static
SYS_INDEX
ExtractSyscallIndex(LPBYTE lpByte)
{
#ifndef _WIN64
	/* mov eax, syscallindex */
	/* buffer + 1 is the syscall index, 0xB8 is the mov instruction */
	return *(ULONG*)(lpByte + 1);
#else
	/* mov r10, rcx */
	/* mov eax, syscall index */
	return *(ULONG*)(lpByte + 4);
#endif
}

SYS_INDEX
HCAPI
HcSyscallIndexA(LPCSTR lpName)
{
	BYTE buffer[10];
	if (!HcFileReadModuleA(HcGlobal.HandleNtdll, lpName, buffer, 10))
	{
		return SYSI_INVALID;
	}

	if (!HcIsSyscallExport(&buffer))
	{
		return SYSI_INVALID;
	}

	return ExtractSyscallIndex(buffer);
}

SYS_INDEX
HCAPI
HcSyscallIndexW(LPCWSTR lpName)
{
	BYTE buffer[10];
	if (!HcFileReadModuleW(HcGlobal.HandleNtdll, lpName, buffer, 10))
	{
		return SYSI_INVALID;
	}

	if (!HcIsSyscallExport(&buffer))
	{
		return SYSI_INVALID;
	}

	return ExtractSyscallIndex(buffer);
}

/* The logic behind this function is checking whether the wow64 call gate is active or not. */
BOOLEAN
NAKED
HcIsWow64()
{
#ifndef _WIN64
	__asm
	{
		mov eax, fs:[0c0h]
		test eax, eax
		jne wow64
		ret
		wow64:
		mov eax, 1
		ret
	}
#else
	return FALSE;
#endif
}

/* Credits to DarthTon */
#ifndef _WIN64

#include <windows.h>

typedef union _reg64
{
	DWORD64 v;
	volatile DWORD dw[2];
} reg64;

/* Pointers should be scaled from 4 bytes (DWORD) to 8 bytes (DWORD64).
-- Example case is NtSuspendProcess(IN HANDLE hProcess). The call would look like this: HcWow64SystemCall(sciSuspendProcess, 1, (DWORD64)hProcess); 
*/

#pragma warning(disable : 4409)
NTSTATUS HCAPI HcWow64SystemCall(DWORD SysIndex, DWORD argC, va_list args)
{
	DWORD64 _rcx = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _rdx = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _r8 = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _r9 = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;

	reg64 _rax;
	_rax.v = 0;

	DWORD64 additionalArgs = (DWORD64)&va_arg(args, DWORD64);

 	DWORD64 _argC = argC;
	DWORD espBackup = 0;

	__asm
	{
		;//keep original esp in back_esp variable
		mov  espBackup, esp

		;//align esp to 8, without aligned stack some syscalls may return errors !
		and  esp, 0xFFFFFFF8

		X64_Start();

		;//fill first four arguments
		push _rcx
		X64_Pop(_RCX);
		push _rdx
		X64_Pop(_RDX);
		push _r8
		X64_Pop(_R8);
		push _r9
		X64_Pop(_R9);

		push edi

		push additionalArgs
		X64_Pop(_RDI);

		push _argC
		X64_Pop(_RAX);

		; /* put any additional of arguments on the stack */

		test eax, eax
		jz _ls_e
		lea  edi, dword ptr[edi + 8 * eax - 8]

		_ls:
		test eax, eax
		jz _ls_e
		push dword ptr[edi]
		sub  edi, 8
		sub  eax, 1
		jmp  _ls
		_ls_e :

		; /* create stack space for spilling registers */
		sub  esp, 0x28

		mov eax, SysIndex
		push _rcx
		X64_Pop(_R10);
		EMIT(0x0F) EMIT(0x05); /* 64bit syscall op */

		; /* cleanup stack */
		push _argC
		X64_Pop(_RCX);
		lea  esp, dword ptr[esp + 8 * ecx + 0x20]

		pop  edi

		/* set return value */
		X64_Push(_RAX);
		pop  _rax.dw[0]

		X64_End();

		mov  esp, espBackup
	}

	return (NTSTATUS)_rax.v;
}
#pragma warning(default : 4409)
/* End Credits to DarthTon */

#else
NTSTATUS HCAPI HcWow64SystemCall(DWORD SysIndex, DWORD argC, va_list args)
{
	return 0;
}
#endif