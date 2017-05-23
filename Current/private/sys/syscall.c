#include <highcall.h>

#include "syscall.h"
#include "../../public/imports.h"

static
BOOLEAN
HCAPI
IsSyscall(LPBYTE lpAddress)
{
#ifdef _WIN64
	return *lpAddress == 0x4c && *(lpAddress + 3) == 0xb8;
#else
	return *lpAddress == 0xb8;
#endif
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

/* The logic behind this function is checking whether the wow64 call gate is active or not. */
BOOLEAN
#ifndef _WIN64
__declspec(naked)
#else
__stdcall
#endif
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


NTSTATUS
SYSCALLAPI
HcClose64(IN DWORD64 hObj)
{
	return (NTSTATUS) HcWow64Syscall(sciClose64, 1, (DWORD64) hObj);
}


NTSTATUS
SYSCALLAPI
HcCreateThreadEx64(OUT PTR_64(PHANDLE) PtrThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN PTR_64(POBJECT_ATTRIBUTES) PtrObjectAttributes OPTIONAL,
	IN PTR_64(HANDLE) ProcessHandle,
	IN PTR_64(PVOID) StartRoutine,
	IN PTR_64(PVOID) Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN PTR_64(ULONG_PTR) ZeroBits OPTIONAL,
	IN PTR_64(SIZE_T) StackSize OPTIONAL,
	IN PTR_64(SIZE_T) MaximumStackSize OPTIONAL,
	IN PTR_64(PVOID) AttributeList OPTIONAL)
{
	return (NTSTATUS) HcWow64Syscall(sciCreateThreadEx64, 11, (DWORD64) PtrThreadHandle,
		(DWORD64) DesiredAccess,
		(DWORD64) PtrObjectAttributes OPTIONAL,
		(DWORD64) ProcessHandle,
		(DWORD64) StartRoutine,
		(DWORD64) Argument OPTIONAL,
		(DWORD64) CreateFlags,
		(DWORD64) ZeroBits OPTIONAL,
		(DWORD64) StackSize OPTIONAL,
		(DWORD64) MaximumStackSize OPTIONAL,
		(DWORD64) AttributeList OPTIONAL);
}

#include <windows.h> /* this shouldn't include any libraries. */

// to fool M$ inline asm compiler I'm using 2 DWORDs instead of DWORD64
// use of DWORD64 will generate wrong 'pop word ptr[]' and it will break stack
union reg64 {
	unsigned long dw[2];
	unsigned long long v;
};

// warning C4409: illegal instruction size
#pragma warning(disable : 4409)
DWORD64 X64SyscallV(int idx, int argC, va_list args)
{
	/* grab the first four arguments to accompany the x86_64 calling convention. */
	DWORD64 _rcx = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _rdx = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _r8 = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _r9 = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	union reg64 _rax;
	DWORD32 _idx = idx;
	_rax.v = 0;

	DWORD64 restArgs = (DWORD64) &va_arg(args, DWORD64);

	/* easier use in inline assembly. */
	DWORD64 _argC = argC;
	DWORD back_esp = 0;

	__asm
	{
		/* save the esp. */
		mov    back_esp, esp

		/* align esp to prepare for the 64bit rsp conversion. */
		and esp, 0xFFFFFFF8

		X64_Start();

		/* x86_64 calling convention. first 4 arguments go into rcx, rdx, r8, r9 */
		push _rcx
		X64_Pop(_RCX);
		push _rdx
		X64_Pop(_RDX);
		push _r8
		X64_Pop(_R8);
		push _r9
		X64_Pop(_R9);

		push edi

		push restArgs
		X64_Pop(_RDI);

		push _argC
		X64_Pop(_RAX);

		/* put rest of arguments on the stack */
		test eax, eax
		jz _ls_e
		lea edi, dword ptr[edi + 8 * eax - 8]

	_ls:
		test eax, eax
		jz _ls_e
		push dword ptr[edi]
		sub edi, 8
		sub eax, 1
		jmp _ls

	_ls_e :
		/* create stack space for spilling registers */
		sub esp, 0x28

		mov eax, _idx
		push _rcx
		X64_Pop(_R10);
		e(0x0F) e(0x05); /* syscall */

		/* cleanup stack */
		push   _argC
		X64_Pop(_RCX);
		lea    esp, dword ptr[esp + 8 * ecx + 0x20]
		pop    edi

		/* set return value */
		X64_Push(_RAX);
		pop _rax.dw[0]
		X64_End();

		mov    esp, back_esp
	}

	return _rax.v;
}


DWORD64
SYSCALLAPI
HcWow64Syscall(int idx, int argC, ...)
{
	va_list args;
	va_start(args, argC);

	return X64SyscallV(idx, argC, args);
}

#pragma warning(default : 4409)