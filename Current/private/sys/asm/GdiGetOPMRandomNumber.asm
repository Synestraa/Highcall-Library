; Hc/NtGdiGetOPMRandomNumber
; This file was automatically generated by Highcall's syscall generator.

IFDEF RAX
; 64bit

EXTERNDEF sciGdiGetOPMRandomNumber:DWORD

.DATA
.CODE

HcGdiGetOPMRandomNumber PROC
	mov r10, rcx
	mov eax, sciGdiGetOPMRandomNumber
	syscall
	ret
HcGdiGetOPMRandomNumber ENDP

ELSE
; 32bit

EXTERNDEF C sciGdiGetOPMRandomNumber:DWORD

.586			  
.MODEL FLAT, C   
.STACK
.DATA
.CODE

ASSUME FS:NOTHING

HcGdiGetOPMRandomNumber PROC
	mov eax, sciGdiGetOPMRandomNumber
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp + 4]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp + 4h]
	call dword ptr fs:[0c0h]
	ret
HcGdiGetOPMRandomNumber ENDP

ENDIF

END