; Hc/NtGdiRectangle
; This file was automatically generated by Highcall's syscall generator.

IFDEF RAX
; 64bit

EXTERNDEF sciGdiRectangle:DWORD

.DATA
.CODE

HcGdiRectangle PROC
	mov r10, rcx
	mov eax, sciGdiRectangle
	syscall
	ret
HcGdiRectangle ENDP

ELSE
; 32bit

EXTERNDEF C sciGdiRectangle:DWORD

.586			  
.MODEL FLAT, C   
.STACK
.DATA
.CODE

ASSUME FS:NOTHING

HcGdiRectangle PROC
	mov eax, sciGdiRectangle
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
HcGdiRectangle ENDP

ENDIF

END