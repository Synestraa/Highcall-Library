; Hc/NtIsUILanguageComitted
; This file was automatically generated by Highcall's syscall generator.

IFDEF RAX
; 64bit

EXTERNDEF sciIsUILanguageComitted:DWORD

.DATA
.CODE

HcIsUILanguageComitted PROC
	mov r10, rcx
	mov eax, sciIsUILanguageComitted
	syscall
	ret
HcIsUILanguageComitted ENDP

ELSE
; 32bit

EXTERNDEF C sciIsUILanguageComitted:DWORD

.586			  
.MODEL FLAT, C   
.STACK
.DATA
.CODE

ASSUME FS:NOTHING

HcIsUILanguageComitted PROC
	mov eax, sciIsUILanguageComitted
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
HcIsUILanguageComitted ENDP

ENDIF

END