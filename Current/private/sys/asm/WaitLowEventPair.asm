; Hc/NtWaitLowEventPair
; This file was automatically generated by Highcall's syscall generator.

IFDEF RAX
; 64bit

EXTERNDEF sciWaitLowEventPair:DWORD

.DATA
.CODE

HcWaitLowEventPair PROC
	mov r10, rcx
	mov eax, sciWaitLowEventPair
	syscall
	ret
HcWaitLowEventPair ENDP

ELSE
; 32bit

EXTERNDEF C sciWaitLowEventPair:DWORD

.586			  
.MODEL FLAT, C   
.STACK
.DATA
.CODE

ASSUME FS:NOTHING

HcWaitLowEventPair PROC
	mov eax, sciWaitLowEventPair
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
HcWaitLowEventPair ENDP

ENDIF

END