; Hc/NtDeleteObjectAuditAlarm
; This file was automatically generated by Highcall's syscall generator.

IFDEF RAX
; 64bit

EXTERNDEF sciDeleteObjectAuditAlarm:DWORD

.DATA
.CODE

HcDeleteObjectAuditAlarm PROC
	mov r10, rcx
	mov eax, sciDeleteObjectAuditAlarm
	syscall
	ret
HcDeleteObjectAuditAlarm ENDP

ELSE
; 32bit

EXTERNDEF C sciDeleteObjectAuditAlarm:DWORD

.586			  
.MODEL FLAT, C   
.STACK
.DATA
.CODE

ASSUME FS:NOTHING

HcDeleteObjectAuditAlarm PROC
	mov eax, sciDeleteObjectAuditAlarm
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
HcDeleteObjectAuditAlarm ENDP

ENDIF

END