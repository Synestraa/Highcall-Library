; SetInformationThread

IFDEF RAX
; 64bit

EXTERNDEF sciSetInformationThread:DWORD
   
.DATA
.CODE
 
HcSetInformationThread PROC 
	mov r10, rcx
	mov eax, sciSetInformationThread
	syscall
	ret
HcSetInformationThread ENDP 

ELSE
; 32bit

EXTERNDEF C sciSetInformationThread:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcSetInformationThread PROC 
	mov eax, sciSetInformationThread
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
HcSetInformationThread ENDP 

ENDIF

END