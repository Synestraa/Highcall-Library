; ResumeProcess

IFDEF RAX
; 64bit
   
EXTERNDEF sciResumeProcess:DWORD

.DATA
.CODE
 
HcResumeProcess PROC 
	mov r10, rcx
	mov eax, sciResumeProcess
	syscall
	ret
HcResumeProcess ENDP 

ELSE
; 32bit

EXTERNDEF C sciResumeProcess:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcResumeProcess PROC 
	mov eax, sciResumeProcess
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
HcResumeProcess ENDP 

ENDIF

END