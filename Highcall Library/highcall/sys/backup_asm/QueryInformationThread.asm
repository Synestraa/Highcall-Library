; QueryInformationThread

IFDEF RAX
; 64bit
   
EXTERNDEF sciQueryInformationThread:DWORD

.DATA
.CODE
 
HcQueryInformationThread PROC 
	mov r10, rcx
	mov eax, sciQueryInformationThread
	syscall
	ret
HcQueryInformationThread ENDP 

ELSE
; 32bit

EXTERNDEF C sciQueryInformationThread:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcQueryInformationThread PROC 
	mov eax, sciQueryInformationThread
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
HcQueryInformationThread ENDP 

ENDIF

END
