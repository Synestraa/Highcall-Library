; QueryInformationProcess

IFDEF RAX
; 64bit
  
EXTERNDEF sciQueryInformationProcess:DWORD
 
.DATA
.CODE
 
HcQueryInformationProcess PROC 
	mov r10, rcx
	mov eax, sciQueryInformationProcess
	syscall
	ret
HcQueryInformationProcess ENDP 

ELSE
; 32bit

EXTERNDEF C sciQueryInformationProcess:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcQueryInformationProcess PROC 
	mov eax, sciQueryInformationProcess
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
HcQueryInformationProcess ENDP 

ENDIF

END
