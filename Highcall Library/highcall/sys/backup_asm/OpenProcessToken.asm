; OpenProcessTokenToken

IFDEF RAX
; 64bit

EXTERNDEF sciOpenProcessToken:DWORD
   
.DATA
.CODE
 
HcOpenProcessToken PROC 
	mov r10, rcx
	mov eax, sciOpenProcessToken
	syscall
	ret
HcOpenProcessToken ENDP 

ELSE
; 32bit

EXTERNDEF C sciOpenProcessToken:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcOpenProcessToken PROC 
	mov eax, sciOpenProcessToken
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
HcOpenProcessToken ENDP 

ENDIF

END
