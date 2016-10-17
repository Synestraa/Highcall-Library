; WaitForMultipleObjects

IFDEF RAX
; 64bit
   
EXTERNDEF sciWaitForMultipleObjects:DWORD

.DATA
.CODE
 
HcWaitForMultipleObjects PROC 
	mov r10, rcx
	mov eax, sciWaitForMultipleObjects
	syscall
	ret
HcWaitForMultipleObjects ENDP 

ELSE
; 32bit

EXTERNDEF C sciWaitForMultipleObjects:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcWaitForMultipleObjects PROC 
	mov eax, sciWaitForMultipleObjects
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
HcWaitForMultipleObjects ENDP 

ENDIF

END