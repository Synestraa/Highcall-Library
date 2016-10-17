; WriteVirtualMemory

IFDEF RAX
; 64bit
   
EXTERNDEF sciWriteVirtualMemory:DWORD

.DATA
.CODE
 
HcWriteVirtualMemory PROC 
	mov r10, rcx
	mov eax, sciWriteVirtualMemory
	syscall
	ret
HcWriteVirtualMemory ENDP 

ELSE
; 32bit

EXTERNDEF C sciWriteVirtualMemory:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcWriteVirtualMemory PROC 
	mov eax, sciWriteVirtualMemory
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
HcWriteVirtualMemory ENDP 

ENDIF

END