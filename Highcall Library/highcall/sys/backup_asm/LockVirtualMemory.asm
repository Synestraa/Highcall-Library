; LockVirtualMemory (HANDLE)

IFDEF RAX
; 64bit
   
EXTERNDEF sciLockVirtualMemory:DWORD

.DATA
.CODE
 
HcLockVirtualMemory PROC 
	mov r10, rcx
	mov eax, sciLockVirtualMemory
	syscall
	ret
HcLockVirtualMemory ENDP 

ELSE
; 32bit

EXTERNDEF C sciLockVirtualMemory:DWORD

.586              
.MODEL FLAT, C   
.STACK         
.DATA
.CODE
 
ASSUME FS:NOTHING	
 
HcLockVirtualMemory PROC 
	mov eax, sciLockVirtualMemory
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
HcLockVirtualMemory ENDP 

ENDIF

END