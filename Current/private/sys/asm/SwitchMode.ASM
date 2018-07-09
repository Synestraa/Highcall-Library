
IFDEF RAX
; 64bit
 
.code
 
    ; Switch to long mode
    Enter64 proc
		push 33h
		call $+5
		add dword ptr [esp], 5
		retf
    Enter64 endp
 
    ; Switch to WOW64 mode
    Enter32 proc
        call $+5
		mov dword ptr [rsp + 4], 23h
		add dword ptr [rsp], 0dh
		retf
    Enter32 endp

ENDIF
    
end