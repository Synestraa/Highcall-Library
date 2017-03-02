IFDEF RAX ;no point in calling this from 32bit

Wow64StdCall PROTO 
.code 

    ; Switch to long mode 
    enter64 proc 
        retf 
    enter64 endp 

    ; Switch to WOW64 mode 
    enter32 proc 
        mov dword ptr [rsp + 4], 23h 
        retf 
    enter32 endp 

    ; Call arbitrary WOW64 stdcall function 
    Wow64StdCall proc 

        call enter32 

      looparg: 
        ;mov eax, dword ptr [esp + edx * 8 + 20h] 
        db 8Bh, 44h, 0D4h, 20h 
         
        ;push eax 
        db 50h 

        sub edx, 1 
      jnz looparg 

        mov eax, ecx 
        ;call eax 
        db 0FFh, 0D0h 

        push 33h 
        call enter64     

        ret 

    Wow64StdCall endp 

ENDIF

END