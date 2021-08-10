extern phookCtx:qword;
extern oriRtlCaptureContext:proc;
extern MyRtlCaptureContext:proc;
extern callFromRip:qword;
extern errorCode:qword;
extern tRegister:qword;
EXTERN g_CpuContextAddress:QWORD;
EXTERN g_KiRetireDpcList:QWORD;
EXTERN switchRsp:QWORD
extern VistaAll_DpcInterceptor:proc
extern nextintruc:qword;
extern addrKiPageFault:qword;
extern PrintfInterpretCount:proc;
extern pKiRetireDpcList:qword
extern GetPteAddress:proc;
extern GetPdeAddress:proc;
extern PrintfRecoverCount:proc

.code
HookRtlCaptureContext proc
    ;int 3
    ;jmp qword ptr [oriRtlCaptureContext]

    ;mov tRegister,rax
    ;mov rax,[rsp]
    ;mov callFromRip,rax
    ;mov rax,tRegister

    

    ;sub rsp,28h
    ;call MyRtlCaptureContext
    ;add rsp,28h

    ret


HookRtlCaptureContext endp

GetRsp  proc
    mov rax,rsp
    ret
GetRsp  endp

GetCpuIndex PROC
    mov     al, gs:[52h]
    movzx   eax, al
    ret
GetCpuIndex ENDP

EnableInterrupts proc
    sti
    ret
EnableInterrupts endp

AdjustStackCallPointer PROC
    mov rsp, rcx
    xchg r8, rcx
    jmp rdx
AdjustStackCallPointer ENDP

RestoreCpuContext PROC
                 push    rax
                 sub     rsp, 20h
                 call    GetCpuIndex
                 add     rsp, 20h
                 mov     r11, 170h
                 mul     r11
                 mov     r11, rax
                 add     r11, g_CpuContextAddress
                 pop     rax
                 mov     rsp, [r11+48h]
                 mov     switchRsp,rsp
                 mov     rbx, [r11+40h]
                 mov     [rsp+0], rbx
                 movdqa  xmm0, xmmword ptr [r11+50h]
                 movdqa  xmm1, xmmword ptr [r11+60h]
                 movdqa  xmm2, xmmword ptr [r11+70h]
                 movdqa  xmm3, xmmword ptr [r11+80h]
                 movdqa  xmm4, xmmword ptr [r11+90h]
                 movdqa  xmm5, xmmword ptr [r11+0A0h]
                 movdqa  xmm6, xmmword ptr [r11+0B0h]
                 movdqa  xmm7, xmmword ptr [r11+0C0h]
                 movdqa  xmm8, xmmword ptr [r11+0D0h]
                 movdqa  xmm9, xmmword ptr [r11+0E0h]
                 movdqa  xmm10, xmmword ptr [r11+0F0h]
                 movdqa  xmm11, xmmword ptr [r11+100h]
                 movdqa  xmm12, xmmword ptr [r11+110h]
                 movdqa  xmm13, xmmword ptr [r11+120h]
                 movdqa  xmm14, xmmword ptr [r11+130h]
                 movdqa  xmm15, xmmword ptr [r11+140h]
                 mov     rbx, [r11]
                 mov     rsi, [r11+8]
                 mov     rdi, [r11+10h]
                 mov     rbp, [r11+18h]
                 mov     r12, [r11+20h]
                 mov     r13, [r11+28h]
                 mov     r14, [r11+30h]
                 mov     r15, [r11+38h]
                 mov     rcx, [r11+150h]
                 mov     rdx, [r11+158h]
                 mov     r8, [r11+160h]
                 mov     r9, [r11+168h]
                 ret
RestoreCpuContext ENDP


HookKiRetireDpcList PROC
                 ;保存环境，然后jmp到原KiRetireDpcList
                 ;
                 ;只有KiRetireDpcList这一个途径可以分发DPC
                 ;也就是说DPC要执行的时候，调用KiRetireDpcList，保存进来的环境，然后调用原来的KiRetireDpcList继续分发DPC
                 ;如果是PG的DPC，那么必定会bugcheck，走到我们hook的RtlCaptureContext，然后恢复环境重新继续执行KiRetireDpcList
                 ;
                 ;
                 ;
                 push    rcx
                 push    rdx
                 push    r8
                 push    r9
                 sub     rsp, 20h
                 call    GetCpuIndex
                 add     rsp, 20h
                 pop     r9
                 pop     r8
                 pop     rdx
                 pop     rcx
                 mov     r11, 170h
                 mul     r11
                 add     rax, g_CpuContextAddress ; RAX = g_CpuContext[CpuIndex]
                 mov     [rax], rbx
                 mov     [rax+8], rsi
                 mov     [rax+10h], rdi
                 mov     [rax+18h], rbp
                 mov     [rax+20h], r12
                 mov     [rax+28h], r13
                 mov     [rax+30h], r14
                 mov     [rax+38h], r15
                 movdqa  xmmword ptr [rax+50h], xmm0
                 movdqa  xmmword ptr [rax+60h], xmm1
                 movdqa  xmmword ptr [rax+70h], xmm2
                 movdqa  xmmword ptr [rax+80h], xmm3
                 movdqa  xmmword ptr [rax+90h], xmm4
                 movdqa  xmmword ptr [rax+0A0h], xmm5
                 movdqa  xmmword ptr [rax+0B0h], xmm6
                 movdqa  xmmword ptr [rax+0C0h], xmm7
                 movdqa  xmmword ptr [rax+0D0h], xmm8
                 movdqa  xmmword ptr [rax+0E0h], xmm9
                 movdqa  xmmword ptr [rax+0F0h], xmm10
                 movdqa  xmmword ptr [rax+100h], xmm11
                 movdqa  xmmword ptr [rax+110h], xmm12
                 movdqa  xmmword ptr [rax+120h], xmm13
                 movdqa  xmmword ptr [rax+130h], xmm14
                 movdqa  xmmword ptr [rax+140h], xmm15
                 mov     [rax+150h], rcx
                 mov     [rax+158h], rdx
                 mov     [rax+160h], r8
                 mov     [rax+168h], r9
                 mov     r11, [rsp]
                 mov     [rax+40h], r11
                 mov     r11, rsp
                 mov     [rax+48h], r11
                 lea     rax, RestoreCpuContext
                 mov     [rsp],rax
                 jmp     g_KiRetireDpcList
HookKiRetireDpcList ENDP

BackTo1942 PROC
                 sub     rsp, 20h 
                 call    GetCpuIndex
                 add     rsp, 20h
                 mov     r11, 170h
                 mul     r11 
                 mov     r11, rax
                 add     r11, g_CpuContextAddress
                 mov     rax, [r11+40h]
                 sub     rax, 5
                 mov     [r11+40h], rax
                 jmp     RestoreCpuContext
BackTo1942 ENDP


TIMER_FIX:
                 mov      rcx,qword ptr [rbx-8]
                 mov      rax, VistaAll_DpcInterceptor
                 jmp      rax 


DPC_FIX proc
                 mov     edi, [rax+1C4h]
                 mov     rdx, rbp
                 mov     rcx, rsi
                 push    nextintruc
                 mov     rax, VistaAll_DpcInterceptor
                 jmp     rax 
DPC_FIX endp


hookKiPageFault proc
            push rcx
            push rax
            push rdx
            push r8
            push r9
            push r11




            mov  rax,[rsp+30h]
            cmp  rax,11h
            jnz  $ori ;非执行异常

            mov  rax,[rsp+38h]
            mov  eax,dword ptr [rax]
            cmp  eax,1131482eh
            jnz  $revocovePteOrPde ;是执行异常,但不是PatchGuardContext

;-----------------------------------------------
            
            ;跟踪PatchGuard

            ;可能为PatchGuard的context
            ;windbg手动使触发pagefault的pte或pde置最高位置0

            ;跟踪PatchGuard的初始化

           

            
            ;
            ;
            ;
            ;
            ;
            ;
            ;
            ;
 
    ;DbgPrint会破坏很多寄存器
            sub rsp,28h
            call PrintfInterpretCount
            add rsp,28h
;---------------------------------------------------
    ;跳过PatchGuard的初始化
            
            ;恢复原来寄存器
                
            ;int 3
            mov rax,[rsp+48h] ;eflags
            and rax,4294967039 ;FFFFFEFF
            push rax
            popfq
            mov ax,[rsp+58h]
            mov ss,ax
            mov rax,[rsp+50h]
            mov rsp,rax

            ret



;-----------------------------------------------
$revocovePteOrPde:
                ;int 3
                mov  rax,[rsp+38h]
                mov rcx,rax
                sub rsp,28h
                call GetPdeAddress
                add rsp,28h
                mov rdx,[rax]
                test rdx,80h
                jnz pde

pte:
                sub rsp,28h
                call GetPteAddress
                add rsp,28h
                mov rdx,[rax]
                mov r8,7FFFFFFFFFFFFFFFh
                and rdx,r8
                mov [rax],rdx
                jmp $ori2
pde:
                mov r8,7FFFFFFFFFFFFFFFh
                and rdx,r8
                mov [rax],rdx

$ori2:          ;返回原来的rip处继续执行
                ;int 3

                mov rcx,[rsp+38h]
                sub rsp,28h
                call PrintfRecoverCount
                add rsp,28h

                pop r11
                pop r9
                pop r8
                pop rdx
                pop rax
                pop rcx

                lea rsp,[rsp+8] ;pop error code
                iretq



$ori:
                
                pop r11
                pop r9
                pop r8
                pop rdx
                pop rax
                pop rcx
                ;--------------------------
                push    rbp
                sub     rsp, 158h
                lea     rbp, [rsp+80h]
                jmp     qword ptr [addrKiPageFault]

hookKiPageFault endp


editRip proc
    mov rax,pKiRetireDpcList
    add rax,25Ah
    jmp rax
editRip endp


END