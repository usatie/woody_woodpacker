[bits 64]
; prologue
push rax
push rdi
push rsi
push rdx
push rcx

; int mprotect(void addr[.len], size_t len, int prot);
lea rdi, [rel $ + 0x11111111 + 0x7]    ; dummy addr (0x11111111), 7 is the length of this instruction
mov rsi, 0x22222222                    ; dummy len (0x22222222)
mov rdx, 7                             ; prot = PROT_READ | PROT_WRITE | PROT_EXEC
mov rax, 10                            ; 10 (sys_mprotect)
syscall

; ptr = _start;
; for (int i = 0xdddddddd; i >= 0; --i) { *ptr = *ptr ^ 0x123456789ABCDEF; ++ptr; }

lea rdi, [rel $ + 0x33333333 + 0x7]    ; rdi = dummy decrypt dst  (0x33333333)
mov rsi, rdi                           ; rsi = dummy decrypt src  (0x33333333)
mov rcx, 0x44444444                    ; rcx = dummy decrypt size (0x44444444)
mov rdx, 0x5555555555555555            ; rdx = dummy decrypt key  (0x555555555555555)

loop_decrypt:
  lodsq                        ; rax = [rsi]
  xor rax, rdx                 ; rax = rax ^ rdx
  stosq                        ; [rdi] = rax
  loop loop_decrypt            ; --rcx;
                               ; if (rcx > 0) { goto decrypt_loop; }

; Clean up memory protection
lea rdi, [rel $ + 0x11111111 + 0x7]    ; dummy addr (0x11111111), 7 is the length of this instruction
mov rsi, 0x22222222                    ; dummy len (0x22222222)
mov rdx, 5                             ; prot = PROT_READ | PROT_EXEC
mov rax, 10                            ; 10 (sys_mprotect)
syscall

; epilogue
pop rcx
pop rdx
pop rsi
pop rdi
pop rax

jmp $ + 0x66666666 + 0x5       ; dummy orig_ep_offset (0x66666666), 5 is the length of this instruction
