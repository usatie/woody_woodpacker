[bits 64]
; Q. Why this prologue is needed even though this is the entry point of the program?
; My answer : The ELF binary is not the first one to be executed. But the Dynamic Linker is the first program to run to interpret the ELF binary. Thus, even before the entry point, some registers already have meaningful values.
; prologue
push rbp
mov rbp, rsp
push rax
push rdi
push rsi
push rdx
push rcx

call packer                              ; call instruction push the next rip to the stack, which is the address of the string data
db      '....WOODY....',0x0a             ; "....WOODY....\n"

packer:
; write(1, "....WOODY....\n", 14);
mov rdi, 1                             ; 1 (STDOUT_FILENO)
pop rsi                                ; "....WOODY....\n"
mov rdx, 14                            ; 14
mov rax, 1                             ; 1 (sys_write)
syscall

; int mprotect(void addr[.len], size_t len, int prot);
lea rdi, [rel $ + 0x11111111 + 0x7]    ; dummy addr (0x11111111), 7 is the length of this instruction
mov rsi, 0x22222222                    ; dummy len (0x22222222)
mov rdx, 7                             ; prot = PROT_READ | PROT_WRITE | PROT_EXEC
mov rax, 10                            ; 10 (sys_mprotect)
syscall

; ptr = _start;
; void decrypt(uint64_t key, uint8_t *data, size_t size);
; int i = 0x44444444; do { *ptr = *ptr ^ 0x555555555555555; ++ptr; --i; } while (i != 0)

lea rdi, [rel $ + 0x33333333 + 0x7]    ; rdi = dummy data  (0x33333333)
mov rsi, rdi                           ; rsi = dummy data  (0x33333333)
mov rcx, 0x44444444                    ; rcx = dummy size (0x44444444)
mov rdx, 0x5555555555555555            ; rdx = dummy key  (0x555555555555555)

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
pop rbp

jmp $ + 0x66666666 + 0x5       ; dummy orig_ep_offset (0x66666666), 5 is the length of this instruction
