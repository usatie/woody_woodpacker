[bits 64]
; prologue
push rax
push rdi
push rsi
push rdx

; int mprotect(void addr[.len], size_t len, int prot);
lea rdi, [rel $-0x184]    ; lea rdi, [rel $-0xaaaaaaaa]
mov rsi, 0x1000 ; mov rsi, 0xbbbbbbbb  ;
mov rdx, 7       ; prot = PROT_READ | PROT_WRITE | PROT_EXEC
mov rax, 10      ; 
syscall

; ptr = 0xcccccccc;
; for (int i = 0xdddddddd; i >= 0; --i) { *ptr = *ptr ^ 0xee; ++ptr; }

lea rdi, [rel $-0x13c] ; mov rdi, 0xcccccccc
mov rsi, rdi
mov rcx, 0x115; mov rdx, 0xdddddddd

decrypt:
  lodsb
  xor al, 0xa5
  stosb
  loop decrypt

; epilogue
pop rdx
pop rsi
pop rdi
pop rax

jmp $ - 0x155
