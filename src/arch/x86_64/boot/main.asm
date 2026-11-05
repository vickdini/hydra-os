global start
extern long_mode_start

section .text
bits 32

start:
    ; set stack pointer
    mov esp, stack_top

    ; check that this code has been loaded by a multiboot bootloader
    call check_multiboot
    ; check the CPU information
    call check_cpuid
    ; check for long (64 bit) mode support
    call check_long_mode

    ; set up the page tables
    call setup_page_tables
    ; enable paging on the CPU
    call enable_paging

    ; load the global descriptor table
    lgdt [gdt64.pointer]
    jmp gdt64.code_segment:long_mode_start

    hlt

check_multiboot:
    cmp eax, 0x36d76289
    jne .no_multiboot
    ret

.no_multiboot:
    ; show multiboot error message
    mov al, "M"
    jmp error

check_cpuid:
    ; Check if CPUID is supported by attempting to flip the ID bit (bit 21) in
    ; the FLAGS register. If we can flip it, CPUID is available.

    ; Copy FLAGS into EAX via stack
    pushfd
    pop eax
    ; Copy to ECX as well for comparing later on
    mov ecx, eax
    ; Flip the ID bit
    xor eax, 1 << 21
    ; Copy EAX to FLAGS via the stack
    push eax
    popfd
    ; Copy FLAGS back to EAX (with the flipped bit if CPUID is supported)
    pushfd
    pop eax
    ; Restore FLAGS from the old version stored in ECX (i.e. flipping the ID bit
    ; back if it was ever flipped).
    push ecx
    popfd
    ; Compare EAX and ECX. If they are equal then that means the bit wasn't
    ; flipped, and CPUID isn't supported.
    cmp eax, ecx
    je .no_cpuid
    ret

.no_cpuid:
    ; show cpuid error message
    mov al, "C"
    jmp error

check_long_mode:
    ; check if extended processor info is supported
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .no_long_mode

    ; check if long mode is available
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29
    jz .no_long_mode

    ret

.no_long_mode:
    ; show long mode error message
    mov al, "L"
    jmp error

setup_page_tables:
    mov eax, page_table_l3
    ; enable the present and writable flags
    or eax, 0b11
    mov [page_table_l4], eax

    mov eax, page_table_l2
    ; enable the present and writable flags
    or eax, 0b11
    mov [page_table_l3], eax

    mov ecx, 0

.loop:
    mov eax, 0x200000
    mul ecx
    ; enable the present, writable, and huge page flags
    or eax, 0b10000011
    mov [page_table_l2 + ecx * 8], eax
    
    ; increase the counter
    inc ecx
    ; check if the whole table is mapped
    cmp ecx, 512
    jne .loop

    ret

enable_paging:
    ; pass the page table location to the CPU
    mov eax, page_table_l4
    mov cr3, eax

    ; enable physical address extension (PAE)
    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax

    ; enable long mode
    mov ecx, 0xC0000080
    rdmsr
    or eax, 1 << 8
    wrmsr

    ; enable paging
    mov eax, cr0
    or eax, 1 << 31
    mov cr0, eax

    ret

error:
    ; print error code X: "ERR: X"
    mov dword [0xb8000], 0x4f524f45
    mov dword [0xb8004], 0x4f3a4f52
    mov dword [0xb8008], 0x4f204f20
    mov byte  [0xb800a], al
    hlt

section .bss
; each table is 4KB
align 4096
page_table_l4:
    resb 4096
page_table_l3:
    resb 4096
page_table_l2:
    resb 4096
stack_bottom:
    resb 4096 * 4
stack_top:

section .rodata:
gdt64:
    ; zero entry
    dq 0
.code_segment: equ $ - gdt64
    ; code segment
    dq (1 << 43) | (1 << 44) | (1 << 47) | (1 << 53)
.pointer:
    dw $ - gdt64 - 1
    dq gdt64