/* One read+execute segment holding everything (headers included), so the file maps as is:
   every section's address equals its file offset. As Linux's vdso-layout. */
SECTIONS
{
    . = SIZEOF_HEADERS;
    .hash           : { *(.hash) }                  :text
    .gnu.hash       : { *(.gnu.hash) }
    .dynsym         : { *(.dynsym) }
    .dynstr         : { *(.dynstr) }
    .gnu.version    : { *(.gnu.version) }
    .gnu.version_d  : { *(.gnu.version_d) }
    .gnu.version_r  : { *(.gnu.version_r) }
    .note           : { *(.note.*) }                :text :note
    .dynamic        : { *(.dynamic) }               :text :dynamic
    .rodata         : { *(.rodata*) }               :text
    .text           : { *(.text*) }                 :text
    /DISCARD/       : { *(.data*) *(.bss*) *(.eh_frame*) *(.comment) *(.got*) *(.plt*) }
}

PHDRS
{
    text    PT_LOAD    FLAGS(5) FILEHDR PHDRS;
    dynamic PT_DYNAMIC FLAGS(4);
    note    PT_NOTE    FLAGS(4);
}
