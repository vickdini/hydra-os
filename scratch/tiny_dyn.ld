PHDRS {
  headers PT_PHDR PHDRS;
  interp PT_INTERP;
  text PT_LOAD FILEHDR PHDRS;
  dynamic PT_DYNAMIC;
}
SECTIONS {
  . = 0x400000 + SIZEOF_HEADERS;
  .interp : { *(.interp) } :text :interp
  .text : { *(.text*) } :text
  .rodata : { *(.rodata*) } :text
  .data : { *(.data*) } :text
  .dynamic : { *(.dynamic) } :text :dynamic
  .dynsym : { *(.dynsym) } :text
  .dynstr : { *(.dynstr) } :text
  .bss : { *(.bss*) } :text
}
