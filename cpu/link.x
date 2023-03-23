OUTPUT_ARCH(riscv)
OUTPUT_FORMAT("elf32-littleriscv", "elf32-littleriscv", "elf32-littleriscv")
ENTRY(_start)


ROM_ORG   = 0x00000000;
META_ORG  = ROM_SIZE;
ICCM_ORG  = 0x40000000;
DCCM_ORG  = 0x50000000;
FHT_ORG   = 0x50002000;
DATA_ORG  = 0x50003000;
STACK_ORG = 0x5001C000;
ESTACK_ORG  = 0x5001F800;
NSTACK_ORG  = 0x5001FC00;


ROM_SIZE    = 32K;
MBOX_SIZE   = 128K;
ICCM_SIZE   = 128K;
DCCM_SIZE   = 128K;
MAN1_SIZE   = 4K;
MAN2_SIZE   = 4K;
FHT_SIZE    = 4K;
DATA_SIZE   = 100K;
STACK_SIZE  = 14K;
ESTACK_SIZE = 1K;
NSTACK_SIZE = 1K;


MEMORY
{
	ROM  (rx) : ORIGIN = ROM_ORG,  LENGTH = ROM_SIZE
	META (r)  : ORIGIN = META_ORG, LENGTH = META_SIZE
	ICCM (rx) : ORIGIN = ICCM_ORG, LENGTH = ICCM_SIZE
	FHT  (rw) : ORIGIN = FHT_ORG,  LENGTH = FHT_SIZE
	DATA (rw) : ORIGIN = DATA_ORG, LENGTH = DATA_SIZE
	STACK(rw) : ORIGIN = STACK_ORG,  LENGTH = STACK_SIZE
	ESTACK (rw) : ORIGIN = ESTACK_ORG, LENGTH = ESTACK_SIZE
	NSTACK (rw) : ORIGIN = NSTACK_ORG, LENGTH = NSTACK_SIZE
} 
/* https://sourceware.org/binutils/docs/ld/REGION_005fALIAS.html#REGION_005fALIAS */
REGION_ALIAS("REGION_TEXT", ICCM);     
REGION_ALIAS("REGION_RODATA", ICCM);  
REGION_ALIAS("REGION_DATA", DATA);     
REGION_ALIAS("REGION_BSS", DATA);      
REGION_ALIAS("REGION_STACK", STACK);     
REGION_ALIAS("REGION_ESTACK", ESTACK);     
REGION_ALIAS("REGION_NSTACK", NSTACK);     

SECTIONS 
{
	.text : ALIGN(4)
	{
        _stext = .;

		KEEP(*(.init .init.*));
        *(.text .text.*);
        KEEP(*(.vectors))

    	. = ALIGN(4);
        _etext = .;
  	} > REGION_TEXT

	.rodata : ALIGN(4)
	{
        _srodata = .;
		
		*(.srodata .srodata.*);
    	*(.rodata .rodata.*);

    	. = ALIGN(4);
        _erodata = .;
	} > REGION_RODATA

	.data : AT (_erodata) ALIGN(4) 
	{
		_sidata = LOADADDR(.data);
	    _sdata = .;
		
	    /* Must be called __global_pointer$ for linker relaxations to work. */
	    PROVIDE(__global_pointer$ = . + 0x800);
   
		*(.sdata .sdata.* .sdata2 .sdata2.*);
	    *(.data .data.*);
	    
		. = ALIGN(4);
	    _edata = .;
	} > REGION_DATA 

 
	.bss (NOLOAD) : ALIGN(4) 
    {
		_sbss = .;

        *(.bss*)
        *(.sbss*)
        *(COMMON)
        . = ALIGN(4);
		
		_ebss = .;
    } > REGION_BSS

    .stack (NOLOAD): ALIGN(4)
    {
    	_estack = .;
		
        . = . + STACK_SIZE;

        . = ALIGN(4);
    	_sstack = .;
    } > REGION_STACK

	.estack (NOLOAD): ALIGN(4)
    {
    	_eestack = .;
		
        . = . + ESTACK_SIZE;

        . = ALIGN(4);
    	_sestack = .;
    } > REGION_ESTACK

	.nstack (NOLOAD): ALIGN(4)
    {
    	_enstack = .;
		
        . = . + NSTACK_SIZE;

        . = ALIGN(4);
    	_snstack = .;
    } > REGION_NSTACK


	.got (INFO) :
  	{
    	KEEP(*(.got .got.*));
  	}

  	.eh_frame (INFO) : 
	{ 
		KEEP(*(.eh_frame))
	}
	
  	.eh_frame_hdr (INFO) :
	{
		*(.eh_frame_hdr) 
	}
}

_bss_len  = SIZEOF(.bss);
_data_len = SIZEOF(.data);

ASSERT(SIZEOF(.got) == 0, ".got section detected");
ASSERT(SIZEOF(.data) == 0, ".data section detected");
ASSERT(SIZEOF(.bss) == 0, ".bss section detected");
ASSERT(SIZEOF(.stack) == STACK_SIZE, ".stack section overflow");
ASSERT(SIZEOF(.estack) == ESTACK_SIZE, ".estack section overflow");
ASSERT(SIZEOF(.nstack) == NSTACK_SIZE, ".nstack section overflow");
