obj-m += arprk.o
arprk-objs := loader.o kernel-asm.o capstone/cs.o capstone/utils.o capstone/SStream.o capstone/MCInstrDesc.o capstone/MCRegisterInfo.o capstone/arch/X86/X86DisassemblerDecoder.o capstone/arch/X86/X86Disassembler.o capstone/arch/X86/X86IntelInstPrinter.o capstone/arch/X86/X86ATTInstPrinter.o capstone/arch/X86/X86Mapping.o capstone/arch/X86/X86Module.o capstone/MCInst.o

EXTRA_CFLAGS := -O0 -I$(PWD)/capstone/include -DCAPSTONE_USE_SYS_DYN_MEM -DCAPSTONE_HAS_X86

KERNEL_HEADERS = /lib/modules/$(shell uname -r)/build

all: arprk

arprk:
	make V=1 -C $(KERNEL_HEADERS) M=$(PWD) kernel.s
	echo "\t.data" > kernel-asm.s
	grep -vE "\.file|\.text|\.rodata|\.bss|\.data|\.version|\.section|\.align|\.p2align|\.balign|\.ident" kernel.s >> kernel-asm.s
	gcc -o kernel-asm.o -c kernel-asm.s
	make V=1 -C $(KERNEL_HEADERS) M=$(PWD) modules

clean:
	make V=1 -C $(KERNEL_HEADERS) M=$(PWD) clean
	rm -f *.plist
