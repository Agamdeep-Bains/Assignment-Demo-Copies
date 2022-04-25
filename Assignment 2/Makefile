assemble:
	@nasm -f elf64 shellcode.asm
	@ld shellcode.o -o shellcode

clean:
	@rm shellcode shellcode.o