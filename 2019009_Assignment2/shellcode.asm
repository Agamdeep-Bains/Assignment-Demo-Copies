global _start

SECTION .text

_start:
	jmp		somewhere_random

print_hello:
	pop		rsi
	push	0x1
	pop		rax
	push	rax
	pop		rdi
	push	11
	pop		rdx
	syscall

	push	60
	pop		rax
	syscall

somewhere_random:
	call	print_hello
	text:	db "Hello World"