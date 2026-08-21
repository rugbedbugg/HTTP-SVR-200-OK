.intel_syntax noprefix

.global	FILE_LIST

.section .rodata
FILES_DIR:	.asciz	"files_root"		# NUL-terminated for open(2)
.set	FILES_DIR_LEN,	10

.section .bss
#===============================================#
#	   File Listing (.bss)			#
#===============================================#
	.lcomm	DENT_BUF, 4096			# getdents64(2) staging buffer
.global	FILELIST_BUF
.balign	8
FILELIST_BUF:
	.zero	8192				# assembled listing body
	.lcomm	FILE_FD, 8			# directory fd during scan
	.lcomm	FILE_WIDX, 8			# current write index into FILELIST_BUF

.section .text
#===============================================#
#		     FILES			#
#===============================================#
# 1. FILE_LIST()
#
# Opens ./files_root (O_DIRECTORY) and walks it with getdents64(2),
# assembling a listing body into FILELIST_BUF: one entry per line,
# directory names suffixed with '/'. Dotfile entries are skipped.
# Stops early (with a partial listing) if the body buffer fills up.
# Returns: rax = body length (>= 0) OR -1 (directory could not be opened)
FILE_LIST:
	lea		rdi,	[rip+FILES_DIR]
	mov		rsi,	0x10000			# O_DIRECTORY (O_RDONLY == 0)
	xor		edx,	edx
	mov		eax,	2			# sys_open
	syscall
	cmp		rax,	0
	jl		.FL_FAIL
	mov		[rip+FILE_FD],	rax
	mov		qword ptr [rip+FILE_WIDX],	0

.FL_READ:
	mov		rdi,	[rip+FILE_FD]
	lea		rsi,	[rip+DENT_BUF]
	mov		rdx,	4096
	mov		eax,	217			# sys_getdents64
	syscall
	test		rax,	rax
	jle		.FL_DONE			# 0 = end of dir, <0 = read error
	mov		r10,	rax			# bytes returned in DENT_BUF
	lea		rbx,	[rip+DENT_BUF]
	xor		r11,	r11			# offset into DENT_BUF

.FL_ENT:
	cmp		r11,	r10
	jae		.FL_READ			# batch exhausted - read more

	# stop before the listing buffer could overflow on a long name
	cmp		qword ptr [rip+FILE_WIDX],	7936
	ja		.FL_DONE

	# linux_dirent64: d_ino(+0) d_off(+8) d_reclen(+16) d_type(+18) d_name(+19)
	movzx		r8d,	word ptr [rbx+r11+16]	# r8 = d_reclen
	movzx		r9d,	byte ptr [rbx+r11+18]	# r9 = d_type
	lea		rsi,	[rbx+r11+19]		# rsi = d_name
	cmp		byte ptr [rsi],	'.'
	je		.FL_SKIP			# hide dotfiles (incl. "." and "..")

	# measure the NUL-terminated name
	mov		rcx,	rsi
.FL_NLEN:
	cmp		byte ptr [rcx],	0
	je		.FL_NEND
	inc		rcx
	jmp		.FL_NLEN
.FL_NEND:
	sub		rcx,	rsi			# rcx = name length

	# append name to FILELIST_BUF
	cld
	lea		rdi,	[rip+FILELIST_BUF]
	add		rdi,	[rip+FILE_WIDX]
	rep		movsb				# copies name, rdi -> past name

	mov		al,	'/'
	cmp		r9d,	4			# DT_DIR
	jne		.FL_NOSEP
	stosb						# directories get a trailing '/'
.FL_NOSEP:
	mov		al,	10			# '\n'
	stosb

	lea		rcx,	[rip+FILELIST_BUF]
	sub		rdi,	rcx
	mov		[rip+FILE_WIDX],	rdi

.FL_SKIP:
	add		r11,	r8			# advance to next dirent
	jmp		.FL_ENT

.FL_DONE:
	mov		rdi,	[rip+FILE_FD]
	mov		eax,	3			# sys_close
	syscall
	mov		rax,	[rip+FILE_WIDX]
	ret

.FL_FAIL:
	mov		rax,	-1
	ret