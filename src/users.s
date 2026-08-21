.intel_syntax noprefix

.global	USER_CREATE
.global	USER_FIND

.extern	SHA256_INIT
.extern	SHA256_UPDATE
.extern	SHA256_FINAL

.section .bss
#===============================================#
#		  User Table (.bss)		#
#===============================================#
# Slot layout (96 bytes):
#   [ 0..31] username  (zero-padded)
#   [32..47] salt      (16 random bytes, generated at USER_CREATE time)
#   [48..79] password hash (SHA-256 of salt || password)
#   [80..95] reserved (zero)
.global	USER_TABLE
.balign	8
USER_TABLE:
	.zero	6144				# 64 slots x 96 bytes
	.lcomm	USERNAME_SCRATCH, 32		# zero-padded username, used for table compares
	.lcomm	PASSWORD_HASH_SCRATCH, 32	# computed hash, used for login password compares
	.lcomm	SHA_CTX_SCRATCH, 128		# streaming SHA-256 context work area

.set	USER_SLOT_LEN,		96
.set	USER_SLOT_COUNT,	64
.set	USERNAME_MAX_LEN,	32
.set	SALT_LEN,		16

.section .text
#===============================================#
#		    USER HELPERS		#
#===============================================#
# 1. USER_CREATE(username_ptr=rdi, username_len=rsi, password_ptr=rdx, password_len=rcx)
#
# Zero-pads the username into USERNAME_SCRATCH, scans USER_TABLE for either
# a duplicate username (fail) or the first free (all-zero-username) slot,
# copies the username in, generates a fresh 16-byte salt via getrandom(2)
# directly into the slot, then hashes salt || password via the streaming
# SHA-256 API into the slot's hash field. Free slots only ever occur at the
# unused tail (accounts are never deleted), so the first empty slot found
# also proves no duplicate exists among the slots before it.
# Returns: rax = 1 (created) OR 0 (duplicate username) OR 2 (table full)
USER_CREATE:
	cmp		rsi,	USERNAME_MAX_LEN
	ja		.UC_REJECT		# defensive: caller (routing.s) already checks this

	push		rdx			# preserve password_ptr across the scan
	push		rcx			# preserve password_len across the scan
	mov		r10,	rdi		# r10 = username_ptr
	mov		r11,	rsi		# r11 = username_len

	lea		rdi,	[rip+USERNAME_SCRATCH]
	xor		rax,	rax
	mov		rcx,	32
	cld
	rep		stosb

	lea		rdi,	[rip+USERNAME_SCRATCH]
	mov		rsi,	r10
	mov		rcx,	r11
	rep		movsb

	lea		r8,	[rip+USER_TABLE]
	xor		r9,	r9
.UC_SCAN:
	cmp		r9,	USER_SLOT_COUNT
	jge		.UC_FULL

	mov		rax,	r9
	imul		rax,	rax,	USER_SLOT_LEN
	lea		rbx,	[r8+rax]		# rbx = &USER_TABLE[slot]

	mov		rax,	qword ptr [rbx]
	or		rax,	qword ptr [rbx+8]
	or		rax,	qword ptr [rbx+16]
	or		rax,	qword ptr [rbx+24]
	cmp		rax,	0
	je		.UC_FREE

	lea		rdi,	[rip+USERNAME_SCRATCH]
	xor		r11,	r11			# accumulate XOR of all byte diffs
	xor		rcx,	rcx
.UC_CMP:
	cmp		rcx,	32
	je		.UC_CMPDONE
	movzx		eax,	byte ptr [rbx+rcx]
	movzx		edx,	byte ptr [rdi+rcx]
	xor		eax,	edx
	or		r11d,	eax
	inc		rcx
	jmp		.UC_CMP

.UC_CMPDONE:
	test		r11,	r11
	je		.UC_DUPLICATE

.UC_NEXT:
	inc		r9
	jmp		.UC_SCAN

.UC_FREE:
	mov		rdi,	rbx
	lea		rsi,	[rip+USERNAME_SCRATCH]
	mov		rcx,	32
	cld
	rep		movsb

	# generate a fresh 16-byte salt directly into the slot's salt field
	lea		rdi,	[rbx+32]
	mov		rsi,	SALT_LEN
	xor		rdx,	rdx			# flags = 0
	mov		rax,	318			# sys_getrandom
	syscall

	pop		r11			# password_len
	pop		r10			# password_ptr

	# hash salt || password into the slot's hash field
	lea		rdi,	[rip+SHA_CTX_SCRATCH]
	call		SHA256_INIT

	lea		rdi,	[rip+SHA_CTX_SCRATCH]
	lea		rsi,	[rbx+32]		# slot's salt field
	mov		rdx,	SALT_LEN
	call		SHA256_UPDATE

	lea		rdi,	[rip+SHA_CTX_SCRATCH]
	mov		rsi,	r10			# password_ptr
	mov		rdx,	r11			# password_len
	call		SHA256_UPDATE

	lea		rdi,	[rip+SHA_CTX_SCRATCH]
	lea		rsi,	[rbx+48]		# slot's password-hash field
	call		SHA256_FINAL

	mov		rax,	1
	ret

.UC_DUPLICATE:
	add		rsp,	16
	xor		rax,	rax
	ret

.UC_FULL:
	add		rsp,	16
	mov		rax,	2
	ret

.UC_REJECT:
	xor		rax,	rax
	ret

# 2. USER_FIND(username_ptr=rdi, username_len=rsi, password_ptr=rdx, password_len=rcx)
#
# Zero-pads the username into USERNAME_SCRATCH, scans USER_TABLE for a
# matching username, then hashes salt || submitted password (using the
# slot's stored salt) via the streaming SHA-256 API and compares it
# against the slot's stored hash.
# Returns: rax = 1 (username + password match) OR 0 (no match)
USER_FIND:
	cmp		rsi,	USERNAME_MAX_LEN
	ja		.UF_LEN_BAD

	push		rdx			# preserve password_ptr across the scan
	push		rcx			# preserve password_len across the scan
	mov		r10,	rdi		# r10 = username_ptr
	mov		r11,	rsi		# r11 = username_len

	lea		rdi,	[rip+USERNAME_SCRATCH]
	xor		rax,	rax
	mov		rcx,	32
	cld
	rep		stosb

	lea		rdi,	[rip+USERNAME_SCRATCH]
	mov		rsi,	r10
	mov		rcx,	r11
	rep		movsb

	lea		r8,	[rip+USER_TABLE]
	xor		r9,	r9
.UF_SCAN:
	cmp		r9,	USER_SLOT_COUNT
	jge		.UF_NOTFOUND

	mov		rax,	r9
	imul		rax,	rax,	USER_SLOT_LEN
	lea		rbx,	[r8+rax]

	mov		rax,	qword ptr [rbx]
	or		rax,	qword ptr [rbx+8]
	or		rax,	qword ptr [rbx+16]
	or		rax,	qword ptr [rbx+24]
	cmp		rax,	0
	je		.UF_NOTFOUND		# reached the unused tail: no match exists

	lea		rdi,	[rip+USERNAME_SCRATCH]
	xor		r11,	r11			# accumulate XOR of all byte diffs
	xor		rcx,	rcx
.UF_CMP:
	cmp		rcx,	32
	je		.UF_CMPDONE
	movzx		eax,	byte ptr [rbx+rcx]
	movzx		edx,	byte ptr [rdi+rcx]
	xor		eax,	edx
	or		r11d,	eax
	inc		rcx
	jmp		.UF_CMP

.UF_CMPDONE:
	test		r11,	r11
	je		.UF_USERNAME_MATCH

.UF_NEXT:
	inc		r9
	jmp		.UF_SCAN

.UF_USERNAME_MATCH:
	pop		r11			# password_len
	pop		r10			# password_ptr

	# hash slot_salt || submitted password into PASSWORD_HASH_SCRATCH
	lea		rdi,	[rip+SHA_CTX_SCRATCH]
	call		SHA256_INIT

	lea		rdi,	[rip+SHA_CTX_SCRATCH]
	lea		rsi,	[rbx+32]		# slot's salt field
	mov		rdx,	SALT_LEN
	call		SHA256_UPDATE

	lea		rdi,	[rip+SHA_CTX_SCRATCH]
	mov		rsi,	r10			# password_ptr
	mov		rdx,	r11			# password_len
	call		SHA256_UPDATE

	lea		rdi,	[rip+SHA_CTX_SCRATCH]
	lea		rsi,	[rip+PASSWORD_HASH_SCRATCH]
	call		SHA256_FINAL

	lea		r8,	[rip+PASSWORD_HASH_SCRATCH]
	xor		r11,	r11			# accumulate XOR of all byte diffs
	xor		rcx,	rcx
.UF_HASHCMP:
	cmp		rcx,	32
	je		.UF_HASHDONE
	movzx		eax,	byte ptr [r8+rcx]
	movzx		r9d,	byte ptr [rbx+48+rcx]
	xor		eax,	r9d
	or		r11d,	eax
	inc		rcx
	jmp		.UF_HASHCMP

.UF_HASHDONE:
	test		r11,	r11
	jne		.UF_NO

.UF_YES:
	mov		rax,	1
	ret

.UF_NOTFOUND:
	add		rsp,	16
.UF_NO:
	xor		rax,	rax
	ret

.UF_LEN_BAD:
	xor		rax,	rax
	ret
