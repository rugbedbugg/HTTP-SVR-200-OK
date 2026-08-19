.intel_syntax noprefix

.global	REQ_BUF
.global	FIND_HDR_END
.global	PARSE_CONTENT_LENGTH
.global	PATH_EQ_SPACE
.global	FORM_HAS_VALUE
.global	FORM_VALUE_EQ

.section .rodata
CONTENT_LENGTH_KEY:	.ascii	"Content-Length:"

.section .bss
#===============================================#
#		Request Buffer (.bss)		#
#===============================================#
	.lcomm	REQ_BUF, 4096

.section .text
#===============================================#
#		     HELPERS			#
#===============================================#
# 1. FIND_HDR_END(buf_ptr=rdi, bytes_read=rsi)
#
# Scans request bytes for "\r\n\r\n" and returns offset to body start
# Returns: rax = offset after boundary OR -1 if not found
FIND_HDR_END:
	xor		rcx,	rcx
.FHE_LOOP:
	cmp		rcx,	rsi
	jge		.FHE_FAIL
	cmp		rcx,	rsi
	jae		.FHE_FAIL
	cmp byte ptr [rdi+rcx], 13
	jne		.FHE_NEXT
	lea		r8,	[rcx+3]
	cmp		r8,	rsi
	jae		.FHE_FAIL
	cmp byte ptr [rdi+rcx+1], 10
	jne		.FHE_NEXT
	cmp byte ptr [rdi+rcx+2], 13
	jne		.FHE_NEXT
	cmp byte ptr [rdi+rcx+3], 10
	jne		.FHE_NEXT
	lea		rax,	[rcx+4]
	ret

.FHE_NEXT:
	inc		rcx
	jmp		.FHE_LOOP

.FHE_FAIL:
	mov		rax,	-1
	ret

# 2. PARSE_CONTENT_LENGTH(req_start=rdi, hdr_end_ptr=rsi)
#
# Returns parsed Content-Length value in rax
# Returns -1 if header is absent OR malformed
PARSE_CONTENT_LENGTH:
	mov		r8,	rdi		# scan pointer
.PCL_SCAN:
	cmp		r8,	rsi
	jae		.PCL_FAIL
	mov		rdi,	r8
	mov		rdx,	rsi
	sub		rdx,	r8
	lea		rbx,	[rip+CONTENT_LENGTH_KEY]
	mov		r9,	15		# CONTENT_LENGTH_KEY_LEN
	cmp		rdx,	r9
	jb		.PCL_NEXT_LINE

	# compare "Content-Length:"
	xor		rcx,	rcx
.PCL_CMP:
	cmp		rcx,	r9
	je		.PCL_FOUND
	mov		al,	byte ptr [r8+rcx]
	cmp		al,	byte ptr [rbx+rcx]
	jne		.PCL_NEXT_LINE
	inc		rcx
	jmp		.PCL_CMP

.PCL_FOUND:
	# parse decimal digits after optional spaces
	lea		r8,	[r8+r9]
.PCL_SKIP_SP:
	cmp		r8,	rsi
	jae		.PCL_FAIL
	cmp byte ptr [r8], ' '
	jne		.PCL_DIGITS
	inc		r8
	jmp		.PCL_SKIP_SP

.PCL_DIGITS:
	xor		rax,	rax
	xor		r11,	r11		# digit count
.PCL_NUM_LOOP:
	cmp		r8,	rsi
	jae		.PCL_DONE
	mov		bl,	byte ptr [r8]
	cmp		bl, 13
	je		.PCL_DONE
	cmp		bl, '0'
	jb		.PCL_FAIL
	cmp		bl, '9'
	ja		.PCL_FAIL
	imul		rax,	rax,	10
	sub		bl,	'0'
	movzx		rbx,	bl
	add		rax,	rbx
	inc		r8
	inc		r11
	jmp		.PCL_NUM_LOOP

.PCL_DONE:
	cmp		r11,	0
	je		.PCL_FAIL
	ret

.PCL_NEXT_LINE:
	# advance to next line by searching '\n'
.PCL_EOL:
	cmp		r8,	rsi
	jae		.PCL_FAIL
	cmp byte ptr [r8], 10
	je		.PCL_ADVANCE
	inc		r8
	jmp		.PCL_EOL

.PCL_ADVANCE:
	inc		r8
	jmp		.PCL_SCAN

.PCL_FAIL:
	mov		rax,	-1
	ret


# 3. FORM_HAS_VALUE(body_ptr=rdi, body_len=rsi, key_ptr=rdx, key_len=rcx)
#
# Finds key pattern in form body and verifies there is at least one value byte
# Returns: rax = 1 (found with non-empty value) OR 0 (missing/empty)
FORM_HAS_VALUE:
	xor		r8,	r8		# start index in body
.FHV_SCAN:
	cmp		r8,	rsi
	jae		.FHV_NO

	# ensure enough remaining bytes for key comparison
	mov		r9,	rsi
	sub		r9,	r8
	cmp		r9,	rcx
	jb		.FHV_NO

	# compare key bytes from body[r8 + i] with key[i]
	xor		r10,	r10
.FHV_CMP:
	cmp		r10,	rcx
	je		.FHV_KEY_MATCH
	lea		rax,	[rdi+r8]
	mov		r11b,	byte ptr [rax+r10]
	cmp		r11b,	byte ptr [rdx+r10]
	jne		.FHV_NEXT
	inc		r10
	jmp		.FHV_CMP

.FHV_KEY_MATCH:
	# check first value byte exists and is not '&' / CR / LF
	lea		rax,	[r8+rcx]
	cmp		rax,	rsi
	jae		.FHV_NO
	lea		r9,	[rdi+rax]
	mov		r11b,	byte ptr [r9]
	cmp		r11b,	'&'
	je		.FHV_NO
	cmp		r11b,	13
	je		.FHV_NO
	cmp		r11b,	10
	je		.FHV_NO
	mov		rax,	1
	ret

.FHV_NEXT:
	inc		r8
	jmp		.FHV_SCAN

.FHV_NO:
	xor		rax,	rax
	ret

# 4. PATH_EQ_SPACE(path_ptr=rdi, literal_ptr=rsi, len=rdx)
#
# Checks whether the request path starts with a specific character
# and that it is immediately followed by a space
#
# Returns: rax = 1 (match) OR 0 (no match)
PATH_EQ_SPACE:
	xor		rcx,	rcx
.PEQ_LOOP:
	cmp		rcx,	rdx
	je		.PEQ_TERM
	mov		r8b,	byte ptr [rdi+rcx]
	mov		r9b,	byte ptr [rsi+rcx]
	cmp		r8b,	r9b
	jne		.PEQ_NO
	inc		rcx
	jmp		.PEQ_LOOP

.PEQ_TERM:
	cmp byte ptr [rdi+rdx], ' '
	jne		.PEQ_NO
	mov		rax,	1
	ret

.PEQ_NO:
	xor		rax,	rax
	ret

# 5. FORM_VALUE_EQ(body_ptr=rdi, body_len=rsi, key_ptr=rdx, key_len=rcx, expected_ptr=r8, expected_len=r9)
#
# Finds key in form body, extracts its value (terminated by '&', CR, LF, or end of body),
# and checks it exactly matches the expected value
# Returns: rax = 1 (match) OR 0 (no match / key missing)
FORM_VALUE_EQ:
	xor		r10,	r10		# start index in body
.FVE_SCAN:
	cmp		r10,	rsi
	jae		.FVE_NO

	# ensure enough remaining bytes for key comparison
	mov		rbx,	rsi
	sub		rbx,	r10
	cmp		rbx,	rcx
	jb		.FVE_NO

	# compare key bytes from body[r10 + i] with key[i]
	xor		r11,	r11
.FVE_KEYCMP:
	cmp		r11,	rcx
	je		.FVE_KEY_MATCH
	lea		rax,	[rdi+r10]
	mov		bl,	byte ptr [rax+r11]
	cmp		bl,	byte ptr [rdx+r11]
	jne		.FVE_NEXT
	inc		r11
	jmp		.FVE_KEYCMP

.FVE_KEY_MATCH:
	# value starts right after the key; scan forward for its end
	lea		r10,	[r10+rcx]	# r10 = value start index
	mov		rbx,	r10		# rbx = scan index
.FVE_VALSCAN:
	cmp		rbx,	rsi
	jae		.FVE_VALEND
	mov		al,	byte ptr [rdi+rbx]
	cmp		al,	'&'
	je		.FVE_VALEND
	cmp		al,	13
	je		.FVE_VALEND
	cmp		al,	10
	je		.FVE_VALEND
	inc		rbx
	jmp		.FVE_VALSCAN

.FVE_VALEND:
	# rbx = value end index, r10 = value start index
	sub		rbx,	r10		# rbx = value length
	cmp		rbx,	r9		# compare against expected_len
	jne		.FVE_NO

	# byte-for-byte compare value against expected
	xor		r11,	r11
.FVE_VALCMP:
	cmp		r11,	r9
	je		.FVE_YES
	lea		rax,	[rdi+r10]
	mov		al,	byte ptr [rax+r11]
	cmp		al,	byte ptr [r8+r11]
	jne		.FVE_NO
	inc		r11
	jmp		.FVE_VALCMP

.FVE_YES:
	mov		rax,	1
	ret

.FVE_NEXT:
	inc		r10
	jmp		.FVE_SCAN

.FVE_NO:
	xor		rax,	rax
	ret
