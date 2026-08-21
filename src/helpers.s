.intel_syntax noprefix

.global	REQ_BUF
.global	FIND_HDR_END
.global	PARSE_CONTENT_LENGTH
.global	PATH_EQ_SPACE
.global	FORM_HAS_VALUE
.global	FORM_VALUE_EQ
.global	HEX_ENCODE
.global	EXTRACT_COOKIE_TOKEN
.global	FORM_EXTRACT_VALUE
.global	DEC_ENCODE

.section .rodata
CONTENT_LENGTH_KEY:	.ascii	"Content-Length:"
HEX_DIGITS:		.ascii	"0123456789abcdef"
COOKIE_KEY:		.ascii	"Cookie:"
SESSION_KEY:		.ascii	"session="
.set	COOKIE_KEY_LEN,		7
.set	SESSION_KEY_LEN,	8

.section .bss
#===============================================#
#		Request Buffer (.bss)		#
#===============================================#
	.lcomm	REQ_BUF, 4096
	.lcomm	DEC_SCRATCH, 32			# backwards digit buffer for DEC_ENCODE

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

# 6. HEX_ENCODE(src_ptr=rdi, src_len=rsi, dst_ptr=rdx)
#
# Encodes src_len raw bytes into 2*src_len lowercase ASCII hex chars at dst_ptr
# Returns: none (writes 2*src_len bytes to [dst_ptr])
HEX_ENCODE:
	lea		r8,	[rip+HEX_DIGITS]
	xor		rcx,	rcx		# src byte index
	xor		r9,	r9		# dst char index
.HE_LOOP:
	cmp		rcx,	rsi
	jge		.HE_DONE
	mov		al,	byte ptr [rdi+rcx]
	mov		r10b,	al
	shr		r10b,	4		# high nibble
	movzx		r10,	r10b
	mov		al,	byte ptr [r8+r10]
	mov		byte ptr [rdx+r9],	al
	inc		r9
	mov		al,	byte ptr [rdi+rcx]
	and		al,	0x0f		# low nibble
	movzx		r10,	al
	mov		al,	byte ptr [r8+r10]
	mov		byte ptr [rdx+r9],	al
	inc		r9
	inc		rcx
	jmp		.HE_LOOP

.HE_DONE:
	ret

# 7. EXTRACT_COOKIE_TOKEN(req_start=rdi, hdr_end_ptr=rsi, out_ptr=rdx)
#
# Scans headers line by line for "Cookie:" (first match only). Within that
# line, scans for "session=" and extracts its value, terminated by ';',
# CR, LF, or end of headers. If the extracted value is exactly 32 bytes,
# copies it to [out_ptr].
# Returns: rax = 1 (32-byte token copied to [out_ptr]) OR 0 (no Cookie
# header / no session= key / value length != 32)
EXTRACT_COOKIE_TOKEN:
	mov		r8,	rdi		# line-scan pointer
.ECT_LINE_SCAN:
	cmp		r8,	rsi
	jae		.ECT_NOTFOUND

	mov		r9,	rsi
	sub		r9,	r8
	cmp		r9,	COOKIE_KEY_LEN
	jb		.ECT_NEXT_LINE

	xor		rcx,	rcx
	lea		rbx,	[rip+COOKIE_KEY]
.ECT_KEYCMP:
	cmp		rcx,	COOKIE_KEY_LEN
	je		.ECT_LINE_FOUND
	mov		al,	byte ptr [r8+rcx]
	cmp		al,	byte ptr [rbx+rcx]
	jne		.ECT_NEXT_LINE
	inc		rcx
	jmp		.ECT_KEYCMP

.ECT_LINE_FOUND:
	lea		r8,	[r8+COOKIE_KEY_LEN]
.ECT_SKIP_SP:
	cmp		r8,	rsi
	jae		.ECT_NOTFOUND
	cmp byte ptr	[r8],	' '
	jne		.ECT_FIND_SESSION
	inc		r8
	jmp		.ECT_SKIP_SP

.ECT_FIND_SESSION:
	mov		r10,	r8		# session-key scan index
.ECT_SESS_SCAN:
	cmp		r10,	rsi
	jae		.ECT_NOTFOUND
	cmp byte ptr	[r10],	13
	je		.ECT_NOTFOUND
	cmp byte ptr	[r10],	10
	je		.ECT_NOTFOUND

	mov		r9,	rsi
	sub		r9,	r10
	cmp		r9,	SESSION_KEY_LEN
	jb		.ECT_SESS_NEXT

	xor		rcx,	rcx
	lea		rbx,	[rip+SESSION_KEY]
.ECT_SESS_KEYCMP:
	cmp		rcx,	SESSION_KEY_LEN
	je		.ECT_SESS_MATCH
	mov		al,	byte ptr [r10+rcx]
	cmp		al,	byte ptr [rbx+rcx]
	jne		.ECT_SESS_NEXT
	inc		rcx
	jmp		.ECT_SESS_KEYCMP

.ECT_SESS_NEXT:
	inc		r10
	jmp		.ECT_SESS_SCAN

.ECT_SESS_MATCH:
	lea		r10,	[r10+SESSION_KEY_LEN]	# value start
	mov		r11,	r10			# value-end scan index
.ECT_VAL_SCAN:
	cmp		r11,	rsi
	jae		.ECT_VAL_END
	mov		al,	byte ptr [r11]
	cmp		al,	';'
	je		.ECT_VAL_END
	cmp		al,	13
	je		.ECT_VAL_END
	cmp		al,	10
	je		.ECT_VAL_END
	inc		r11
	jmp		.ECT_VAL_SCAN

.ECT_VAL_END:
	mov		r9,	r11
	sub		r9,	r10			# value length
	cmp		r9,	32
	jne		.ECT_NOTFOUND

	mov		rdi,	rdx			# out_ptr (original req_start is
							# already dead - r8 holds the scan state)
	mov		rsi,	r10
	mov		rcx,	32
	cld
	rep		movsb
	mov		rax,	1
	ret

.ECT_NEXT_LINE:
.ECT_EOL:
	cmp		r8,	rsi
	jae		.ECT_NOTFOUND
	cmp byte ptr	[r8],	10
	je		.ECT_ADV
	inc		r8
	jmp		.ECT_EOL
.ECT_ADV:
	inc		r8
	jmp		.ECT_LINE_SCAN

.ECT_NOTFOUND:
	xor		rax,	rax
	ret

# 8. FORM_EXTRACT_VALUE(body_ptr=rdi, body_len=rsi, key_ptr=rdx, key_len=rcx)
#
# Finds key in form body and returns a pointer to its value (terminated by
# '&', CR, LF, or end of body), without copying or comparing it. Unlike
# FORM_HAS_VALUE/FORM_VALUE_EQ, this hands back the raw value so callers
# can consume arbitrary-length submitted data (e.g. registration fields).
# Returns: rax = value pointer (0 if key missing), rbx = value length
FORM_EXTRACT_VALUE:
	xor		r10,	r10		# start index in body
.FEV_SCAN:
	cmp		r10,	rsi
	jae		.FEV_NO

	mov		rbx,	rsi
	sub		rbx,	r10
	cmp		rbx,	rcx
	jb		.FEV_NO

	xor		r11,	r11
.FEV_KEYCMP:
	cmp		r11,	rcx
	je		.FEV_KEY_MATCH
	lea		rax,	[rdi+r10]
	mov		bl,	byte ptr [rax+r11]
	cmp		bl,	byte ptr [rdx+r11]
	jne		.FEV_NEXT
	inc		r11
	jmp		.FEV_KEYCMP

.FEV_KEY_MATCH:
	lea		r10,	[r10+rcx]	# r10 = value start index
	mov		rbx,	r10		# rbx = value-end scan index
.FEV_VALSCAN:
	cmp		rbx,	rsi
	jae		.FEV_VALEND
	mov		al,	byte ptr [rdi+rbx]
	cmp		al,	'&'
	je		.FEV_VALEND
	cmp		al,	13
	je		.FEV_VALEND
	cmp		al,	10
	je		.FEV_VALEND
	inc		rbx
	jmp		.FEV_VALSCAN

.FEV_VALEND:
	lea		rax,	[rdi+r10]	# rax = value pointer
	sub		rbx,	r10		# rbx = value length
	ret

.FEV_NEXT:
	inc		r10
	jmp		.FEV_SCAN

.FEV_NO:
	xor		rax,	rax
	xor		rbx,	rbx
	ret

# 9. DEC_ENCODE(value=rdi, dst=rsi)
#
# Writes the unsigned decimal ASCII representation of value at dst
# (up to 20 digits). Used to build dynamic Content-Length headers.
# Returns: rax = number of digits written
DEC_ENCODE:
	push		rbx
	mov		rax,	rdi
	lea		r8,	[rip+DEC_SCRATCH]
	lea		rcx,	[r8+32]			# fill digits backwards from the end
.DEC_SPLIT:
	xor		edx,	edx
	mov		rbx,	10
	div		rbx				# rax = quotient, rdx = remainder
	add		dl,	'0'
	dec		rcx
	mov		[rcx],	dl
	cmp		rax,	0
	jne		.DEC_SPLIT

	lea		r11,	[r8+32]
	xor		r9,	r9			# digits copied so far
.DEC_COPY:
	cmp		rcx,	r11
	jae		.DEC_DONE
	mov		al,	byte ptr [rcx]
	mov		[rsi+r9], al
	inc		r9
	inc		rcx
	jmp		.DEC_COPY

.DEC_DONE:
	mov		rax,	r9
	pop		rbx
	ret
