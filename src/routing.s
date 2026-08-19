.intel_syntax noprefix

.global	ROUTE

.extern	PATH_EQ_SPACE
.extern	FORM_HAS_VALUE
.extern	FORM_VALUE_EQ

.extern	RESP_OK
.extern	RESP_BAD_REQUEST
.extern	RESP_NOT_FOUND
.extern	RESP_METHOD_NOT_ALLOWED
.extern	RESP_NOT_IMPLEMENTED
.extern	RESP_LOGIN_OK
.extern	RESP_UNAUTHORIZED
.extern	RESP_LOGOUT_OK
.extern	RESP_SERVICE_UNAVAILABLE

.extern	SESSION_CREATE
.extern	SESSION_FIND
.extern	SESSION_INVALIDATE
.extern	EXTRACT_COOKIE_TOKEN
.extern	LOGOUT_TOKEN_SCRATCH

.extern	REQ_BUF
.extern	REQ_BYTES

.section .rodata
### Currently configured endpoints
#==================
PATH_HEALTH:	.ascii	"/health"
PATH_LOGIN:	.ascii	"/login"
PATH_FILES:	.ascii	"/files"
PATH_LOGOUT:	.ascii	"/logout"
FORM_USERNAME_KEY:	.ascii	"username="
FORM_PASSWORD_KEY:	.ascii	"password="
LOGIN_USER:	.ascii	"admin"
LOGIN_PASS:	.ascii	"password123"
###################

### Endpoints' path lengths
#==================
.set 	PATH_HEALTH_LEN,	7
.set 	PATH_LOGIN_LEN,		6
.set 	PATH_FILES_LEN,		6
.set 	PATH_LOGOUT_LEN,	7
.set 	FORM_USERNAME_KEY_LEN,	9
.set 	FORM_PASSWORD_KEY_LEN,	9
.set 	LOGIN_USER_LEN,		5
.set 	LOGIN_PASS_LEN,		11
###################

.section .text
#===============================================#
#		   Routing			#
#===============================================#
ROUTE:
	// /health => GET only
	mov		rdi,	r14
	lea		rsi,	[rip+PATH_HEALTH]
	mov		rdx,	PATH_HEALTH_LEN
	call		PATH_EQ_SPACE
	cmp		rax,	1
	jne		CHECK_LOGIN
	cmp		r15,	1
	jne		RESP_METHOD_NOT_ALLOWED
	jmp		RESP_OK

CHECK_LOGIN:
	mov		rdi,	r14
	lea		rsi,	[rip+PATH_LOGIN]
	mov		rdx,	PATH_LOGIN_LEN
	call		PATH_EQ_SPACE
	cmp		rax,	1
	jne		CHECK_FILES
	cmp		r15,	2
	jne		RESP_METHOD_NOT_ALLOWED	# /login currently supports POST only
	cmp		r11,	0
	jle		RESP_BAD_REQUEST		# POST /login requires valid/non-empty Content-Length

	# ensure request buffer currently contains full body bytes
	lea		r9,	[rip+REQ_BUF]
	add		r9,	qword ptr [rip+REQ_BYTES]
	sub		r9,	r10
	cmp		r11,	r9
	jg		RESP_BAD_REQUEST

	# validate: username=<value> exists in POST body
	mov		rdi,	r10		# body_ptr
	mov		rsi,	r11		# body_len (Content-Length)
	lea		rdx,	[rip+FORM_USERNAME_KEY]
	mov		rcx,	FORM_USERNAME_KEY_LEN
	push		r10		# preserve body_ptr across helper call
	push		r11		# preserve Content-Length across helper call
	call		FORM_HAS_VALUE
	pop		r11
	pop		r10
	cmp		rax,	1
	jne		RESP_BAD_REQUEST

	# validate: password=<value> exists in POST body
	mov		rdi,	r10		# body_ptr
	mov		rsi,	r11		# body_len (Content-Length)
	lea		rdx,	[rip+FORM_PASSWORD_KEY]
	mov		rcx,	FORM_PASSWORD_KEY_LEN
	push		r10		# preserve body_ptr across helper call
	push		r11		# preserve Content-Length across helper call
	call		FORM_HAS_VALUE
	pop		r11
	pop		r10
	cmp		rax,	1
	jne		RESP_BAD_REQUEST

	# validate: username value matches configured credential
	mov		rdi,	r10		# body_ptr
	mov		rsi,	r11		# body_len (Content-Length)
	lea		rdx,	[rip+FORM_USERNAME_KEY]
	mov		rcx,	FORM_USERNAME_KEY_LEN
	lea		r8,	[rip+LOGIN_USER]
	mov		r9,	LOGIN_USER_LEN
	push		r10		# preserve body_ptr across helper call
	push		r11		# preserve Content-Length across helper call
	call		FORM_VALUE_EQ
	pop		r11
	pop		r10
	cmp		rax,	1
	jne		RESP_UNAUTHORIZED

	# validate: password value matches configured credential
	mov		rdi,	r10		# body_ptr
	mov		rsi,	r11		# body_len (Content-Length)
	lea		rdx,	[rip+FORM_PASSWORD_KEY]
	mov		rcx,	FORM_PASSWORD_KEY_LEN
	lea		r8,	[rip+LOGIN_PASS]
	mov		r9,	LOGIN_PASS_LEN
	push		r10		# preserve body_ptr across helper call
	push		r11		# preserve Content-Length across helper call
	call		FORM_VALUE_EQ
	pop		r11
	pop		r10
	cmp		rax,	1
	jne		RESP_UNAUTHORIZED

	# password matched - issue a new session before responding
	call		SESSION_CREATE
	cmp		rax,	0
	je		RESP_SERVICE_UNAVAILABLE	# session table full
	jmp		RESP_LOGIN_OK

CHECK_FILES:
	mov		rdi,	r14
	lea		rsi,	[rip+PATH_FILES]
	mov		rdx,	PATH_FILES_LEN
	call		PATH_EQ_SPACE
	cmp		rax,	1
	jne		CHECK_LOGOUT
	jmp		RESP_NOT_IMPLEMENTED

CHECK_LOGOUT:
	mov		rdi,	r14
	lea		rsi,	[rip+PATH_LOGOUT]
	mov		rdx,	PATH_LOGOUT_LEN
	call		PATH_EQ_SPACE
	cmp		rax,	1
	jne		RESP_NOT_FOUND
	cmp		r15,	2
	jne		RESP_METHOD_NOT_ALLOWED	# /logout currently supports POST only

	# extract session token from the Cookie header
	lea		rdi,	[rip+REQ_BUF]
	mov		rsi,	r10		# header-end ptr, still valid here
	lea		rdx,	[rip+LOGOUT_TOKEN_SCRATCH]
	call		EXTRACT_COOKIE_TOKEN
	cmp		rax,	1
	jne		RESP_UNAUTHORIZED		# no Cookie header / no session= / wrong length

	# look up token in the session table
	lea		rdi,	[rip+LOGOUT_TOKEN_SCRATCH]
	mov		rsi,	32
	call		SESSION_FIND
	cmp		rax,	0
	je		RESP_UNAUTHORIZED		# token not recognized / already invalidated

	# rax = matching slot pointer; invalidate it
	mov		rdi,	rax
	call		SESSION_INVALIDATE

	jmp		RESP_LOGOUT_OK
