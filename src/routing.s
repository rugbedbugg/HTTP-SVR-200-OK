.intel_syntax noprefix

.global	ROUTE

.extern	PATH_EQ_SPACE
.extern	FORM_HAS_VALUE
.extern	FORM_VALUE_EQ
.extern	FORM_EXTRACT_VALUE

.extern	RESP_OK
.extern	RESP_BAD_REQUEST
.extern	RESP_NOT_FOUND
.extern	RESP_METHOD_NOT_ALLOWED
.extern	RESP_NOT_IMPLEMENTED
.extern	RESP_LOGIN_OK
.extern	RESP_UNAUTHORIZED
.extern	RESP_LOGOUT_OK
.extern	RESP_SERVICE_UNAVAILABLE
.extern	RESP_REGISTER_OK
.extern	RESP_USERNAME_TAKEN
.extern	RESP_USER_TABLE_FULL

.extern	SESSION_CREATE
.extern	SESSION_FIND
.extern	SESSION_INVALIDATE
.extern	EXTRACT_COOKIE_TOKEN
.extern	LOGOUT_TOKEN_SCRATCH

.extern	USER_CREATE
.extern	USER_FIND

.extern	REQ_BUF
.extern	REQ_BYTES

.section .rodata
### Currently configured endpoints
#==================
PATH_HEALTH:	.ascii	"/health"
PATH_LOGIN:	.ascii	"/login"
PATH_REGISTER:	.ascii	"/register"
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
.set 	PATH_REGISTER_LEN,	9
.set 	PATH_FILES_LEN,		6
.set 	PATH_LOGOUT_LEN,	7
.set 	FORM_USERNAME_KEY_LEN,	9
.set 	FORM_PASSWORD_KEY_LEN,	9
.set 	LOGIN_USER_LEN,		5
.set 	LOGIN_PASS_LEN,		11
.set	USERNAME_MAX_LEN,	32
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
	jne		CHECK_REGISTER
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
	jne		TRY_DYNAMIC_LOGIN

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
	jne		TRY_DYNAMIC_LOGIN

	# password matched - issue a new session before responding
	call		SESSION_CREATE
	cmp		rax,	0
	je		RESP_SERVICE_UNAVAILABLE	# session table full
	jmp		RESP_LOGIN_OK

TRY_DYNAMIC_LOGIN:
	# hardcoded admin credentials didn't match - fall back to the
	# registered-user table before giving up
	push		r10		# preserve body_ptr across helper call
	push		r11		# preserve Content-Length across helper call
	mov		rdi,	r10
	mov		rsi,	r11
	lea		rdx,	[rip+FORM_USERNAME_KEY]
	mov		rcx,	FORM_USERNAME_KEY_LEN
	call		FORM_EXTRACT_VALUE
	pop		r11
	pop		r10
	cmp		rax,	0
	je		RESP_UNAUTHORIZED		# defensive: FORM_HAS_VALUE already guarantees this
	mov		r8,	rax			# r8 = username_ptr
	mov		r9,	rbx			# r9 = username_len

	push		r10		# preserve body_ptr across helper call
	push		r11		# preserve Content-Length across helper call
	mov		rdi,	r10
	mov		rsi,	r11
	lea		rdx,	[rip+FORM_PASSWORD_KEY]
	mov		rcx,	FORM_PASSWORD_KEY_LEN
	call		FORM_EXTRACT_VALUE
	pop		r11
	pop		r10
	cmp		rax,	0
	je		RESP_UNAUTHORIZED		# defensive: FORM_HAS_VALUE already guarantees this

	mov		rdi,	r8			# username_ptr
	mov		rsi,	r9			# username_len
	mov		rdx,	rax			# password_ptr
	mov		rcx,	rbx			# password_len
	call		USER_FIND
	cmp		rax,	1
	jne		RESP_UNAUTHORIZED

	# registered user matched - issue a new session before responding
	call		SESSION_CREATE
	cmp		rax,	0
	je		RESP_SERVICE_UNAVAILABLE	# session table full
	jmp		RESP_LOGIN_OK

CHECK_REGISTER:
	mov		rdi,	r14
	lea		rsi,	[rip+PATH_REGISTER]
	mov		rdx,	PATH_REGISTER_LEN
	call		PATH_EQ_SPACE
	cmp		rax,	1
	jne		CHECK_FILES
	cmp		r15,	2
	jne		RESP_METHOD_NOT_ALLOWED	# /register currently supports POST only
	cmp		r11,	0
	jle		RESP_BAD_REQUEST		# POST /register requires valid/non-empty Content-Length

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

	# extract the submitted username
	push		r10		# preserve body_ptr across helper call
	push		r11		# preserve Content-Length across helper call
	mov		rdi,	r10
	mov		rsi,	r11
	lea		rdx,	[rip+FORM_USERNAME_KEY]
	mov		rcx,	FORM_USERNAME_KEY_LEN
	call		FORM_EXTRACT_VALUE
	pop		r11
	pop		r10
	mov		r8,	rax			# r8 = username_ptr
	mov		r9,	rbx			# r9 = username_len
	cmp		r9,	USERNAME_MAX_LEN
	ja		RESP_BAD_REQUEST		# username longer than the account slot can hold

	# extract the submitted password
	push		r10		# preserve body_ptr across helper call
	push		r11		# preserve Content-Length across helper call
	mov		rdi,	r10
	mov		rsi,	r11
	lea		rdx,	[rip+FORM_PASSWORD_KEY]
	mov		rcx,	FORM_PASSWORD_KEY_LEN
	call		FORM_EXTRACT_VALUE
	pop		r11
	pop		r10

	mov		rdi,	r8			# username_ptr
	mov		rsi,	r9			# username_len
	mov		rdx,	rax			# password_ptr
	mov		rcx,	rbx			# password_len
	call		USER_CREATE
	cmp		rax,	1
	je		RESP_REGISTER_OK
	cmp		rax,	0
	je		RESP_USERNAME_TAKEN
	jmp		RESP_USER_TABLE_FULL		# rax == 2

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
