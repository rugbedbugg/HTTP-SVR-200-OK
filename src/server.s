.intel_syntax noprefix
.global _start



#===============================================#
#	 	  Read-Only Data		#
#===============================================#
.section .rodata

### HTTP Status Codes
#==================
# 1. Status 200: OK
RESP_200:
	.ascii	"HTTP/1.1 200 OK\r\n"
	.ascii	"Content-Length: 3\r\n"
	.ascii	"Connection: close\r\n"
	.ascii	"\r\n"
	.ascii	"OK\n"
RESP_200_END:
#==================
# 2. Status 400: Bad Request
RESP_400:
	.ascii	"HTTP/1.1 400 Bad Request\r\n"
	.ascii	"Content-Length: 12\r\n"
	.ascii	"Connection: close\r\n"
	.ascii	"\r\n"
	.ascii	"Bad Request\n"
RESP_400_END:
#==================
# 3. Status 404: Not Found
RESP_404:
	.ascii	"HTTP/1.1 404 Not Found\r\n"
	.ascii	"Content-Length: 10\r\n"
	.ascii	"Connection: close\r\n"
	.ascii	"\r\n"
	.ascii	"Not Found\n"
RESP_404_END:
#==================
# 4. Status 405: Method Not Allowed
RESP_405:
	.ascii	"HTTP/1.1 405 Method Not Allowed\r\n"
	.ascii	"Content-Length: 19\r\n"
	.ascii	"Connection: close\r\n"
	.ascii	"\r\n"
	.ascii	"Method Not Allowed\n"
RESP_405_END:
#==================
# 5. Status 501: Not implemented
RESP_501:
	.ascii	"HTTP/1.1 501 Not Implemented\r\n"
	.ascii	"Content-Length: 5\r\n"
	.ascii	"Connection: close\r\n"
	.ascii	"\r\n"
	.ascii	"TODO\n"
RESP_501_END:
###################

### Currently configured endpoints
#==================
PATH_HEALTH:	.ascii	"/health"
PATH_LOGIN:	.ascii	"/login"
PATH_FILES:	.ascii	"/files"
PATH_LOGOUT:	.ascii	"/logout"
###################

### Calculate & store endpoint path length
#==================
.set 	RESP_200_LEN,	RESP_200_END - RESP_200
.set 	RESP_400_LEN,	RESP_400_END - RESP_400
.set 	RESP_404_LEN,	RESP_404_END - RESP_404
.set 	RESP_405_LEN,	RESP_405_END - RESP_405
.set 	RESP_501_LEN,	RESP_501_END - RESP_501
###################

### Endpoints' path lengths
#==================
.set 	PATH_HEALTH_LEN,	7
.set 	PATH_LOGIN_LEN,		6
.set 	PATH_FILES_LEN,		6
.set 	PATH_LOGOUT_LEN,	7
###################

#===============================================#
#		Request Buffer			#
#===============================================#
.section .bss
	.lcomm	REQ_BUF, 4096




.section .text
_start:
#===============================================#
#		SOCKET CALL (41)		#
#===============================================#
SOCK:	// socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
	mov 		rdi,	2		# AF_INET
	mov 		rsi,	1		# SOCK_STREAM
	mov 		rdx,	0		# IPPROTO_IP
	mov 		rax,	41		# sys_socket
	syscall
	mov		r12,	rax		# Listening socket FD


#===============================================#
#		BIND CALL (49)			#
#===============================================#
BIND:	// bind(FD, *SOCKADDR_IN, sizeof(SOCKADDR_IN))
SK_FD:	mov		rdi,	r12		# Listening socket FD
SK_ADRb:	sub 		rsp,	16		# Reserve SOCKADDR_IN (16B)
	mov word ptr 	[rsp],	2		# AF_INET
	mov word ptr 	[rsp+2],0x901f		# sin_port = 8080
	mov dword ptr 	[rsp+4],0x00000000	# sin_addr = 0.0.0.0 (INADDR_ANY)
	mov qword ptr 	[rsp+8],0		# sin_zero
	mov 		rsi,	rsp		# *SOCKADDR_IN
SK_LENb:mov		rdx,	16		# sizeof(SOCKADDR_IN)
	mov		rax,	49		# sys_bind
	syscall


#===============================================#
#		LISTEN CALL (50)		#
#===============================================#
LISTEN:	// listen(SOCKFD, BACKLOG)
	mov 		rdi,	r12		# Listening socket FD
	mov		rsi,	4096		# BACKLOG
	mov		rax,	50		# sys_listen
	syscall


#===============================================#
#		ACCEPT CALL (43)		#
#===============================================#
ACCEPT:	// accept(SOCKFD, NULL, NULL)
	sub		rsp,	32		# keep stack room style-consistent with previous layout
SK_LENa:mov dword ptr [rsp+16], 16
	mov		rdi,	r12		# Listening socket FD
SK_ADRa:xor 		rsi,	rsi		# NULL SOCKADDR
	xor		rdx,	rdx		# NULL SOCKADDR length ptr
	mov		rax,	43		# sys_accept
	syscall
	cmp		rax,	0
	jl		ACCEPT			# if accept fails, retry
	mov 		r13,	rax		# Client socket FD


#===============================================#
#		READ CALL (0)			#
#===============================================#
READ_REQ:	// read(client_fd, REQ_BUF, 4096)
	mov		rdi,	r13
	lea		rsi,	[rip+REQ_BUF]
	mov		rdx,	4096
	mov		rax,	0		# sys_read
	syscall
	cmp		rax,	0
	jle		CLOSE			# closed/error => close client, continue accept loop


#===============================================#
#	     	Request Parsing			#
#===============================================#
PARSE:	// parse METHOD + PATH from request line
	lea		rbx,	[rip+REQ_BUF]

GET_CHECK:
	cmp byte ptr 	[rbx], 		'G'
	jne		POST_CHECK
	cmp byte ptr 	[rbx+1], 	'E'
	jne		POST_CHECK
	cmp byte ptr 	[rbx+2], 	'T'
	jne		POST_CHECK
	cmp byte ptr [rbx+3], 		' '
	jne		POST_CHECK
	lea		r14,	[rbx+4]		# PATH pointer (after "GET ")
	mov		r15,	1		# METHOD ID: GET
	jmp		ROUTE

POST_CHECK:
	cmp byte ptr 	[rbx], 		'P'
	jne		RESP_METHOD_NOT_ALLOWED
	cmp byte ptr 	[rbx+1], 	'O'
	jne		RESP_METHOD_NOT_ALLOWED
	cmp byte ptr 	[rbx+2], 	'S'
	jne		RESP_METHOD_NOT_ALLOWED
	cmp byte ptr 	[rbx+3], 	'T'
	jne		RESP_METHOD_NOT_ALLOWED
	cmp byte ptr 	[rbx+4], 	' '
	jne		RESP_METHOD_NOT_ALLOWED	# Check for "POST " in the HTTP request, if not, return

	lea		r14,	[rbx+5]		# PATH pointer (after "POST ")
	mov		r15,	2		# METHOD ID: POST


#===============================================#
#	  HTTP Header Boundary Parsing		#
#===============================================#
HDR_BOUNDARY: // find "\r\n\r\n" delimiter in current request buffer
	lea		rdi,	[rip+REQ_BUF]	# request buffer ptr
	mov		rsi,	rax		# bytes_read from READ_REQ
	call		FIND_HDR_END
	cmp		rax,	0
	jl		RESP_BAD_REQUEST		# malformed/incomplete header => 400
	lea		r10,	[rdi+rax]		# r10 points to first byte after "\r\n\r\n"


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
	jmp		RESP_NOT_IMPLEMENTED

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
	jmp		RESP_NOT_IMPLEMENTED


#===============================================#
#		WRITE CALL (1)			#
#===============================================#
RESP_OK:					// What to response if HTTP request is good
	mov		rdi,	r13
	lea		rsi,	[rip+RESP_200]
	mov		rdx,	RESP_200_LEN
	jmp		WRITE

RESP_BAD_REQUEST:				// What to respond if request format is malformed
	mov		rdi,	r13
	lea		rsi,	[rip+RESP_400]
	mov		rdx,	RESP_400_LEN
	jmp		WRITE

RESP_NOT_FOUND:					// What to respond if HTTP request method is invalid
	mov		rdi,	r13
	lea		rsi,	[rip+RESP_404]
	mov		rdx,	RESP_404_LEN
	jmp		WRITE

RESP_METHOD_NOT_ALLOWED:			// What to respond if HTTP request method is not allowed
	mov		rdi,	r13
	lea		rsi,	[rip+RESP_405]
	mov		rdx,	RESP_405_LEN
	jmp		WRITE

RESP_NOT_IMPLEMENTED:				// What is respond if HTTP request method hasnt been implemented yet
	mov		rdi,	r13
	lea		rsi,	[rip+RESP_501]
	mov		rdx,	RESP_501_LEN

WRITE:	// write(client_fd, response, response_len)
	mov 		rax,	1		# sys_write
	syscall


#===============================================#
#		CLOSE CALL (3)			#
#===============================================#
CLOSE:	// close(client_fd)
	mov		rdi,	r13
	mov 		rax,	3		# sys_close
	syscall
	jmp		ACCEPT			# loop forever


#===============================================#
#		EXIT CALL (60)			#
#===============================================#
EXIT:	// Server exit syscall
	mov		rdi,	0
	mov 		rax,	60		# sys_exit
	syscall


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

# 2. PATH_EQ_SPACE(path_ptr=rdi, literal_ptr=rsi, len=rdx)
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
