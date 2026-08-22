.intel_syntax noprefix
.global _start
.global ACCEPT
.global REQ_BYTES

.extern	REQ_BUF
.extern	FIND_HDR_END
.extern	PARSE_CONTENT_LENGTH
.extern	ROUTE

.extern	RESP_BAD_REQUEST
.extern	RESP_METHOD_NOT_ALLOWED

.section .bss
	.lcomm	REQ_BYTES, 8

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
	# NOTE: using NULL/NULL so no stack reservation is required here
	mov		rdi,	r12		# Listening socket FD
SK_ADRa:xor 		rsi,	rsi		# NULL SOCKADDR
	xor		rdx,	rdx		# NULL SOCKADDR length ptr
	mov		rax,	43		# sys_accept
	syscall
	mov		qword ptr [rip+REQ_BYTES],	rax
	cmp		rax,	0
	jl		ACCEPT			# if accept fails, retry
	mov 		r13,	rax		# Client socket FD


#===============================================#
#	  SETSOCKOPT CALL (54)		#
#===============================================#
RCV_TIMEOUT:	// setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeval, sizeof(timeval))
	# caps how long a client can stall while sending the request, so a
	# slowloris-style connection can't pin the single-threaded loop forever
	sub		rsp,	16		# struct timeval {tv_sec, tv_usec}
	mov qword ptr	[rsp],	5		# tv_sec = 5s
	mov qword ptr	[rsp+8],0		# tv_usec = 0
	mov		rdi,	r13		# Client socket FD
	mov		rsi,	1		# SOL_SOCKET
	mov		rdx,	20		# SO_RCVTIMEO
	mov		r10,	rsp		# *timeval
	mov		r8,	16		# sizeof(timeval)
	mov		rax,	54		# sys_setsockopt
	syscall
	add		rsp,	16


#===============================================#
#		READ CALL (0)			#
#===============================================#
READ_REQ:	// read(client_fd, REQ_BUF, 4096)
	mov		rdi,	r13
	lea		rsi,	[rip+REQ_BUF]
	mov		rdx,	4096
	mov		rax,	0		# sys_read
	syscall
	mov		qword ptr [rip+REQ_BYTES],	rax
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
	jmp		AFTER_METHOD

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
AFTER_METHOD:
HDR_BOUNDARY: // find "\r\n\r\n" delimiter in current request buffer
	lea		rdi,	[rip+REQ_BUF]	# request buffer ptr
	mov		rsi,	rax		# bytes_read from READ_REQ
	call		FIND_HDR_END
	cmp		rax,	0
	jl		RESP_BAD_REQUEST		# malformed/incomplete header => 400
	lea		r10,	[rdi+rax]		# r10 points to first byte after "\r\n\r\n"


#===============================================#
#	      Header Parsing			#
#===============================================#
HDR_PARSE:	// parse Content-Length (used for POST body validation path)
	lea		rdi,	[rip+REQ_BUF]	# request buffer start
	mov		rsi,	r10		# request header end ptr (exclusive)
	call		PARSE_CONTENT_LENGTH
	mov		r11,	rax		# store parsed Content-Length (-1 if absent/invalid)


#===============================================#
#		   Routing			#
#===============================================#
	jmp		ROUTE


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
