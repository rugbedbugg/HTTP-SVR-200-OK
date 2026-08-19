.intel_syntax noprefix

.global	RESP_OK
.global	RESP_BAD_REQUEST
.global	RESP_NOT_FOUND
.global	RESP_METHOD_NOT_ALLOWED
.global	RESP_NOT_IMPLEMENTED
.global	RESP_LOGIN_OK
.global	RESP_UNAUTHORIZED

.extern	ACCEPT

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
	.ascii	"Content-Length: 41\r\n"
	.ascii	"Connection: close\r\n"
	.ascii	"\r\n"
	.ascii	"Nope, doesn't exist. Try something else.\n"
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
#==================
# 6. Status 200: Login OK
RESP_200_LOGIN:
	.ascii	"HTTP/1.1 200 OK\r\n"
	.ascii	"Content-Length: 17\r\n"
	.ascii	"Connection: close\r\n"
	.ascii	"\r\n"
	.ascii	"Login successful\n"
RESP_200_LOGIN_END:
#==================
# 7. Status 401: Unauthorized
RESP_401:
	.ascii	"HTTP/1.1 401 Unauthorized\r\n"
	.ascii	"Content-Length: 20\r\n"
	.ascii	"Connection: close\r\n"
	.ascii	"\r\n"
	.ascii	"Invalid credentials\n"
RESP_401_END:
###################

.set 	RESP_200_LEN,	RESP_200_END - RESP_200
.set 	RESP_400_LEN,	RESP_400_END - RESP_400
.set 	RESP_404_LEN,	RESP_404_END - RESP_404
.set 	RESP_405_LEN,	RESP_405_END - RESP_405
.set 	RESP_501_LEN,	RESP_501_END - RESP_501
.set 	RESP_200_LOGIN_LEN,	RESP_200_LOGIN_END - RESP_200_LOGIN
.set 	RESP_401_LEN,	RESP_401_END - RESP_401

.section .text
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
	jmp		WRITE

RESP_LOGIN_OK:					// What to respond if /login credentials are valid
	mov		rdi,	r13
	lea		rsi,	[rip+RESP_200_LOGIN]
	mov		rdx,	RESP_200_LOGIN_LEN
	jmp		WRITE

RESP_UNAUTHORIZED:				// What to respond if /login credentials are invalid
	mov		rdi,	r13
	lea		rsi,	[rip+RESP_401]
	mov		rdx,	RESP_401_LEN

WRITE:	// write(client_fd, response, response_len)
	mov 		rax,	1		# sys_write
	syscall

#===============================================#
#		CLOSE CALL (3)			#
#===============================================#
	mov		rdi,	r13
	mov 		rax,	3		# sys_close
	syscall
	jmp		ACCEPT			# loop forever
