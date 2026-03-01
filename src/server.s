.intel_syntax noprefix
.global _start

#===============================================#
#		HTTP Status Codes		#
#===============================================#
.section .rodata
RESP_200:
	.ascii	"HTTP/1.1 200 OK\r\n"
	.ascii	"Content-Length: 3\r\n"
	.ascii	"Connection: close\r\n"
	.ascii	"\r\n"
	.ascii	"OK\n"
RESP_200_END:

.set 	RESP_200_LEN, 	RESP_200_END - RESP_200

.section .text
_start:

#===============================================#
#		SOCKET CALL (41)		#
#===============================================#
SOCK:	// Socket call
	// socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
	mov 		rdi, 	2		# AF_INET 	= 2 (defined)
	mov 		rsi, 	1		# SOCK_STREAM 	= 1 (widely used default)
	mov 		rdx, 	0		# IPPROTO_IP 	= 0 (common default)
	mov 		rax, 	41		# syscall ID for socket call
	syscall
	mov		r12, 	rax		# Listening socket 	(r12, r13 => callee-saved register)


#===============================================#
#		BIND CALL (49)			#
#===============================================#
BIND:	// Bind call
	// bind(FD, *SOCKADDR_IN, sizeof(SOCKADDR_IN))
	// where,
	// struct SOCKADDR_IN {sa_family, sin_port, sin_addr, sin_zero}
SK_FD:	mov		rdi, 	r12		# set listening socket [FD (File descriptor) from socket call]
SK_ADRb:sub 		rsp, 	16		# Reserve 16 bytes for SOCKADDR_IN struct
	mov word ptr 	[rsp], 	2		# sa_family = AF_INET = 2		(2 bytes)
	mov word ptr 	[rsp+2],0x901f		# sin_port = 8080			(2 bytes)
	mov dword ptr 	[rsp+4],0x0100007f	# sin_addr = INADDR_ANY = 127.0.0.1	(4 bytes)
	mov qword ptr 	[rsp+8],0		# sin_zero (padding bytes)		(8 bytes)
	mov 		rsi, 	rsp		# input SOCKADDR_IN struct			Total = 16 bytes
SK_LENb:mov		rdx, 	16		# struct SOCKADDR_IN size is fixed 16 bytes
	mov		rax, 	49		# syscall ID for bind call
	syscall


#===============================================#
#		LISTEN CALL (50)		#
#===============================================#
LISTEN: // Listen call
	// listen(SOCKFD, BACKLOG)
	// rdi (SOCKFD) uses FD value from socket call
	mov 		rdi, 	r12		# Use listening socket
	mov		rsi, 	4096		# BACKLOG value (old linux => 128, new linux => 4096)
						# No. of fully est. conns. waiting to be accepted
						# Excessive no. of conns. => Dropping of connections
	mov		rax, 	50		# syscall ID for listen call
	syscall


#===============================================#
#		ACCEPT CALL (43)		#
#===============================================#
ACCEPT: // Accept call
	// accept(SOCKFD, *SOCKADDR, *sizeof(SOCKADDR))
	// where,
	// struct SOCKADDR {sa_family[2 bytes], sa_data[14 bytes]}
	// NOTE: we need a pointer to the length of SOCKADDR
	sub		rsp, 	32		# Reserve enough space for *SOCKADDR [16B] + *sizeof(...) [4B]
SK_LENa:mov dword ptr [rsp+16], 16
	mov		rdi, 	r12		# Use listening socket [FD (File descriptor) from socket call]

	// TODO: Enable logging
	// CURRENT: accept(3, NULL, NULL)
	// 	- NULL#1 => Donot store client IP address		[ 127.0.0.1 | LAN | ?? ]
	//	- NULL#2 => Donot store client IP address length
SK_ADRa:xor 		rsi, 	rsi		# SOCKADDR buffer
	xor		rdx, 	rdx		# pointer to sizeof(SOCKADDR)
	mov		rax, 	43		# syscall ID for accept call
	syscall
	// After this syscall
	// rax will contain the new client socket FD
	mov 		r13, 	rax		# Client Socket 	(Callee-saved register)

#===============================================#
#		WRITE CALL (1)			#
#===============================================#
WRITE:	// Send HTTP 200 response to client socket
	// write(client_fd, response, response_len)
	mov		rdi,	r13		# client socket fd
	lea		rsi,	[rip+RESP_200]	# Response buffer
	mov		rdx, 	RESP_200_LEN	# Response length
	mov 		rax, 	1		# sys_write
	syscall
	jmp		ACCEPT			# loop forever: accept next connection

#===============================================#
#		CLOSE CALL (6)			#
#===============================================#
CLOSE:	// Close client syscall
	mov		rdi, 	r13		# client socket fd
	mov 		rax, 	3		# sys_close
	syscall

#===============================================#
#		EXIT CALL (60)			#
#===============================================#
EXIT:	// Server exit syscall
	mov		rdi, 	0		# code 0 (success)
	mov 		rax, 	60		# sys_exit
	syscall
