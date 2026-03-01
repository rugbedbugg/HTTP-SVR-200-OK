.intel_syntax noprefix
.global _start

# ===============================================================
# HTTP-SVR-200-OK — Phase 2 kickoff (deep request parsing start)
# - Persistent accept loop
# - Read raw HTTP request bytes
# - Parse method + path
# - Route: /health, /login, /files, /logout, fallback 404
# ===============================================================

.section .rodata
RESP_200:
    .ascii  "HTTP/1.1 200 OK\r\n"
    .ascii  "Content-Length: 3\r\n"
    .ascii  "Connection: close\r\n"
    .ascii  "\r\n"
    .ascii  "OK\n"
RESP_200_END:
.set RESP_200_LEN, RESP_200_END - RESP_200

RESP_404:
    .ascii  "HTTP/1.1 404 Not Found\r\n"
    .ascii  "Content-Length: 10\r\n"
    .ascii  "Connection: close\r\n"
    .ascii  "\r\n"
    .ascii  "Not Found\n"
RESP_404_END:
.set RESP_404_LEN, RESP_404_END - RESP_404

RESP_405:
    .ascii  "HTTP/1.1 405 Method Not Allowed\r\n"
    .ascii  "Content-Length: 19\r\n"
    .ascii  "Connection: close\r\n"
    .ascii  "\r\n"
    .ascii  "Method Not Allowed\n"
RESP_405_END:
.set RESP_405_LEN, RESP_405_END - RESP_405

RESP_501:
    .ascii  "HTTP/1.1 501 Not Implemented\r\n"
    .ascii  "Content-Length: 5\r\n"
    .ascii  "Connection: close\r\n"
    .ascii  "\r\n"
    .ascii  "TODO\n"
RESP_501_END:
.set RESP_501_LEN, RESP_501_END - RESP_501

PATH_HEALTH: .ascii "/health"
.set PATH_HEALTH_LEN, 7
PATH_LOGIN:  .ascii "/login"
.set PATH_LOGIN_LEN, 6
PATH_FILES:  .ascii "/files"
.set PATH_FILES_LEN, 6
PATH_LOGOUT: .ascii "/logout"
.set PATH_LOGOUT_LEN, 7

.section .bss
    .lcomm REQ_BUF, 4096

.section .text
_start:
# socket(AF_INET, SOCK_STREAM, 0)
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    mov rax, 41
    syscall
    mov r12, rax                      # listening socket fd

# bind(listen_fd, sockaddr_in, 16)
    sub rsp, 16
    mov word ptr  [rsp],   2          # AF_INET
    mov word ptr  [rsp+2], 0x901f     # port 8080 (network byte order)
    mov dword ptr [rsp+4], 0x00000000 # 0.0.0.0
    mov qword ptr [rsp+8], 0

    mov rdi, r12
    mov rsi, rsp
    mov rdx, 16
    mov rax, 49
    syscall

# listen(listen_fd, backlog)
    mov rdi, r12
    mov rsi, 4096
    mov rax, 50
    syscall

ACCEPT_LOOP:
# accept(listen_fd, NULL, NULL)
    mov rdi, r12
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 43
    syscall
    cmp rax, 0
    jl ACCEPT_LOOP
    mov r13, rax                      # client fd

# read(client_fd, REQ_BUF, 4096)
    mov rdi, r13
    lea rsi, [rip + REQ_BUF]
    mov rdx, 4096
    mov rax, 0
    syscall
    cmp rax, 0
    jle CLOSE_CLIENT

# r14 = path_ptr, r15 = method_id (1=GET,2=POST)
# check "GET "
    lea rbx, [rip + REQ_BUF]
    cmp byte ptr [rbx], 'G'
    jne CHECK_POST
    cmp byte ptr [rbx+1], 'E'
    jne CHECK_POST
    cmp byte ptr [rbx+2], 'T'
    jne CHECK_POST
    cmp byte ptr [rbx+3], ' '
    jne CHECK_POST
    lea r14, [rbx+4]
    mov r15, 1
    jmp ROUTE_PATH

CHECK_POST:
    cmp byte ptr [rbx], 'P'
    jne RESP_METHOD_NOT_ALLOWED
    cmp byte ptr [rbx+1], 'O'
    jne RESP_METHOD_NOT_ALLOWED
    cmp byte ptr [rbx+2], 'S'
    jne RESP_METHOD_NOT_ALLOWED
    cmp byte ptr [rbx+3], 'T'
    jne RESP_METHOD_NOT_ALLOWED
    cmp byte ptr [rbx+4], ' '
    jne RESP_METHOD_NOT_ALLOWED
    lea r14, [rbx+5]
    mov r15, 2

ROUTE_PATH:
# /health => GET only
    mov rdi, r14
    lea rsi, [rip + PATH_HEALTH]
    mov rdx, PATH_HEALTH_LEN
    call path_eq_space_terminated
    cmp rax, 1
    jne CHECK_LOGIN
    cmp r15, 1
    jne RESP_METHOD_NOT_ALLOWED
    jmp RESP_OK

CHECK_LOGIN:
    mov rdi, r14
    lea rsi, [rip + PATH_LOGIN]
    mov rdx, PATH_LOGIN_LEN
    call path_eq_space_terminated
    cmp rax, 1
    jne CHECK_FILES
    jmp RESP_NOT_IMPLEMENTED

CHECK_FILES:
    mov rdi, r14
    lea rsi, [rip + PATH_FILES]
    mov rdx, PATH_FILES_LEN
    call path_eq_space_terminated
    cmp rax, 1
    jne CHECK_LOGOUT
    jmp RESP_NOT_IMPLEMENTED

CHECK_LOGOUT:
    mov rdi, r14
    lea rsi, [rip + PATH_LOGOUT]
    mov rdx, PATH_LOGOUT_LEN
    call path_eq_space_terminated
    cmp rax, 1
    jne RESP_NOT_FOUND
    jmp RESP_NOT_IMPLEMENTED

RESP_OK:
    mov rdi, r13
    lea rsi, [rip + RESP_200]
    mov rdx, RESP_200_LEN
    jmp WRITE_AND_CLOSE

RESP_NOT_FOUND:
    mov rdi, r13
    lea rsi, [rip + RESP_404]
    mov rdx, RESP_404_LEN
    jmp WRITE_AND_CLOSE

RESP_METHOD_NOT_ALLOWED:
    mov rdi, r13
    lea rsi, [rip + RESP_405]
    mov rdx, RESP_405_LEN
    jmp WRITE_AND_CLOSE

RESP_NOT_IMPLEMENTED:
    mov rdi, r13
    lea rsi, [rip + RESP_501]
    mov rdx, RESP_501_LEN

WRITE_AND_CLOSE:
    mov rax, 1
    syscall

CLOSE_CLIENT:
    mov rdi, r13
    mov rax, 3
    syscall
    jmp ACCEPT_LOOP

# ---------------------------------------------------------------
# path_eq_space_terminated(path_ptr=rdi, literal_ptr=rsi, len=rdx)
# returns rax=1 if [path_ptr..] starts with literal and next char is ' '
# else rax=0
# clobbers: rcx, r8, r9
# ---------------------------------------------------------------
path_eq_space_terminated:
    xor rcx, rcx
.CMP_LOOP:
    cmp rcx, rdx
    je .CHECK_TERM
    mov r8b, byte ptr [rdi + rcx]
    mov r9b, byte ptr [rsi + rcx]
    cmp r8b, r9b
    jne .NO
    inc rcx
    jmp .CMP_LOOP

.CHECK_TERM:
    cmp byte ptr [rdi + rdx], ' '
    jne .NO
    mov rax, 1
    ret

.NO:
    xor rax, rax
    ret
