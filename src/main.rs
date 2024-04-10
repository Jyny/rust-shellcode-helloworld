use std::mem::transmute;

/*
section .text
    global _start
_start:
    jmp short ending

    main_func:

    xor rax,rax	; zero rax
    xor rdi, rdi	; zero rdi
    xor rsi, rsi	; zero rsi
    xor rdx, rdx	; zero rdx

    mov al, 1	; set syscall to size_t sys_write(unsigned int fd, const char * buf, size_t count);
    mov dil, 1	; set file descriptor to 1; 0 = stdin, 1 = stdout, 2 = stderr

    pop rsi		; pop "Hello World!" from stack
    mov dl, 12	; set "Hello World!" size to 12
    syscall
    xor rax, rax	; zero rax

    mov al, 60	; set syscall to int sys_exit(int status)
    mov dil, 0	; set return value to 0, programm exited succesfully
    syscall

    ending:
    call main_func
    db "Hello World!"
*/
// https://gist.github.com/procinger/a65c8bde824a10294a4a6966de5a47b4

#[no_mangle]
#[link_section = ".text"]
static shellcode: [u8; 51] = [
    0xeb, 0x20, // jmp 0x20
    0x48, 0x31, 0xc0, // xor rax, rax
    0x48, 0x31, 0xff, // xor rdi, rdi
    0x48, 0x31, 0xf6, // xor rsi, rsi
    0x48, 0x31, 0xd2, // xor rdx, rdx
    0xb0, 0x01, // mov al, 0x01
    0x40, 0xb7, 0x01, // mov dil, 0x01
    0x5e, // pop rsi
    0xb2, 0x0c, // mov dl, 0x0c
    0x0f, 0x05, // syscall
    0x48, 0x31, 0xc0, // xor rax, rax
    0xb0, 0x3c, // mov al, 0x3c
    0x40, 0xb7, 0x00, // mov dil, 0x00
    0x0f, 0x05, // syscall
    0xe8, 0xdb, 0xff, 0xff, 0xff, // call -0x25
    0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, // Hello World!
];

fn main() {
    let exec: extern "C" fn() = unsafe { transmute(shellcode.as_ptr()) };
    exec();
}
