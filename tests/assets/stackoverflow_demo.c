#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

unsigned char backdoor[] =
"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50\x54\x5f"
"\x52\x66\x68\x2d\x63\x54\x5e\x52\xe8\x08\x00\x00\x00\x2f"
"\x62\x69\x6e\x2f\x73\x68\x00\x56\x57\x54\x5e\x6a\x3b\x58"
"\x0f\x05";

void init()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);

    void *addr = mmap((void *)0xdead0000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
    {
        perror("mmap failed");
        exit(1);
    }

    memcpy(addr, backdoor, sizeof(backdoor));
}

int main()
{
    init();

    char buf[0x10];
    puts("Enter something:");
    gets(buf);
    return 0;
}