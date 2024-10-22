#include<stdio.h>
#include<string.h>
#include<sys/mman.h>

#define BACKDOOR_ADDRESS (void*)0xdead0000

__attribute__((constructor))
void setup(void){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main(void){
    unsigned char shellcode[] = \
"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05";
    char payload[200];
    void *mem = mmap(BACKDOOR_ADDRESS, 4096, PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    printf("%p\n", &payload);
    memcpy(mem, shellcode, sizeof(shellcode));
    scanf("%200s", payload);
    printf(payload);

    return 0;
}