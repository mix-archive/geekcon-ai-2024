#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main()
{
    char buf[0x20];
    memset(buf,0,0x20);
    read(0,buf,0x20);
    system(buf);
    return 0;
}