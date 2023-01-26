#include <stdio.h>

int main(){
    char buf[0x10];
    read(0, buf, 0x100);
    puts(buf);
    read(0, buf, 0x100);
    
    return 0;
}