// notes:
// save base pointer and set up stack frame
// reserve 32 bytes on stack
// store first argument (argc) from edi register to local stack
// store second argument (argv) from rsi register to local stack
// store var_c address in rax register 
// move address of var_c into rsi register for function call to scanf
// load address of string constant (maybe %d?) or another input format specifier for scanf
// rdi register (first argument of functional call) loaded with format string
// clear eax register

#include <stdio.h>

int main(int argc, char *argv[]) { // argc and argv are placed at the bottom
{
    int var_c;
    scanf("%d", &var_c);
    if (var_c != 1337)
    {
        puts(""); // print some value from value stored in data_2015
    } 
    else 
    {
        puts("Your so leet!"); // print value loaded in data_2007
    }

    return 1;
}