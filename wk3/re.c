#include <stdio.h>

int main(int argc, char *argv[]) // argc and argv are placed at the bottom
{
    int var_b = 0;
    while (var_b <= 9) {
        if (var_b & 1) {
            // test eax, eax would check for eax = 1 (odd case) and 0-flag would not be set when eax is non-zero
            // jump occurs when zero flag is set 
            printf("%d\n", var_b);
        }
        var_b += 1;
    }
    return 1;
}