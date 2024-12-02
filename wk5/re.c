// function divides the sum of two numbers by 3 and returns the remainder
// effectively approximating to a mod by 3 function for the sum of two numbers
// i.e. (arg1 + arg2) % 3


// loading function arguments
int re_this(int arg1, int arg2)
{
    // addition
    int var_c = arg1;
    int var_10 = arg2;
    int temp = var_c + var_10;

    // sign extend temp to rax (64 bit) and multiple by constant
    // this multiplication seems to approximate to a division by 3
    long long temp_2 = (long long)(temp) * 0x2aaaaaab;

    // shift by 0x20 (32) bits to only hold the higher 32 bits temp_2
    var_10 = temp_2 >> 32;

    // adjust sign and subtract
    var_10 -= temp >> 31;

    // eax (storing var_10) is added 3 times and then subtracted from ecx (storing temp)
    temp -= var_10 + var_10 + var_10;
    return temp;
}