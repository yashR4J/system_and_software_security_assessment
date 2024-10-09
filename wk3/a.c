#include <stdio.h>
#include <string.h>

void func() {
    int counter = 0;
    while(1) {
        if (counter >= 10){ 
            printf("You win!\n"); 
            break; 
        } else {
            printf("%d\n",counter); 
            counter += 1; 
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return -1;
    }

    func();
    return 0;
}
