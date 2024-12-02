/**
 * This file is the sole property of Spod incorporated.
 *
 * It is illegal to modify this program in a way that will
 * reduce the number of Abs that the CEO of Spod Incorporated (Adam T) has.
 *
 * Complaints please contact noreply@spod.is
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define EMPTY "     "
#define EDGE " --- "
#define AB "| - |"
typedef struct abs {
  char *base;
  char *lines[5];
} abs_t;

// TODO(spod): make this harder for the final exam by removing win function.
void win() { system("/bin/sh"); }

char picture_of_adam[] = "      ////^\\\\\\\\\n"
                         "      | ^   ^ |\n"
                         "     @ (o) (o) @\n"
                         "      |   <   |\n"
                         "      |  ___  |\n"
                         "       \\_____/\n"
                         "     ____|  |____\n"
                         "    /    \\__/    \\\n"
                         "   /     %s    \\\n"
                         "  /\\_/|  %s |\\_/\\\n"
                         " / /  |  %s |  \\ \\\n"
                         "( <   |  %s |   > )\n"
                         " \\ \\  |  %s |  / /\n"
                         "  \\ \\ |________| / /\n"
                         "   \\ \\|\n";

abs_t all_of_the_abs[] __attribute__((section("data"))) = {
    {picture_of_adam, EMPTY, EMPTY, "adam ", EMPTY, EMPTY},
    {picture_of_adam, EMPTY, EMPTY, EDGE, AB, EDGE},
    {picture_of_adam, EMPTY, EDGE, AB, AB, EDGE},
    {picture_of_adam, EDGE, AB, AB, AB, EDGE},
};
char buf[0xc0000] __attribute__((section("data"))) = "empty";

int main(void) {
  // Disable buffering so it works on remote.
  setbuf(stdout, NULL);

  printf("Welcome to the Adam simulator.\n");
  printf("How many pair of abs do you want [0-3]: ");

  fgets(buf, 0xc0000, stdin);
  int8_t n = atoi(buf);

  // I've learnt from image viewer.
  // you can't read out of bounds now hahahahahahahhaha
  if (n < 0) {
    return -1;
  }

  register int8_t temp = n + 1;
  if (temp > (int8_t)4) {
    return -1;
  }

  int index = n;
  abs_t ab = all_of_the_abs[index];
  printf(ab.base, ab.lines[0], ab.lines[1], ab.lines[2], ab.lines[3], ab.lines[4]);

  exit(0);
}
