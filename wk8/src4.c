#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *chunks[64];
int len = 0;

void flush(void) {
  char ch;
  while ((ch = getchar()) && ch != EOF && ch != '\n') {
  }
}

void getstr(char *buf) { fgets(buf, 128, stdin); }

void waitForKey(void) {
  printf("Press any key to continue...\n");
  flush();
  printf("\n");
}

void allocate() {
  len++;
  if (len >= 64) {
    puts("too many chunks");
    exit(0);
  }

  printf("Chunk id: %d", len);
  chunks[len - 1] = malloc(16);
}

void free_it() {
  int id = 0;
  printf("Enter chunk id: ");
  scanf("%d", &id);
  flush();

  if (id >= len) {
    puts("Chunk not allocated");
    exit(0);
  }

  free(chunks[id]);
}

void write_it() {
  int id = 0;
  printf("Enter chunk id: ");
  scanf("%d", &id);
  flush();

  if (id >= len) {
    puts("Chunk not allocated");
    exit(0);
  }

  fgets(chunks[id], 16, stdin);
}

void print_it() {
  int id = 0;
  printf("Enter chunk id: ");
  scanf("%d", &id);
  flush();

  if (id >= len) {
    puts("Chunk not allocated");
    exit(0);
  }

  printf("%s\n", chunks[id]);
  len--;
}

int menu() {
  printf("\n");
  printf("[A]llocate\n");
  printf("[F]ree the chunk\n");
  printf("[W]rite\n");
  printf("[P]rint \n");
  printf("[Q]uit\n");
  printf("\n");
  printf("Enter your choice, (or press enter to refresh): ");

  char ch = getchar();

  switch (ch) {
  case EOF:
  case 'q':
  case 'Q':
    exit(0);

  case 'a':
  case 'A':
    flush();
    allocate();
    break;

  case 'f':
  case 'F':
    flush();
    free_it();
    break;

  case 'w':
  case 'W':
    flush();
    write_it();
    break;

  case 'p':
  case 'P':
    flush();
    print_it();
    break;

  default:
    printf("\n");
    break;
  }

  return 1;
}

int main(void) {
  setbuf(stdout, NULL);

  do {
  } while (menu());
}
