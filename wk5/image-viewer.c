#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SECRETSAUCE "flat earth truth"

struct image {
  int id;
  char *filename;
};

char buf[256] = "empty";
struct image images[] = {
    {0, "adam hawaii trip"},
    {1, "adam france trip"},
    {2, "adam's basement"},
    {3, SECRETSAUCE},
};

void timeout() {
  puts("Connection timed out.");
  exit(0);
}

void read_input() {
  printf("$ ");

  if (!fgets(buf, sizeof(buf), stdin)) {
    exit(0);
  }

  char *newline = strchr(buf, '\n');
  if (newline) {
    *newline = '\0';
  }
}

int main(int argc, char *argv[]) {
  signal(SIGALRM, timeout);
  alarm(30);
  setbuf(stdout, NULL);

  printf("password pls\n");
  read_input();

  if (strcmp(buf, "password123")) {
    puts("Invalid password.");
    exit(0);
  }

  puts("\nWelcome to the.. uhh.. Legitimate image service. Select a photo to view...");

  for (int i = 0; i < 4; i++) {
    printf("[%d] %s\n", i, images[i].filename);
  }

  puts("");
  read_input();

  struct image image = images[atoi(buf)];
  if (!strcmp(image.filename, SECRETSAUCE)) {
    puts("uhh... feds. Image not found...");
    exit(0);
  }
  int id = atoi(buf);

  if (image.id != id) {
    printf("Image id must be %d, but supplied id is %d\n", image.id, id);
    exit(0);
  }

  FILE *f = fopen(image.filename, "r");
  if (f) {
    puts("\n\
+----------------------------------------------------------------------------------------------------------------------------------+\n\
|                                                      Image Viewer                                                                |\n\
+----------------------------------------------------------------------------------------------------------------------------------+");

    while (fgets(buf, sizeof(buf), f)) {
      char *newline = strchr(buf, '\n');
      if (newline) {
        *newline = '\0';
      }

      printf("| %-*s |\n", (int)sizeof(buf), buf);
    }

    puts("+--------------------------------------------------------------------"
         "--------------------------------------------------------------+");
  } else {
    puts("Error: File not found");
  }

  return 0;
}
