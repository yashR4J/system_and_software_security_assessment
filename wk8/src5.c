#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <xml.h>

#define MAX_FILE_SIZE 9999

static int string_equals(struct xml_string *a, char const *b) {
  size_t a_length = xml_string_length(a);
  size_t b_length = strlen(b);

  char *a_buffer = alloca((a_length + 1) * sizeof(char));
  xml_string_copy(a, a_buffer, a_length);
  a_buffer[a_length] = 0;

  if (a_length != b_length) {
    return 0;
  }

  size_t i = 0;
  for (; i < a_length; ++i) {
    if (a_buffer[i] != b[i]) {
      return 0;
    }
  }

  return 1;
}

// DFS search of nodes.
struct xml_string **find_all_htmls(struct xml_node *root) {
  int totalLen = 0; // should be size_t

  // First we walk down the html node to find number of elems.
  for (int i = 0; i < xml_node_children(root); i++) {
    struct xml_node *child = xml_node_child(root, i);

    if (string_equals(child->str, "href")) {
      totalLen += xml_node_children(child);
    }
  }

  // Sanity checks!
  assert(totalLen >= 0);
  assert(totalLen <= 512);
  struct xml_string **buffer =
      (struct xml_string **)calloc(sizeof(struct xml_string *), 512);

  int g = 0;
  if (buffer == NULL) {
    return NULL;
  }

  // Now add them.
  for (int i = 0; i < xml_node_children(root); i++) {
    struct xml_node *child = xml_node_child(root, i);

    if (string_equals(child->str, "href")) {
      for (int j = 0; j < xml_node_children(child); j++) {
        buffer[g++] = xml_node_child(child, j)->str;
      }
    }
  }

  return buffer;
}

int main(int argc, char *argv[], char *envp[]) {
  char buf[MAX_FILE_SIZE];
  fread(buf, MAX_FILE_SIZE - 1, sizeof(char), stdin); // need to ensure this is null-terminated

  struct xml_document *document = xml_parse_document(buf, strlen(buf));
  if (!document) {
    printf("Could parse document\n");
    return 0;
  }

  struct xml_node *root = xml_document_root(document);
  if (root == NULL) {
    printf("No root node\n");
    return 0;
  }

  for (struct xml_string **start = find_all_htmls(root); *start != NULL;
       start++) {
    struct xml_node *curr = *start;
    printf("%s\n", curr);
  }
}
