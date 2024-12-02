// #include <stdio.h>
// #include <stdlib.h>

// struct s {
//     int data;
//     struct s *next;
// };

// struct s* new() {
//     struct s *next = NULL;
//     int counter = 0;

//     while (counter <= 9) {
//         struct s *data_struct = (struct s *)malloc(sizeof(struct s)); // 16 bytes allocated (padding included)
//         if (data_struct == NULL) {
//             exit(1);
//         }

//         data_struct->data = counter + 65; 
//         data_struct->next = next;
//         next = data_struct;

//         counter++;
//     }

//     return next; 
// }

#include <stdio.h>
#include <stdlib.h>

struct s {
    char str;
    struct s *next;
};

struct s* new() {
    struct s *head = NULL;
    int counter = 0;

    for (int i = 0; i <= 9; i++) {
        struct s *curr = (struct s *)malloc(sizeof(struct s));
        if (curr == NULL) {
            exit(1);
        }

        if (head == 0) {
            head = curr;
        } else {
            curr->next = head;
            head = curr;
        }

        curr->next = NULL;
        curr->str = i + 'A';
    }

    return head; 
}