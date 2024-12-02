## Vulnerabilities

1. [Line 70] `fread` reads data up to `MAX_FILE_SIZE - 1` into buf but does not ensure the read input is null-terminated.
3. [Line 39] `totalLen` could be subject to integer overflow if the number of xml_node_children is very large so the value returned by xml_node_children should probably be checked before adding to totalLen.
    - wrap around would cause buffer to allocate insufficient memory and subsequently, we will write data into memory beyond what was allocated, corrupting the heap and potentially overwriting adjacent memory segments.
3. [Line 84] xml_string object is not freed after use, leading to a memory leak. Additionally, the dangling pointer should be replaced with an iterating counter and we should free each `xml_string *` after use.