# Vulnerabilities

- `len` decrements after `print_it` is called, which may lead to chunks not being able to be freed if their id >= previous len 
- bounds checking on `id` does not consider negative indices, which could lead to out-of-bounds access
    - conditions should be changed to `if (id < 0 || id  >= len)`
- double free vulnerability since chunks[id] is not set to NULL after free > if free_it is called again with the same id,
this could potentially lead to the attacker tampering with memory management to cause arbitrary code execution 
- not necessarily a bug but program should check that the malloc call succeeded