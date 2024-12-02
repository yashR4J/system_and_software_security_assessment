## Vulnerabilities

**Directory Traversal**

```c
  snprintf(buf, MAX_LEN, "./webpath/%s", action);
```

[Lines 71, 97]

User input (action) is concatenated to create file path and could be manipulated by attacked using '../' sequences to navigate into other unprivileged directories.

- In `write_file()` the "w" flag would allow the attacker to create or overwrite any file with write access
- In `read_file()` the attacker can read arbitrary files to expose sensitive information

**Format String Vulnerability / Log Injection**

```c
    snprintf(log, MAX_LEN,
             "SERVER: %d admin level, attempting command %x, args %s\n",
             admin_level, action[0], action + 1);
    syslog(LOG_INFO, log);
```

[Lines 143-146]

Insecure logging of user-supplied input can lead to a manipulation of log entries.

**Privilege Escalation / Type Mismatch**

```c
    uint8_t admin_level = 0;
    ...
    int level = -1;
```

[Lines 140, 159]

If the value of level 0x100 (256), it will set admin_level to 0x00 since it only stores the last byte, granting the user with admin privileges. Also, there is no break statement, so the COMMAND case will execute right after setting the admin_level.

**Improper Error Handling**

```c
    write_socket(socket, READY, sizeof(READY));
    ...
    len = read_socket(socket, action, MAX_LEN);
```

[Lines 137, 139]

If these methods fail, there is no proper error handling propagation which could potentially lead to unintended consequences if the program assumes that len is positive (i.e. buffer overflows or leaks of sensitive data).

```c
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(sock, (struct sockaddr *)&sin, sizeof(sin));
    ...
    fd = accept(socket, (struct sockaddr *)&client, &len);
```

[Lines 195, 196, 210]

Result is again not checked for failure event so the server may proceed with a misconfigured socket?

If `accept()` fails, `handle_conn()` is called with an invalid file descriptor.

**EAX exploitation**

```c
int handle_conn(int socket) {
    ...
}
```

[Lines 131-178]

Method does not return an integer, leaving eax in an undefined state for the attacker to potentially use in a ROP chain for exploitation.

**Command Execution**

```c
    system(action);
```

[Line 128]

User-controlled input directly executes arbitrary system commands that are not appropriately sanitised. 