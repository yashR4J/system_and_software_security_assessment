# Vulnerabilities

- Memory allocated by strdup needs to be freed 
    - safety checks should probably be in place after strdup calls are made to ensure allocated memory for
    other parts of the program is also freed appropriately 
        - for instance, 

                ```c
                logged_in_user->name = strdup(arg);
                if (!logged_in_user->name)
                {
                    free(logged_in_user);
                }
                logged_in_user->auth = find_permission_level(arg);
                ```

    - there are also calls to strdup made when `run_command_in_sandbox` and `syslog` are called [Lines 74-75] which 
    allocate memory that is not freed after.

- Potential format string vulnerability from calling SYS_LOG on user controlled input without sanitising input.

- not a bug but logout is never called..?