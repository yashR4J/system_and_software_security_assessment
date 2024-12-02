# Vulnerabilities

1. Potential Integer Overflow of User Controlled `len` - if len is large enough (i.e. INT_MAX),
the result of header_size + len will wrap around and the conditional check will succeed.
Consequently, the `read` call will result in a buffer overflow, allowing the user to read more data
than what `storage` can hold.