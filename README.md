# Fuzzinator

Fuzzinator is a powerful web application fuzzing tool that supports multiple FUZZ keyword injections. It allows for concurrent fuzzing operations with customizable payloads, filters, and output options.

## Features

- Multiple FUZZ keyword support in URLs and POST data
- Concurrent fuzzing with configurable thread count
- Support for different payload types:
  - Numeric ranges (e.g., 1-100)
  - Hexadecimal ranges (e.g., 0x00-0xFF)
  - Wordlist files
- Customizable HTTP methods (GET, POST, PUT, DELETE, HEAD, OPTIONS)
- Custom header support
- Response filtering by:
  - Status codes (including ranges like 2xx, 3xx)
  - Response size
- Colorized output option
- Progress tracking
- Configurable request delays and timeouts
- Verbose output mode
