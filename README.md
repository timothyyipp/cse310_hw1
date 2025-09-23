# README

This file provides details about the external libraries used, instructions on how to run the `mydig.py` program, and the expected output for some example queries.

## External Libraries Used
The `mydig.py` program relies on the following external libraries:
- `sys`: For system-specific parameters and functions.
- `time`: For handling time-related tasks.
- `threading`: For managing threads.
- `datetime`: For working with date and time.
- `dns.message`, `dns.query`, `dns.rdatatype`, `dns.exception`: From the `dnspython` library, used for DNS resolution.

Ensure these libraries are available in your Python environment. You may need to install `dnspython` using:
```bash
pip install dnspython
```

## Instructions to Run the Program
1. Open a terminal or command prompt.
2. Navigate to the directory containing `mydig.py`.
3. Run the program using the following command:
    ```bash
    python mydig.py <query>
    ```
    Replace `<query>` with the desired input query.

## Expected Output
For example, running:
```bash
python mydig.py example.com
```
The program will output the DNS resolution details for `example.com`, including IP addresses and other relevant information.

Ensure you have Python installed and properly configured before running the program.