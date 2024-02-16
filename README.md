# Site SSL Certificate Checker

This Python script checks the SSL certificate of a specified host and port, validates it against a trusted CA bundle provided by `certifi`, and displays detailed information about the certificate, including its expiration date.

## Features

- Retrieves the SSL certificate of a given host.
- Parses and displays key information from the certificate, such as the issuer, subject, and validity period.
- Validates the certificate against the trusted CA bundle from `certifi`.
- Provides return values indicating the validation status of the certificate.

## Requirements

- Python 3.x
- `certifi` package (can be installed via pip)

## Usage
Run the script with the host as an argument:

```bash
python certcheck.py example.com
```

### Optional Arguments:

-p or --port: Specify the port number (default is 443).

#### Basic usage for port 8443:

```bash
python certcheck.py example.com -p 8443
```

### Displaying help information

```bash
python certcheck.py --help
```

### Return Values
The script returns the following exit codes:
- 0: Certificate is valid.
- 1: Certificate is invalid.
- 2: An error occurred during the process.
