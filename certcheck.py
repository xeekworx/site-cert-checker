import ssl
import socket
from datetime import datetime
import certifi  # pip install certifi
import sys
import argparse


def setup_arg_parser():
    """
    Sets up an argument parser for the script to handle command line arguments.

    Returns:
    - argparse.ArgumentParser: Configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Check and display SSL certificate information for a given host.",
        epilog="Return values:\n"
        "  0 - Certificate is valid.\n"
        "  1 - Certificate is invalid.\n"
        "  2 - An error occurred during the process.\n\n"
        "Use this script to validate SSL certificates and display their details, "
        "including expiration date.",
        formatter_class=argparse.RawTextHelpFormatter,  # Use RawTextHelpFormatter for better formatting of the epilog
    )
    parser.add_argument(
        "host",
        help="The hostname or IP address of the server to check.",
        type=str,
        nargs="?",
    )
    parser.add_argument(
        "-p",
        "--port",
        help="The port number to connect to at the host. Default is 443.",
        type=int,
        default=443,
    )
    return parser


def get_ssl_certificate(host: str, port: int = 443) -> dict[str, any]:
    """
    Retrieves the SSL certificate from the specified host and port.

    Parameters:
    - host (str): The hostname or IP address of the server to connect to.
    - port (int): The port number to connect to at the host. Default is 443.

    Returns:
    - dict: A dictionary object representing the SSL certificate of the host.
    """
    context = ssl.create_default_context()

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            certificate = ssock.getpeercert()

    return certificate


def parse_certificate(certificate: any) -> dict[str, any]:
    """
    Parses an SSL certificate to extract and organize important information.

    Parameters:
    - certificate (dict): The SSL certificate obtained from get_ssl_certificate.

    Returns:
    - dict: A dictionary containing parsed certificate information such as issuer,
      subject, valid from, valid until, and version.
    """
    cert_info = {
        "issuer": dict(x[0] for x in certificate["issuer"]),
        "subject": dict(x[0] for x in certificate["subject"]),
        "valid_from": certificate["notBefore"],
        "valid_until": certificate["notAfter"],
        "version": certificate["version"],
    }
    return cert_info


def get_certificate_expiration_date(
    cert_info: dict, date_format: str = "%A, %B %d, %Y %H:%M:%S %Z"
) -> str:
    """
    Converts the 'valid until' date of an SSL certificate into a readable string using a specified format.

    Parameters:
    - cert_info (dict): A dictionary containing parsed SSL certificate information.
    - date_format (str): The format string to use for the expiration date. Defaults to "%A, %B %d, %Y %H:%M:%S %Z".

    Returns:
    - str: The expiration date of the certificate in the specified format.
    """
    valid_until = cert_info["valid_until"]
    expiration_date = datetime.strptime(valid_until, "%b %d %H:%M:%S %Y %Z")
    expiration_date_str = expiration_date.strftime(date_format)

    return expiration_date_str


def validate_certificate(
    host: str, port: int = 443, cafile=certifi.where()
) -> tuple[bool, str]:
    """
    Validates the SSL certificate of a given host and port against the CA bundle provided by certifi.

    Parameters:
    - host (str): The hostname or IP address to validate the SSL certificate for.
    - port (int): The port number to use for the connection. Default is 443.
    - cafile (str): The path to the CA bundle file used for validation. Defaults to certifi.where().

    Returns:
    - tuple: A tuple containing a boolean indicating whether the certificate is valid, and a string message.
      The boolean is True if valid, False if invalid, and None if an error occurred. The message provides
      additional context.
    """
    try:
        # Create a context with default configurations and the certifi CA bundle
        context = ssl.create_default_context(cafile=cafile)
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # If the handshake is successful, the certificate is valid
                ssock.getpeercert()
        return True, "Certificate is valid"
    except ssl.SSLCertVerificationError as e:
        return False, f"Certificate is invalid: {e.strerror}"  # Certificate is invalid
    except Exception as e:
        return None, f"An error occurred: {e}"


if __name__ == "__main__":
    parser = setup_arg_parser()
    args = parser.parse_args()

    if not args.host or not args.host.strip():
        # Display help message if no host is provided
        parser.print_help()
        sys.exit(1)

    # Validate certificate
    is_valid, message = validate_certificate(args.host, args.port)
    print(message)

    if is_valid is None:
        sys.exit(2)

    try:
        certificate = get_ssl_certificate(args.host, args.port)
        cert_info = parse_certificate(certificate)
        expiration_date_str = get_certificate_expiration_date(cert_info)

        print(f"Certificate for {args.host} expires on: {expiration_date_str}\n")
        print("Certificate Details:")
        for key, value in cert_info.items():
            if isinstance(value, dict):
                print(f"{key.capitalize()}:")
                for sub_key, sub_value in value.items():
                    print(f"  {sub_key}: {sub_value}")
            else:
                print(f"{key.capitalize()}: {value}")
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(2)

    if is_valid:
        sys.exit(0)
    else:
        sys.exit(1)
