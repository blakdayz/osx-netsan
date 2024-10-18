import re


def match_port(port: int, allowed_ports: list):
    """Check if the given port is in the allowed ports list."""
    return port in allowed_ports


def match_host(hostname: str, patterns: list):
    """Check if the hostname matches any of the provided patterns."""
    for pattern in patterns:
        regex = re.escape(pattern).replace(r'\*', '.*')
        if re.fullmatch(regex, hostname):
            return True
    return False