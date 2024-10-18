import re
from typing import List


def match_port(port: int, allowed_ports: List[int]) -> bool:
    """
    :param port: The port number to be checked.
    :param allowed_ports: A list of allowed port numbers.
    :return: True if the port is in the allowed_ports list, False otherwise.
    """
    return port in allowed_ports


def match_host(hostname: str, patterns: List[str]) -> bool:
    """
    :param hostname: The hostname string to be matched against the patterns.
    :param patterns: A list of patterns where each pattern may contain wildcard '*' characters.
    :return: True if the hostname matches any of the patterns, otherwise False.
    """
    for pattern in patterns:
        regex = re.escape(pattern).replace(
            r"\\\*", ".*"
        )  # Note how the backslash is doubled
        if re.fullmatch(regex, hostname):
            return True
    return False