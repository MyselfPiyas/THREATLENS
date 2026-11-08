"""Strict URL normalization and public-address validation for outbound scans."""

import asyncio
import ipaddress
import socket
import re
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

from app.core.config import get_settings

_SENSITIVE_QUERY_KEYS = {
    "access_token", "api_key", "apikey", "auth", "authorization", "client_secret",
    "code", "code_verifier", "id_token", "key", "jwt", "password", "passwd",
    "refresh_token", "secret", "session", "signature", "token", "otp", "bearer",
}
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".test", ".invalid", ".example")
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")


class UnsafeTarget(ValueError):
    """The requested target cannot be fetched safely."""


def _public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise UnsafeTarget("The target resolved to an invalid network address.") from error
    # is_global excludes private, loopback, link-local, multicast, reserved,
    # unspecified, documentation and shared address space on supported Python.
    return address.is_global and not (
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_multicast or address.is_reserved or address.is_unspecified
    )


def normalize_url(value: str) -> str:
    settings = get_settings()
    candidate = value.strip()
    if not candidate or len(candidate) > settings.url_scan_max_url_length:
        raise UnsafeTarget("Enter a URL within the allowed length.")
    if _CONTROL_OR_SPACE.search(candidate) or "\\" in candidate:
        raise UnsafeTarget("The URL contains unsupported characters.")
    try:
        parts = urlsplit(candidate)
        port = parts.port
    except ValueError as error:
        raise UnsafeTarget("The URL is not valid.") from error
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise UnsafeTarget("Only public HTTP and HTTPS URLs are supported.")
    if parts.username is not None or parts.password is not None:
        raise UnsafeTarget("URLs containing credentials are not accepted.")
    if parts.fragment:
        raise UnsafeTarget("Remove the URL fragment before scanning.")

    scheme = parts.scheme.lower()
    allowed_port = 80 if scheme == "http" else 443
    if port not in {None, allowed_port}:
        raise UnsafeTarget("Only the standard HTTP and HTTPS ports are supported.")

    hostname = parts.hostname.rstrip(".").lower()
    if not hostname or hostname == "localhost" or hostname.endswith(_BLOCKED_SUFFIXES):
        raise UnsafeTarget("Local and reserved hostnames cannot be scanned.")
    try:
        ipaddress.ip_address(hostname)
        if not _public_ip(hostname):
            raise UnsafeTarget("Private and reserved IP addresses cannot be scanned.")
        ascii_host = hostname
    except ValueError as error:
        if isinstance(error, UnsafeTarget):
            raise
        try:
            ascii_host = hostname.encode("idna").decode("ascii")
        except UnicodeError as idna_error:
            raise UnsafeTarget("The hostname is not valid.") from idna_error
        if len(ascii_host) > 253 or not all(
            label and len(label) <= 63 and label[0] != "-" and label[-1] != "-"
            and re.fullmatch(r"[a-z0-9-]+", label)
            for label in ascii_host.split(".")
        ):
            raise UnsafeTarget("The hostname is not valid.")

    for key, _ in parse_qsl(parts.query, keep_blank_values=True, max_num_fields=100):
        normalized_key = key.casefold().replace("-", "_")
        if normalized_key in _SENSITIVE_QUERY_KEYS or normalized_key.endswith(("_token", "_secret", "_password", "_key")):
            raise UnsafeTarget("Remove authentication tokens and secrets from the URL before scanning.")

    netloc = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    if port is not None:
        netloc = f"{netloc}:{port}"
    safe_path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~%")
    safe_query = quote(parts.query, safe="/%?:@!$&'()*+,;=-._~%")
    return urlunsplit((scheme, netloc, safe_path, safe_query, ""))


async def resolve_public_addresses(hostname: str, timeout_seconds: float | None = None) -> list[str]:
    """Resolve once and reject the entire answer set unless every IP is public."""
    try:
        ipaddress.ip_address(hostname)
        answers = [hostname]
    except ValueError:
        timeout = timeout_seconds or get_settings().url_scan_connect_timeout_seconds
        try:
            loop = asyncio.get_running_loop()
            records = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM), timeout=timeout
            )
        except (TimeoutError, OSError) as error:
            raise UnsafeTarget("The destination hostname could not be resolved safely.") from error
        answers = list(dict.fromkeys(record[4][0] for record in records))
    if not answers or any(not _public_ip(address) for address in answers):
        raise UnsafeTarget("The destination resolves to a private or reserved network address.")
    return answers
