"""Bounded passive TLS and HTTP security-header inspection."""

from __future__ import annotations

import asyncio
import ssl
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

from app.core.config import Settings, get_settings
from app.scanners.url_scanner import _request_response_headers
from app.scanners.url_validation import UnsafeTarget, normalize_url, resolve_public_addresses

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def _name(name: x509.Name) -> str:
    return ", ".join(f"{attribute.oid._name or attribute.oid.dotted_string}={attribute.value}" for attribute in name)


def _key_details(public_key: Any) -> tuple[str, int | None]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC {public_key.curve.name}", public_key.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 456
    return type(public_key).__name__, None


def _peer_chain(ssl_object: ssl.SSLObject) -> dict[str, Any]:
    getter = getattr(ssl_object, "get_verified_chain", None) or getattr(ssl_object, "get_unverified_chain", None)
    if not callable(getter):
        return {"available": False, "certificates": [], "detail": "This Python SSL runtime did not expose the peer certificate chain."}
    try:
        certificates = getter()
        subjects: list[str] = []
        for item in certificates or []:
            der = item.public_bytes() if hasattr(item, "public_bytes") else item
            subjects.append(_name(x509.load_der_x509_certificate(der).subject))
        return {"available": bool(subjects), "certificate_count": len(subjects), "subjects": subjects, "detail": "Peer chain metadata was extracted from the TLS session." if subjects else "The peer did not expose a certificate chain."}
    except (TypeError, ValueError, OSError):
        return {"available": False, "certificates": [], "detail": "The peer certificate chain could not be decoded safely."}


async def certificate_transparency_lookup(hostname: str) -> dict[str, Any]:
    """Query crt.sh for public CT entries; failures remain explicitly unavailable."""
    sources = (
        ("crt.sh", "https://crt.sh/", {"q": hostname, "output": "json"}),
        ("certspotter", "https://api.certspotter.com/v1/issuances", {"domain": hostname, "include_subdomains": "true", "expand": "dns_names"}),
    )
    for source, endpoint, params in sources:
        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
                response = await client.get(endpoint, params=params, headers={"Accept": "application/json", "User-Agent": "THREATLENS-passive-tls/1.0"})
            if response.status_code != 200 or len(response.content) > 1_000_000:
                continue
            rows = response.json()
            if not isinstance(rows, list):
                continue
            matching = []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                names = str(row.get("name_value", "")).split("\n") + [str(name) for name in (row.get("dns_names") or [])]
                if hostname.casefold() in {name.casefold().lstrip("*.") for name in names}:
                    matching.append(row)
            return {"available": True, "source": source, "domain": hostname, "entry_count": len(matching), "latest_issuance": max((str(row.get("not_before") or row.get("not_before_date")) for row in matching), default=None), "domain_match": bool(matching)}
        except (httpx.HTTPError, ValueError, RuntimeError, TypeError):
            continue
    return {"available": False, "source": "crt.sh+certspotter", "domain": hostname, "detail": "Certificate Transparency data was unavailable or did not return a verifiable matching entry."}


async def _mixed_content_sample(url: str, addresses: list[str], settings: Settings) -> dict[str, Any]:
    parts = urlsplit(url)
    if parts.scheme != "https":
        return {"available": False, "detail": "Mixed-content inspection applies only to HTTPS pages."}
    hostname = parts.hostname or ""
    port = 443
    target = parts.path or "/"
    if parts.query:
        target += f"?{parts.query}"
    request = f"GET {target} HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: THREATLENS-passive-tls/1.0\r\nAccept: text/html\r\nRange: bytes=0-{settings.url_scan_max_response_bytes - 1}\r\nConnection: close\r\n\r\n".encode("ascii")
    context = ssl.create_default_context()
    for address in addresses:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port, ssl=context, server_hostname=hostname), timeout=settings.url_scan_connect_timeout_seconds)
            writer.write(request)
            await writer.drain()
            sample = await asyncio.wait_for(reader.read(settings.url_scan_max_response_bytes), timeout=settings.url_scan_total_timeout_seconds)
            text = sample.decode("utf-8", errors="ignore")
            header, _, body = text.partition("\r\n\r\n")
            if "text/html" not in header.casefold():
                return {"available": False, "detail": "The bounded response was not identified as HTML."}
            urls = re.findall(r"(?:src|href)\s*=\s*[\"'](http://[^\"']+)[\"']|url\(\s*(http://[^)\s]+)", body, re.IGNORECASE)
            matches = [item for pair in urls for item in pair if item]
            return {"available": True, "detected": bool(matches), "http_resources": matches[:100], "detail": "A bounded HTML sample was inspected; scripts were not executed."}
        except (OSError, ssl.SSLError, asyncio.TimeoutError, UnicodeError):
            continue
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
    return {"available": False, "detail": "The bounded HTML sample could not be safely retrieved."}


async def _tls_probe(hostname: str, addresses: list[str], settings: Settings) -> dict[str, Any]:
    context = ssl.create_default_context()
    last_error: Exception | None = None
    port = 443
    for address in addresses:
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(address, port, ssl=context, server_hostname=hostname),
                timeout=settings.url_scan_connect_timeout_seconds,
            )
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                raise ssl.SSLError("TLS session details were unavailable")
            der = ssl_object.getpeercert(binary_form=True)
            if not der:
                raise ssl.SSLError("Peer certificate was unavailable")
            certificate = x509.load_der_x509_certificate(der)
            now = datetime.now(UTC)
            not_before = certificate.not_valid_before_utc
            not_after = certificate.not_valid_after_utc
            sans: list[str] = []
            try:
                sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass
            key_algorithm, key_size = _key_details(certificate.public_key())
            return {
                "hostname": hostname,
                "hostname_matching": True,
                "validity_start": not_before.isoformat(),
                "validity_end": not_after.isoformat(),
                "expired": now > not_after,
                "expires_soon": (not_after - now).days <= 30,
                "subject_alternative_names": sans[:100],
                "issuer": _name(certificate.issuer),
                "subject": _name(certificate.subject),
                "chain": _peer_chain(ssl_object),
                "key_algorithm": key_algorithm,
                "key_size": key_size,
                "signature_algorithm": certificate.signature_hash_algorithm.name if certificate.signature_hash_algorithm else None,
                "tls_version": ssl_object.version(),
                "cipher": ssl_object.cipher()[0] if ssl_object.cipher() else None,
                "revocation_checked": False,
                "certificate_transparency": {"available": False, "detail": "Certificate Transparency lookup is performed after the TLS session."},
            }
        except (OSError, ssl.SSLError, asyncio.TimeoutError, ValueError) as error:
            last_error = error
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
    raise last_error or OSError("TLS connection failed")


async def analyze_tls(url: str, settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    normalized = normalize_url(url)
    parts = urlsplit(normalized)
    if parts.scheme != "https":
        return {"url": normalized, "available": False, "reason": "TLS analysis only applies to HTTPS URLs.", "certificate": None}
    hostname = parts.hostname or ""
    try:
        addresses = await resolve_public_addresses(hostname, settings.url_scan_connect_timeout_seconds)
        certificate = await _tls_probe(hostname, addresses, settings)
        certificate["certificate_transparency"] = await certificate_transparency_lookup(hostname)
    except (UnsafeTarget, OSError, ssl.SSLError, asyncio.TimeoutError, ValueError) as error:
        return {
            "url": normalized,
            "available": False,
            "reason": "The TLS connection could not be safely verified.",
            "error_type": type(error).__name__,
            "certificate": None,
            "limitations": ["No certificate conclusion was drawn from the failed handshake."],
        }
    return {"url": normalized, "available": True, "certificate": certificate, "limitations": ["Certificate validity does not establish website trust.", "Revocation was not checked."]}


async def analyze_security_headers(url: str, settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    normalized = normalize_url(url)
    parts = urlsplit(normalized)
    hostname = parts.hostname or ""
    try:
        addresses = await resolve_public_addresses(hostname, settings.url_scan_connect_timeout_seconds)
        status, headers = await _request_response_headers(normalized, addresses, settings)
    except (UnsafeTarget, OSError, ssl.SSLError, asyncio.TimeoutError, ValueError) as error:
        return {
            "url": normalized,
            "available": False,
            "http_status": None,
            "headers": {},
            "missing": list(SECURITY_HEADERS.values()),
            "findings": [],
            "mixed_content": {"available": False, "detail": "Response content was not safely accessible."},
            "limitations": ["No header conclusion was drawn from the failed connection.", f"Failure type: {type(error).__name__}"],
        }
    present = {key: bool(headers.get(key)) for key in SECURITY_HEADERS}
    values = {SECURITY_HEADERS[key]: headers.get(key) for key in SECURITY_HEADERS if headers.get(key)}
    findings: list[dict[str, str]] = []
    for key, label in SECURITY_HEADERS.items():
        raw = headers.get(key, "")
        if not raw:
            findings.append({"header": label, "status": "missing", "remediation": f"Consider adding {label} after testing compatibility."})
            continue
        weak = (
            (key == "strict-transport-security" and "max-age=" not in raw.lower())
            or (key == "x-content-type-options" and raw.casefold() != "nosniff")
            or (key == "x-frame-options" and raw.casefold() not in {"deny", "sameorigin"})
            or (key == "content-security-policy" and not raw.strip())
        )
        findings.append({"header": label, "status": "weak" if weak else "present", "remediation": f"Review the {label} value for a policy appropriate to the site." if weak else "No immediate presence issue observed."})
    mixed_content = await _mixed_content_sample(normalized, addresses, settings)
    return {
        "url": normalized,
        "available": True,
        "http_status": status,
        "headers": {SECURITY_HEADERS[key]: ("present" if value else "missing") for key, value in present.items()},
        "values": values,
        "findings": findings,
        "missing": [SECURITY_HEADERS[key] for key, value in present.items() if not value],
        "mixed_content": mixed_content,
        "limitations": ["Header presence is not a complete security assessment.", "Response bodies and scripts were not executed."],
    }
