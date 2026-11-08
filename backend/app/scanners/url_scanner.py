"""Conservative URL assessment with DNS-pinned, redirect-by-redirect HTTP access."""

import asyncio
import ipaddress
import logging
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin, urlsplit
from uuid import UUID

import httpx

from app.core.config import Settings, get_settings
from app.scanners.url_validation import UnsafeTarget, normalize_url, resolve_public_addresses

logger = logging.getLogger("threatlens.scanner.url")
EventSink = Callable[[str, str, str, dict[str, Any]], Awaitable[None]]


@dataclass
class Finding:
    category: str
    title: str
    description: str
    severity: str
    evidence: dict[str, Any]
    source: str
    confidence: float


@dataclass
class ScanOutcome:
    risk_level: str
    risk_score: int
    summary: str
    findings: list[Finding] = field(default_factory=list)


class ReputationLookupUnavailable(RuntimeError):
    """Trusted threat-intelligence lookup could not complete."""


async def _request_response_headers(
    url: str,
    addresses: list[str],
    settings: Settings,
) -> tuple[int, dict[str, str]]:
    """Connect only to prevalidated IPs, retaining the URL hostname for TLS SNI."""
    parts = urlsplit(url)
    hostname = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    target = parts.path or "/"
    if parts.query:
        target += f"?{parts.query}"
    host_header = f"[{hostname}]" if ":" in hostname else hostname
    if parts.port is not None:
        host_header += f":{parts.port}"
    request = (
        f"GET {target} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "User-Agent: THREATLENS-URL-Inspector/1.0\r\n"
        "Accept: text/html,application/xhtml+xml,text/plain,application/json;q=0.8,*/*;q=0.1\r\n"
        "Accept-Encoding: identity\r\n"
        f"Range: bytes=0-{settings.url_scan_max_response_bytes - 1}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    tls_context = ssl.create_default_context() if parts.scheme == "https" else None
    last_error: Exception | None = None
    for address in addresses:
        writer: asyncio.StreamWriter | None = None
        deadline = asyncio.get_running_loop().time() + settings.url_scan_total_timeout_seconds

        def remaining_timeout() -> float:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError()
            return remaining

        try:
            connect = asyncio.open_connection(
                address, port, ssl=tls_context,
                server_hostname=hostname if tls_context else None,
                limit=settings.url_scan_max_response_bytes,
            )
            reader, writer = await asyncio.wait_for(
                connect, timeout=min(settings.url_scan_connect_timeout_seconds, remaining_timeout())
            )
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=remaining_timeout())
            header_bytes = 0

            async def read_line() -> bytes:
                nonlocal header_bytes
                line = await asyncio.wait_for(reader.readline(), timeout=remaining_timeout())
                header_bytes += len(line)
                if not line or header_bytes > settings.url_scan_max_response_bytes:
                    raise OSError("Response headers exceeded the configured limit.")
                return line

            status_line = (await read_line()).decode("ascii", errors="strict").rstrip("\r\n")
            match = re.fullmatch(r"HTTP/1\.[01] ([1-5][0-9]{2})(?: .*)?", status_line)
            if not match:
                raise OSError("The HTTP response status line was invalid.")
            response_headers: dict[str, str] = {}
            for _ in range(64):
                line = await read_line()
                if line in {b"\r\n", b"\n"}:
                    return int(match.group(1)), response_headers
                decoded = line.decode("latin-1").rstrip("\r\n")
                if ":" not in decoded or decoded[:1].isspace():
                    raise OSError("The HTTP response headers were invalid.")
                name, value = decoded.split(":", 1)
                normalized_name = name.strip().casefold()
                if normalized_name in {
                    "location", "content-type", "content-length", "strict-transport-security",
                    "content-security-policy", "x-content-type-options", "x-frame-options",
                    "referrer-policy", "permissions-policy",
                }:
                    response_headers[normalized_name] = value.strip()
            raise OSError("The HTTP response had too many headers.")
        except (OSError, asyncio.TimeoutError, UnicodeError, ssl.SSLError, ValueError) as error:
            last_error = error
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, ssl.SSLError):
                    pass
    if last_error:
        raise last_error
    raise OSError("No validated destination address was available.")


async def lookup_trusted_indicator(
    url: str,
    hostname: str,
    settings: Settings | None = None,
) -> dict[str, Any] | None:
    """Query only exact domain/URL values using a backend-only key."""
    settings = settings or get_settings()
    if not settings.supabase_url or not settings.supabase_admin_key_value:
        raise ReputationLookupUnavailable("Trusted indicator storage is not configured.")
    trusted_sources = {source.strip().casefold() for source in settings.url_scan_trusted_threat_sources.split(",") if source.strip()}
    if not trusted_sources:
        raise ReputationLookupUnavailable("No trusted threat-intelligence sources are configured.")
    headers = {"apikey": settings.supabase_admin_key_value}
    if not settings.supabase_admin_key_value.startswith("sb_secret_"):
        headers["Authorization"] = f"Bearer {settings.supabase_admin_key_value}"
    base = f"{settings.supabase_url.rstrip('/')}/rest/v1/threat_indicators"
    async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
        for indicator_type, indicator_value in (("url", url), ("domain", hostname)):
            try:
                response = await client.get(
                    base,
                    headers=headers,
                    params={
                        "select": "indicator_type,indicator_value,source,threat_category,confidence,first_seen,last_seen",
                        "indicator_type": f"eq.{indicator_type}",
                        "indicator_value": f"eq.{indicator_value}",
                        "limit": "5",
                    },
                )
            except httpx.HTTPError:
                logger.warning("Threat-intelligence lookup unavailable", extra={"indicator_type": indicator_type})
                raise ReputationLookupUnavailable("Threat-intelligence request failed.")
            if response.status_code != 200:
                logger.warning("Threat-intelligence lookup returned HTTP %s", response.status_code)
                raise ReputationLookupUnavailable("Threat-intelligence request failed.")
            try:
                rows = response.json()
            except ValueError:
                raise ReputationLookupUnavailable("Threat-intelligence response was invalid.")
            if not isinstance(rows, list):
                raise ReputationLookupUnavailable("Threat-intelligence response was invalid.")
            for row in rows:
                if not isinstance(row, dict):
                    continue
                source = str(row.get("source", "")).casefold()
                category = str(row.get("threat_category", "")).casefold()
                try:
                    confidence = float(row.get("confidence", 0))
                except (TypeError, ValueError):
                    continue
                if (
                    source in trusted_sources
                    and category in {"malicious", "phishing", "malware", "fraud", "confirmed_malicious"}
                    and confidence >= settings.url_scan_confirmed_min_confidence
                    and row.get("indicator_value") == indicator_value
                    and row.get("indicator_type") == indicator_type
                ):
                    return {
                        "indicator_type": indicator_type,
                        "source": source,
                        "threat_category": category,
                        "confidence": confidence,
                        "first_seen": row.get("first_seen"),
                        "last_seen": row.get("last_seen"),
                    }
    return None


def _finding(
    category: str, title: str, description: str, points: int, confidence: float,
    evidence: dict[str, Any], source: str = "url_pattern_analysis",
) -> tuple[Finding, int]:
    severity = "high" if points >= 35 else "medium" if points >= 20 else "low"
    return Finding(category, title, description, severity, evidence, source, confidence), points


def classify_risk(score: int, settings: Settings, confirmed: bool = False) -> str:
    if confirmed:
        return "CONFIRMED_MALICIOUS"
    if score >= settings.url_scan_high_risk_score:
        return "HIGH_RISK"
    if score >= settings.url_scan_suspicious_score:
        return "SUSPICIOUS"
    return "LOW_RISK"


async def inspect_url(
    raw_url: str,
    *,
    event_sink: EventSink,
    settings: Settings | None = None,
    reputation_lookup: Callable[[str, str, Settings | None], Awaitable[dict[str, Any] | None]] = lookup_trusted_indicator,
) -> ScanOutcome:
    settings = settings or get_settings()
    url = normalize_url(raw_url)
    parsed_initial = urlsplit(url)
    hostname = parsed_initial.hostname or ""
    findings: list[Finding] = []
    score = 0
    await event_sink("url_normalized", "Domain normalized", "The URL was normalized and restricted to HTTP or HTTPS.", {"host": hostname})

    labels = hostname.split(".")
    domain_evidence = {"host": hostname, "label_count": len(labels), "idn_punycode": hostname.startswith("xn--") or ".xn--" in hostname}
    await event_sink("domain_inspected", "Domain information inspected", "The hostname structure and internationalized-domain markers were checked. Registration age is unavailable without a configured registrar source.", domain_evidence)
    if domain_evidence["idn_punycode"]:
        item, points = _finding("url_pattern", "Internationalized hostname", "The hostname contains an IDN punycode label. This can be legitimate, but can also resemble another domain.", settings.url_scan_weight_punycode, 0.62, {"idn_punycode": True})
        findings.append(item)
        score += points
    if len(labels) >= 6:
        item, points = _finding("url_pattern", "Unusually deep subdomain", "The hostname has many subdomain labels, a weak pattern signal that needs context.", settings.url_scan_weight_deep_subdomain, 0.55, {"label_count": len(labels)})
        findings.append(item)
        score += points
    if re.search(r"(?:login|verify|account|wallet|password|secure|support)", urlsplit(url).path, re.IGNORECASE):
        item, points = _finding("url_pattern", "Sensitive-action wording in path", "The URL path uses sensitive account or credential wording. This alone does not indicate malicious activity.", settings.url_scan_weight_sensitive_path, 0.5, {"path_keyword_match": True})
        findings.append(item)
        score += points
    if urlsplit(url).scheme == "http":
        item, points = _finding("transport", "Unencrypted HTTP", "The submitted URL uses HTTP, so the connection does not provide HTTPS transport protection.", settings.url_scan_weight_http, 0.9, {"scheme": "http"}, source="http_response_inspection")
        findings.append(item)
        score += points

    redirects: list[str] = []
    visited_urls = {url}
    network_complete = True
    redirect_attempted = False
    current = url
    current_stage = "dns"
    response_status: int | None = None
    try:
        for hop in range(settings.url_scan_max_redirects + 1):
            current_stage = "dns"
            current_parts = urlsplit(current)
            current_host = current_parts.hostname or ""
            addresses = await resolve_public_addresses(current_host, settings.url_scan_connect_timeout_seconds)
            await event_sink("dns_inspected", "DNS records inspected", "DNS answers were resolved for this connection hop.", {"host": current_host, "address_count": len(addresses)})
            await event_sink("destination_checked", "Destination IP checked", "Every resolved address passed public-IP validation and is pinned for this connection.", {"host": current_host, "addresses": addresses})
            current_stage = "http"
            response_status, response_headers = await _request_response_headers(current, addresses, settings)
            if current_parts.scheme == "https":
                await event_sink(
                    "tls_inspected",
                    "TLS handshake completed",
                    "The HTTPS connection completed its TLS handshake. Certificate identity and expiry details were not collected.",
                    {"host": current_host, "handshake": "completed", "certificate_details_collected": False},
                )
            content_length = response_headers.get("content-length", "")
            await event_sink("http_response_inspected", "HTTP response inspected", "Only the bounded response headers were inspected; no response body was read or saved.", {
                "http_status": response_status,
                "content_type": response_headers.get("content-type"),
                "content_length": int(content_length) if content_length.isdigit() else None,
            })
            if response_status in {301, 302, 303, 307, 308} and response_headers.get("location"):
                if hop >= settings.url_scan_max_redirects:
                    item, points = _finding("redirect_chain", "Redirect limit reached", "The target exceeded the configured redirect limit.", settings.url_scan_weight_redirect_limit, 0.8, {"redirect_count": len(redirects)}, "redirect_chain_inspection")
                    findings.append(item)
                    score += points
                    break
                redirect_attempted = True
                current_stage = "redirect_validation"
                redirect_target = normalize_url(urljoin(current, response_headers["location"]))
                redirects.append(redirect_target)
                await event_sink("redirect_inspected", "Redirect destination checked", "A redirect destination was normalized and will be checked before any connection.", {"hop": hop + 1, "host": urlsplit(redirect_target).hostname})
                if redirect_target in visited_urls:
                    item, points = _finding(
                        "redirect_chain",
                        "Redirect loop detected",
                        "The redirect chain returned to a URL that was already inspected. The loop was stopped before another request.",
                        settings.url_scan_weight_redirect_chain,
                        0.9,
                        {"redirect_count": len(redirects)},
                        "redirect_chain_inspection",
                    )
                    findings.append(item)
                    score += points
                    await event_sink(
                        "redirect_loop_detected",
                        "Redirect loop stopped",
                        "A previously visited URL was detected; no further request was made.",
                        {"redirect_count": len(redirects)},
                    )
                    break
                visited_urls.add(redirect_target)
                current = redirect_target
                continue
            # Only bounded response headers are inspected. The body is never read,
            # saved, rendered, parsed or executed, including binary/executable data.
            break
    except UnsafeTarget as error:
        network_complete = False
        blocked_redirect = redirect_attempted
        if blocked_redirect:
            item, points = _finding("redirect_chain", "Unsafe redirect destination blocked", "A redirect resolved to a local or reserved destination and was blocked before connecting.", settings.url_scan_weight_blocked_redirect, 0.94, {"redirect_count": len(redirects)}, "redirect_chain_inspection")
            findings.append(item)
            score += points
        await event_sink("destination_blocked", "Unsafe destination blocked", str(error), {
            "stage": current_stage,
            "failure_type": type(error).__name__,
            "redirect_count": len(redirects),
        })
    except (asyncio.TimeoutError, OSError, UnicodeError, ssl.SSLError, ValueError) as error:
        network_complete = False
        logger.info("URL inspection could not complete (%s)", type(error).__name__)
        await event_sink(
            "network_stage_failed",
            "Network inspection incomplete",
            "A timeout or transport error interrupted this stage. No conclusion was drawn from the incomplete response.",
            {"stage": current_stage, "failure_type": type(error).__name__, "redirect_count": len(redirects)},
        )

    await event_sink(
        "redirect_chain_inspected",
        "Redirect chain inspected" if network_complete else "Redirect inspection stopped early",
        "Each redirect destination was checked before connecting." if network_complete else "The redirect chain could not be fully inspected; remaining destinations are unknown.",
        {"redirect_count": len(redirects), "final_host": urlsplit(current).hostname,
         "http_status": response_status, "complete": network_complete},
    )
    if len(redirects) >= 3:
        item, points = _finding("redirect_chain", "Multiple redirects", "The URL redirected through several destinations. This is a weak signal and may be legitimate.", settings.url_scan_weight_redirect_chain, 0.58, {"redirect_count": len(redirects)}, "redirect_chain_inspection")
        findings.append(item)
        score += points
    reputation_targets = [(url, hostname)]
    final_host = urlsplit(current).hostname or hostname
    if current != url:
        reputation_targets.append((current, final_host))
    indicator = None
    reputation_complete = True
    try:
        for candidate_url, candidate_host in reputation_targets:
            indicator = await reputation_lookup(candidate_url, candidate_host, settings)
            if indicator:
                break
    except Exception as error:
        reputation_complete = False
        indicator = None
        logger.warning("Threat-intelligence lookup could not complete (%s)", type(error).__name__)
    await event_sink(
        "reputation_queried", "Threat intelligence checked",
        "Exact submitted and final destination indicators were checked against configured trusted sources." if reputation_complete else "Threat-intelligence lookup could not complete; no reputation conclusion was available.",
        {"target_count": len(reputation_targets), "lookup_complete": reputation_complete,
         "match_found": bool(indicator) if reputation_complete else None,
         "source": indicator.get("source") if indicator else None},
    )
    confirmed_match = bool(indicator)
    if indicator:
        findings.append(Finding(
            category="threat_intelligence",
            title="Exact match in trusted threat intelligence",
            description=f"An exact {indicator['indicator_type']} match was found in the configured {indicator['source']} feed.",
            severity="critical", evidence={
                "indicator_type": indicator["indicator_type"],
                "threat_category": indicator["threat_category"],
                "first_seen": indicator.get("first_seen"), "last_seen": indicator.get("last_seen"),
            },
            source=indicator["source"], confidence=float(indicator["confidence"]),
        ))
    if confirmed_match:
        score = max(score, settings.url_scan_high_risk_score)
        risk_level = "CONFIRMED_MALICIOUS"
        summary = "A high-confidence exact match was found in a configured trusted threat-intelligence source."
    elif not network_complete or not reputation_complete:
        risk_level = "HIGH_RISK" if score >= settings.url_scan_high_risk_score else "INCONCLUSIVE"
        summary = "The scan could not complete all network checks. No safety conclusion can be drawn."
    else:
        score = min(100, score)
        risk_level = classify_risk(score, settings, confirmed=confirmed_match)
        if risk_level == "LOW_RISK":
            summary = "No strong malicious indicators were observed by these checks. This is not proof that the website is safe."
        elif risk_level == "CONFIRMED_MALICIOUS":
            summary = "A high-confidence exact match was found in a configured trusted threat-intelligence source."
        else:
            summary = "The scan observed one or more risk signals. Review the evidence; automated results can be incomplete."
    score = min(100, score)
    await event_sink("findings_generated", "Findings generated", f"The scan recorded {len(findings)} evidence-based finding(s).", {"finding_count": len(findings)})
    await event_sink("risk_classified", "Risk classification completed", f"The configured scoring rules assigned {risk_level} with score {score}.", {"risk_level": risk_level, "risk_score": score})
    return ScanOutcome(risk_level=risk_level, risk_score=score, summary=summary, findings=findings)
