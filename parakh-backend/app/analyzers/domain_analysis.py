"""Layer 2: DNS, WHOIS domain age and SSL certificate checks."""
import asyncio
import datetime as dt
import ipaddress
import socket
import ssl
import time

from ..findings import Finding


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


async def resolve(host: str) -> list[str]:
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return []
    return sorted({i[4][0] for i in infos})


def _whois_sync(domain: str):
    import whois  # python-whois

    created = whois.whois(domain).creation_date
    if isinstance(created, list):
        created = [c for c in created if isinstance(c, dt.datetime)]
        created = min(created) if created else None
    if not isinstance(created, dt.datetime):
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=dt.timezone.utc)
    return created


async def domain_age_days(domain: str, timeout: float = 8.0) -> int | None:
    """Age in days, or None if WHOIS data is unavailable (common for some country domains)."""
    try:
        created = await asyncio.wait_for(asyncio.to_thread(_whois_sync, domain), timeout)
    except Exception:
        return None
    if not created:
        return None
    return max((dt.datetime.now(dt.timezone.utc) - created).days, 0)


def _ssl_sync(host: str, port: int) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        days_left = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400)
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        return {"checked": True, "valid": True, "days_left": days_left,
                "issuer": issuer.get("organizationName") or issuer.get("commonName"), "error": None}
    except ssl.SSLCertVerificationError as e:
        return {"checked": True, "valid": False, "days_left": None, "issuer": None, "error": e.verify_message}
    except (OSError, ssl.SSLError) as e:
        return {"checked": False, "valid": None, "days_left": None, "issuer": None, "error": str(e)}


async def ssl_check(host: str, port: int | None) -> dict:
    return await asyncio.to_thread(_ssl_sync, host, port or 443)


def domain_findings(age_days: int | None, resolved: bool, ssl_info: dict | None) -> list[Finding]:
    out: list[Finding] = []
    if age_days is not None:
        if age_days < 30:
            out.append(Finding("domain_very_new", 30, f"The domain was registered only {age_days} days ago",
                               f"ڈومین صرف {age_days} دن پہلے رجسٹر ہوا ہے", "domain"))
        elif age_days < 180:
            out.append(Finding("domain_new", 15, f"The domain is fairly new (about {age_days // 30} months old)",
                               f"ڈومین نسبتاً نیا ہے (تقریباً {age_days // 30} ماہ پرانا)", "domain"))
        elif age_days >= 730:
            out.append(Finding("domain_established", -5, f"The domain has existed for about {age_days // 365} years",
                               f"ڈومین تقریباً {age_days // 365} سال سے موجود ہے", "domain"))
    if not resolved:
        out.append(Finding("dns_fail", 10, "The domain could not be resolved (it may be offline or taken down)",
                           "ڈومین resolve نہیں ہو سکا (ہو سکتا ہے بند ہو چکا ہو)", "domain"))
    if ssl_info and ssl_info.get("checked") and ssl_info.get("valid") is False:
        out.append(Finding("ssl_invalid", 20, "The website's security certificate is invalid or does not match the domain",
                           "ویب سائٹ کا سیکیورٹی سرٹیفکیٹ غلط ہے یا ڈومین سے مطابقت نہیں رکھتا", "domain"))
    return out
