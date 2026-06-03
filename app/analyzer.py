from __future__ import annotations

import ipaddress
import json
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx


SUSPICIOUS_KEYWORDS = {
    "account",
    "auth",
    "bank",
    "billing",
    "confirm",
    "free",
    "gift",
    "login",
    "password",
    "paypal",
    "secure",
    "signin",
    "support",
    "update",
    "verify",
    "wallet",
}

URL_SHORTENERS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "tinyurl.com",
    "t.co",
}

KNOWN_BRANDS_PATH = Path(__file__).resolve().parent.parent / "data" / "known_brands.json"
MAX_REDIRECTS = int(os.getenv("PHISHGUARD_MAX_REDIRECTS", "5"))
REQUEST_TIMEOUT_SECONDS = float(os.getenv("PHISHGUARD_REQUEST_TIMEOUT_SECONDS", "5"))


@dataclass(frozen=True)
class Finding:
    name: str
    risk_points: int
    explanation: str
    category: str


def load_known_brand_domains() -> dict[str, str]:
    with KNOWN_BRANDS_PATH.open(encoding="utf-8") as brand_file:
        data = json.load(brand_file)

    return {str(brand).lower(): str(domain).lower() for brand, domain in data.items()}


def normalize_url(raw_url: str) -> str:
    candidate = raw_url.strip()
    if not candidate:
        raise ValueError("URL vide.")

    parsed = urlparse(candidate)
    if not parsed.scheme:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Seuls les schemas http et https sont acceptes.")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("URL invalide: nom de domaine introuvable.")

    return candidate


def is_private_or_reserved_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_host_ips(hostname: str) -> list[str]:
    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []

    ips: set[str] = set()
    for address in addresses:
        sockaddr = address[4]
        if sockaddr:
            ips.add(sockaddr[0])
    return sorted(ips)


def is_safe_public_target(hostname: str) -> tuple[bool, list[str], str | None]:
    if is_private_or_reserved_ip(hostname):
        return False, [hostname], "Adresse IP privee, locale ou reservee."

    resolved_ips = resolve_host_ips(hostname)
    blocked_ips = [ip for ip in resolved_ips if is_private_or_reserved_ip(ip)]
    if blocked_ips:
        return False, resolved_ips, "Le domaine resout vers une adresse privee, locale ou reservee."

    return True, resolved_ips, None


def approximate_registered_domain(hostname: str) -> str:
    if _is_any_ip(hostname):
        return hostname

    labels = [part for part in hostname.lower().strip(".").split(".") if part]
    if len(labels) <= 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


def primary_domain_label(hostname: str) -> str:
    registered_domain = approximate_registered_domain(hostname)
    if _is_any_ip(registered_domain):
        return registered_domain
    return registered_domain.split(".", 1)[0]


def levenshtein_distance(left: str, right: str, max_distance: int = 3) -> int:
    if left == right:
        return 0
    if abs(len(left) - len(right)) > max_distance:
        return max_distance + 1

    previous = list(range(len(right) + 1))
    for index_left, char_left in enumerate(left, start=1):
        current = [index_left]
        smallest = current[0]
        for index_right, char_right in enumerate(right, start=1):
            insertion = current[index_right - 1] + 1
            deletion = previous[index_right] + 1
            substitution = previous[index_right - 1] + (char_left != char_right)
            value = min(insertion, deletion, substitution)
            current.append(value)
            smallest = min(smallest, value)
        if smallest > max_distance:
            return max_distance + 1
        previous = current

    return previous[-1]


def detect_brand_impersonation(hostname: str) -> tuple[list[dict[str, Any]], list[Finding]]:
    if _is_any_ip(hostname):
        return [], []

    label = primary_domain_label(hostname)
    matches: list[dict[str, Any]] = []
    findings: list[Finding] = []

    for brand, official_domain in load_known_brand_domains().items():
        if label == brand:
            continue

        if brand in label:
            matches.append(
                {
                    "observed_label": label,
                    "target_brand": brand,
                    "official_domain": official_domain,
                    "match_type": "brand_embedded",
                }
            )
            continue

        distance = levenshtein_distance(label, brand)
        if distance <= 1 or (len(brand) >= 8 and distance <= 2):
            matches.append(
                {
                    "observed_label": label,
                    "target_brand": brand,
                    "official_domain": official_domain,
                    "match_type": "lookalike",
                    "edit_distance": distance,
                }
            )

    if matches:
        best_match = matches[0]
        findings.append(
            Finding(
                "brand_impersonation",
                35,
                (
                    "Le domaine ressemble fortement a "
                    f"{best_match['official_domain']} sans etre ce domaine officiel."
                ),
                "domain_risk",
            )
        )

    return matches, findings


def analyze_domain(parsed_url: Any) -> tuple[dict[str, Any], list[Finding]]:
    hostname = (parsed_url.hostname or "").lower()
    labels = [part for part in hostname.split(".") if part]
    findings: list[Finding] = []
    uses_ip_address = _is_any_ip(hostname)
    brand_lookalikes, brand_findings = detect_brand_impersonation(hostname)
    findings.extend(brand_findings)

    if is_private_or_reserved_ip(hostname):
        findings.append(
            Finding(
                "ip_address",
                20,
                "L'URL utilise directement une adresse IP au lieu d'un domaine lisible.",
                "domain_risk",
            )
        )

    if hostname.startswith("xn--") or ".xn--" in hostname:
        findings.append(
            Finding(
                "punycode",
                15,
                "Le domaine contient du Punycode, parfois utilise pour imiter des marques.",
                "domain_risk",
            )
        )

    if hostname.count("-") >= 2:
        findings.append(
            Finding(
                "many_hyphens",
                5,
                "Le domaine contient plusieurs tirets, un signal faible mais frequent dans les URL trompeuses.",
                "domain_risk",
            )
        )

    if len(hostname) > 60:
        findings.append(
            Finding(
                "long_domain",
                5,
                "Le nom de domaine est long, ce qui peut masquer sa vraie destination.",
                "domain_risk",
            )
        )

    subdomain_count = 0 if uses_ip_address else max(0, len(labels) - 2)
    if subdomain_count >= 3:
        findings.append(
            Finding(
                "many_subdomains",
                10,
                "L'URL contient beaucoup de sous-domaines, ce qui peut rendre le domaine reel moins visible.",
                "domain_risk",
            )
        )

    if hostname in URL_SHORTENERS:
        findings.append(
            Finding(
                "url_shortener",
                20,
                "Le domaine est un raccourcisseur d'URL, la destination finale est masquee.",
                "domain_risk",
            )
        )

    port = parsed_url.port
    if port and port not in {80, 443}:
        findings.append(
            Finding(
                "non_standard_port",
                10,
                "L'URL utilise un port non standard.",
                "transport_risk",
            )
        )

    domain_report = {
        "hostname": hostname,
        "registered_domain_estimate": approximate_registered_domain(hostname),
        "primary_label": primary_domain_label(hostname),
        "subdomain_count": subdomain_count,
        "uses_ip_address": uses_ip_address,
        "port": port,
        "brand_lookalikes": brand_lookalikes,
    }
    return domain_report, findings


def _is_any_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def analyze_keywords(url: str) -> tuple[list[str], list[Finding]]:
    lowered = url.lower()
    matches = sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lowered)
    risk = min(len(matches) * 10, 30)

    if not matches:
        return [], []

    return matches, [
        Finding(
            "suspicious_keywords",
            risk,
            "L'URL contient des mots souvent presents dans des tentatives de phishing.",
            "content_risk",
        )
    ]


async def inspect_redirects(url: str) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
            timeout=REQUEST_TIMEOUT_SECONDS,
        ) as client:
            response = await client.head(url)
    except httpx.TooManyRedirects:
        return {
            "checked": True,
            "error": f"Plus de {MAX_REDIRECTS} redirections.",
            "chain": [],
            "final_url": None,
            "redirect_count": MAX_REDIRECTS + 1,
        }, [
            Finding(
                "too_many_redirects",
                20,
                "La chaine de redirections depasse la limite prudente de l'analyse.",
                "redirect_risk",
            )
        ]
    except httpx.HTTPError as exc:
        return {
            "checked": True,
            "error": str(exc),
            "chain": [],
            "final_url": None,
            "redirect_count": 0,
        }, [
            Finding(
                "redirect_check_unavailable",
                5,
                "La verification des redirections n'a pas abouti avec une requete HEAD limitee.",
                "redirect_risk",
            )
        ]

    history = [str(item.url) for item in response.history]
    final_url = str(response.url)
    redirect_count = len(history)

    if redirect_count:
        findings.append(
            Finding(
                "redirects_present",
                min(redirect_count * 5, 20),
                "L'URL effectue une ou plusieurs redirections avant la destination finale.",
                "redirect_risk",
            )
        )

    initial = urlparse(url)
    final = urlparse(final_url)
    if initial.scheme == "https" and final.scheme == "http":
        findings.append(
            Finding(
                "https_downgrade",
                25,
                "La redirection finale degrade HTTPS vers HTTP.",
                "transport_risk",
            )
        )

    if final.hostname and initial.hostname and final.hostname.lower() != initial.hostname.lower():
        findings.append(
            Finding(
                "domain_change_after_redirect",
                10,
                "La redirection change de nom de domaine.",
                "redirect_risk",
            )
        )

    return {
        "checked": True,
        "status_code": response.status_code,
        "chain": history + [final_url],
        "final_url": final_url,
        "redirect_count": redirect_count,
    }, findings


def risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def serialize_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    return [
        {
            "name": finding.name,
            "risk_points": finding.risk_points,
            "explanation": finding.explanation,
            "category": finding.category,
        }
        for finding in findings
    ]


def build_score_breakdown(findings: list[Finding]) -> dict[str, Any]:
    categories = {
        "domain_risk": 0,
        "transport_risk": 0,
        "redirect_risk": 0,
        "content_risk": 0,
    }

    for finding in findings:
        categories[finding.category] = categories.get(finding.category, 0) + finding.risk_points

    total = min(100, sum(categories.values()))
    return {
        "total": total,
        "categories": categories,
    }


async def analyze_url(raw_url: str, demo_mode: bool = False) -> dict[str, Any]:
    normalized_url = normalize_url(raw_url)
    parsed = urlparse(normalized_url)

    findings: list[Finding] = []
    domain_report, domain_findings = analyze_domain(parsed)
    findings.extend(domain_findings)

    https_report = {
        "uses_https": parsed.scheme == "https",
        "scheme": parsed.scheme,
    }
    if parsed.scheme != "https":
        findings.append(
            Finding(
                "no_https",
                25,
                "L'URL n'utilise pas HTTPS, les echanges peuvent etre interceptes ou modifies.",
                "transport_risk",
            )
        )

    suspicious_keywords, keyword_findings = analyze_keywords(normalized_url)
    findings.extend(keyword_findings)

    hostname = parsed.hostname or ""
    if demo_mode:
        network_allowed = False
        resolved_ips = []
        block_reason = "Mode demo: aucune requete reseau n'est effectuee."
    else:
        network_allowed, resolved_ips, block_reason = is_safe_public_target(hostname)

    safety_report = {
        "network_allowed": network_allowed,
        "resolved_ips": resolved_ips,
        "block_reason": block_reason,
        "policy": "Analyse limitee: requete HEAD uniquement, timeout court, maximum 5 redirections.",
    }

    if network_allowed:
        redirect_report, redirect_findings = await inspect_redirects(normalized_url)
        findings.extend(redirect_findings)
    else:
        redirect_report = {
            "checked": False,
            "error": block_reason,
            "chain": [],
            "final_url": None,
            "redirect_count": 0,
        }

    score_breakdown = build_score_breakdown(findings)
    score = score_breakdown["total"]

    return {
        "submitted_url": raw_url,
        "normalized_url": normalized_url,
        "score": score,
        "risk_level": risk_level(score),
        "analysis_mode": "passive-light",
        "demo_mode": demo_mode,
        "score_breakdown": score_breakdown,
        "domain": domain_report,
        "https": https_report,
        "redirections": redirect_report,
        "suspicious_keywords": suspicious_keywords,
        "safety": safety_report,
        "findings": serialize_findings(findings),
        "explanation": build_score_explanation(score, findings),
    }


def build_score_explanation(score: int, findings: list[Finding]) -> str:
    if not findings:
        return "Aucun signal de risque notable detecte avec les controles limites de PhishGuard."

    top_findings = sorted(findings, key=lambda item: item.risk_points, reverse=True)[:3]
    reasons = "; ".join(finding.explanation for finding in top_findings)
    return f"Score {score}/100 base sur les principaux signaux suivants: {reasons}"
