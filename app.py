from __future__ import annotations

import streamlit as st
import re
import urllib.parse
import socket
import ssl
import datetime
import requests
from collections import Counter

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Phishing Link Detector",
    page_icon="🛡️",
    layout="centered",
)

# ── Helpers ───────────────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account", "banking",
    "password", "confirm", "paypal", "apple", "microsoft", "amazon", "netflix",
    "ebay", "google", "facebook", "instagram", "support", "helpdesk",
    "webscr", "cmd=", "dispatch", "checkout", "wallet", "crypto", "free",
    "winner", "prize", "claim", "urgent", "alert", "suspended", "limited",
]

TRUSTED_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".io", ".co"}

IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def extract_features(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    path     = parsed.path or ""
    full     = url.lower()

    features = {}

    # 1. URL length
    features["url_length"]        = len(url)
    features["long_url"]          = len(url) > 75

    # 2. Uses IP address instead of domain
    features["uses_ip"]           = bool(IP_PATTERN.match(hostname))

    # 3. HTTPS
    features["has_https"]         = parsed.scheme == "https"

    # 4. Count of dots in hostname
    features["dot_count"]         = hostname.count(".")
    features["excessive_dots"]    = hostname.count(".") > 3

    # 5. Count of suspicious keywords
    kw_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
    features["suspicious_keywords"] = kw_hits
    features["keyword_count"]     = len(kw_hits)

    # 6. Special character counts
    features["hyphen_count"]      = hostname.count("-")
    features["at_sign"]           = "@" in url
    features["double_slash"]      = url.count("//") > 1
    features["hex_chars"]         = bool(re.search(r"%[0-9a-fA-F]{2}", url))

    # 7. Subdomain depth
    parts = [p for p in hostname.split(".") if p]
    features["subdomain_depth"]   = max(len(parts) - 2, 0)
    features["deep_subdomain"]    = features["subdomain_depth"] > 2

    # 8. TLD check
    tld = "." + parts[-1] if parts else ""
    features["tld"]               = tld
    features["uncommon_tld"]      = tld not in TRUSTED_TLDS

    # 9. Brand impersonation (well-known brand in subdomain/path but not TLD-owner)
    BRANDS = ["paypal", "apple", "microsoft", "amazon", "netflix", "google",
              "facebook", "instagram", "ebay", "bankofamerica", "chase"]
    brand_hits = [b for b in BRANDS if b in hostname and not hostname.endswith(b + tld)]
    features["brand_impersonation"] = brand_hits

    # 10. Shortener service
    SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
                  "rb.gy", "is.gd", "buff.ly", "short.io", "cutt.ly"]
    features["is_shortener"]      = any(s in hostname for s in SHORTENERS)

    # 11. Port in URL
    features["non_standard_port"] = parsed.port not in (None, 80, 443)

    # 12. Path depth
    path_parts = [p for p in path.split("/") if p]
    features["path_depth"]        = len(path_parts)

    # 13. Digit ratio in hostname
    digit_count = sum(c.isdigit() for c in hostname)
    features["digit_ratio"]       = round(digit_count / max(len(hostname), 1), 2)

    return features


def score_url(features: dict) -> tuple[int, list[str]]:
    """Return (risk_score 0-100, list_of_reasons)."""
    score   = 0
    reasons = []

    if features["uses_ip"]:
        score += 30
        reasons.append("🔴 URL uses an IP address instead of a domain name")

    if not features["has_https"]:
        score += 20
        reasons.append("🔴 No HTTPS — connection is not encrypted")

    if features["long_url"]:
        score += 10
        reasons.append(f"🟠 Unusually long URL ({features['url_length']} chars)")

    if features["excessive_dots"]:
        score += 10
        reasons.append(f"🟠 Excessive dots in hostname ({features['dot_count']})")

    if features["keyword_count"] >= 2:
        score += 15
        reasons.append(f"🟠 Multiple suspicious keywords: {', '.join(features['suspicious_keywords'])}")
    elif features["keyword_count"] == 1:
        score += 7
        reasons.append(f"🟡 Suspicious keyword found: {', '.join(features['suspicious_keywords'])}")

    if features["at_sign"]:
        score += 20
        reasons.append("🔴 @ symbol in URL — browser ignores everything before it")

    if features["double_slash"]:
        score += 15
        reasons.append("🟠 Double slash redirection detected in URL path")

    if features["hyphen_count"] > 2:
        score += 10
        reasons.append(f"🟠 Many hyphens in domain ({features['hyphen_count']}) — common in fake domains")

    if features["deep_subdomain"]:
        score += 15
        reasons.append(f"🟠 Deep subdomain structure (depth {features['subdomain_depth']})")

    if features["brand_impersonation"]:
        score += 25
        reasons.append(f"🔴 Brand name in hostname but domain is not official: {', '.join(features['brand_impersonation'])}")

    if features["is_shortener"]:
        score += 20
        reasons.append("🟠 URL is a known shortener service — destination is hidden")

    if features["non_standard_port"]:
        score += 15
        reasons.append("🟠 Non-standard port number detected")

    if features["hex_chars"]:
        score += 10
        reasons.append("🟡 URL-encoded (hex) characters found — possible obfuscation")

    if features["digit_ratio"] > 0.3:
        score += 10
        reasons.append(f"🟡 High digit ratio in hostname ({features['digit_ratio']:.0%})")

    if features["uncommon_tld"] and not features["uses_ip"]:
        score += 5
        reasons.append(f"🟡 Uncommon TLD: {features['tld']}")

    score = min(score, 100)
    return score, reasons


def verdict(score: int) -> tuple[str, str]:
    if score >= 70:
        return "⛔ HIGH RISK — Likely Phishing", "red"
    elif score >= 40:
        return "⚠️ MEDIUM RISK — Suspicious", "orange"
    else:
        return "✅ LOW RISK — Likely Safe", "green"


def check_ssl(hostname: str) -> dict:
    result = {"valid": False, "issuer": "N/A", "expires": "N/A", "error": None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=5),
            server_hostname=hostname,
        ) as s:
            cert = s.getpeercert()
            issuer = dict(x[0] for x in cert.get("issuer", []))
            result["valid"]   = True
            result["issuer"]  = issuer.get("organizationName", "Unknown")
            not_after         = cert.get("notAfter", "")
            if not_after:
                exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                result["expires"] = exp.strftime("%Y-%m-%d")
    except Exception as e:
        result["error"] = str(e)
    return result


def resolve_shortener(url: str) -> str | None:
    try:
        resp = requests.head(url, allow_redirects=True, timeout=5)
        if resp.url != url:
            return resp.url
    except Exception:
        pass
    return None


# ── UI ────────────────────────────────────────────────────────────────────────

st.markdown(
    """
    <h1 style='text-align:center;'>🛡️ Phishing Link Detector</h1>
    <p style='text-align:center; color:#57606a;'>
        Paste any URL below to instantly analyse it for phishing indicators.
    </p>
    """,
    unsafe_allow_html=True,
)

st.divider()

url_input = st.text_input(
    "Enter URL to analyse",
    placeholder="https://example.com/login",
    label_visibility="visible",
)

col1, col2 = st.columns([1, 3])
with col1:
    analyse_btn = st.button("🔍 Analyse", use_container_width=True, type="primary")
with col2:
    deep_check  = st.checkbox("Deep check (SSL + redirect resolution)", value=False)

st.divider()

if analyse_btn:
    if not url_input.strip():
        st.warning("Please enter a URL first.")
    else:
        url = normalize_url(url_input)

        with st.spinner("Analysing URL …"):
            features = extract_features(url)
            score, reasons = score_url(features)
            label, colour  = verdict(score)

        # ── Verdict banner ────────────────────────────────────────────────────
        st.markdown(
            f"""
            <div style='
                background: {"#fff1f0" if colour=="red" else "#fffbe6" if colour=="orange" else "#f6ffed"};
                border: 2px solid {"#ff4d4f" if colour=="red" else "#faad14" if colour=="orange" else "#52c41a"};
                border-radius: 10px;
                padding: 20px;
                text-align: center;
            '>
                <h2 style='color:{"#cf1322" if colour=="red" else "#d46b08" if colour=="orange" else "#237804"};
                           margin:0;'>{label}</h2>
                <p style='font-size:1.1rem; margin:6px 0 0;'>Risk Score: <strong>{score}/100</strong></p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("### 📊 Risk Score")
        st.progress(score / 100)

        # ── Findings ──────────────────────────────────────────────────────────
        if reasons:
            st.markdown("### 🔎 Findings")
            for r in reasons:
                st.markdown(f"- {r}")
        else:
            st.success("No suspicious indicators found.")

        # ── Feature details ───────────────────────────────────────────────────
        with st.expander("📋 Detailed Feature Breakdown"):
            parsed = urllib.parse.urlparse(url)
            st.markdown(f"""
| Feature | Value |
|---|---|
| Scheme | `{parsed.scheme}` |
| Hostname | `{parsed.hostname}` |
| Path | `{parsed.path or '/'}` |
| URL Length | `{features['url_length']}` |
| Dot Count | `{features['dot_count']}` |
| Hyphen Count | `{features['hyphen_count']}` |
| Subdomain Depth | `{features['subdomain_depth']}` |
| TLD | `{features['tld']}` |
| Digit Ratio | `{features['digit_ratio']:.0%}` |
| Uses IP | `{features['uses_ip']}` |
| Has HTTPS | `{features['has_https']}` |
| @ Symbol | `{features['at_sign']}` |
| Double Slash | `{features['double_slash']}` |
| Hex Characters | `{features['hex_chars']}` |
| Known Shortener | `{features['is_shortener']}` |
| Non-standard Port | `{features['non_standard_port']}` |
""")

        # ── Deep check ────────────────────────────────────────────────────────
        if deep_check:
            hostname = parsed.hostname or ""

            with st.spinner("Running deep checks …"):
                # Shortener resolution
                if features["is_shortener"]:
                    resolved = resolve_shortener(url)
                    if resolved:
                        st.info(f"🔗 Shortener resolves to: `{resolved}`")

                # SSL check
                if hostname:
                    ssl_info = check_ssl(hostname)
                    st.markdown("### 🔒 SSL Certificate")
                    if ssl_info["valid"]:
                        st.success(
                            f"Valid certificate  |  Issuer: **{ssl_info['issuer']}**  |  Expires: **{ssl_info['expires']}**"
                        )
                    else:
                        st.error(
                            f"SSL check failed: {ssl_info['error']}"
                        )

        st.divider()

        # ── Bulk history (session) ─────────────────────────────────────────────
        if "history" not in st.session_state:
            st.session_state.history = []
        st.session_state.history.insert(0, {"url": url, "score": score, "verdict": label})

if "history" in st.session_state and st.session_state.history:
    with st.expander(f"📜 Session History ({len(st.session_state.history)} URLs)"):
        for item in st.session_state.history:
            st.markdown(f"- **{item['score']}/100** — `{item['url']}` → {item['verdict']}")

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <hr style='margin-top:40px;'>
    <p style='text-align:center; font-size:12px; color:#57606a;'>
        Phishing Link Detector · Built with Python &amp; Streamlit ·
        <em>For educational use only — always verify with professional security tools.</em>
    </p>
    """,
    unsafe_allow_html=True,
)
