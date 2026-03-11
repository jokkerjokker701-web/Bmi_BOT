import asyncio
import ipaddress
import re
import socket
from urllib.parse import parse_qs, urlparse

import httpx
import tldextract

URL_RE = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)

SHORTENER_DOMAINS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
    "ow.ly",
    "shorturl.at",
    "soo.gd",
    "trib.al",
    "shorte.st",
    "buff.ly",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "xyz",
    "top",
    "click",
    "link",
    "cam",
    "lol",
    "icu",
    "work",
    "party",
    "gq",
    "tk",
    "ml",
    "cf",
    "support",
    "shop",
    "buzz",
}

PHISH_WORDS = [
    "login",
    "log-in",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "security",
    "update",
    "unlock",
    "bonus",
    "free",
    "airdrop",
    "wallet",
    "claim",
    "password",
    "support",
    "restore",
    "authorize",
    "confirm",
    "billing",
    "invoice",
    "bank",
    "card",
    "otp",
    "2fa",
    "crypto",
    "gift",
    "reward",
]

BRAND_WORDS = [
    "telegram",
    "paypal",
    "visa",
    "mastercard",
    "bank",
    "google",
    "apple",
    "microsoft",
    "facebook",
    "instagram",
    "amazon",
]

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}


def extract_urls(text: str) -> list[str]:
    return URL_RE.findall(text or "")


def normalize_to_url(text: str) -> str | None:
    text = (text or "").strip()
    if not text:
        return None

    found = extract_urls(text)
    if found:
        return found[0]

    if "." in text and " " not in text:
        if not text.startswith(("http://", "https://")):
            return "https://" + text
        return text

    return None


async def dns_resolves(host: str) -> bool:
    loop = asyncio.get_running_loop()

    def _resolve():
        socket.gethostbyname(host)

    try:
        await loop.run_in_executor(None, _resolve)
        return True
    except Exception:
        return False


async def expand_url(url: str):
    reasons = []
    redirected = False
    status_code = None

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if host in SHORTENER_DOMAINS:
        reasons.append("Short link aniqlandi")

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(10.0, connect=8.0),
        headers=DEFAULT_HEADERS,
    ) as client:
        try:
            resp = await client.head(url)
            status_code = resp.status_code
            final_url = str(resp.url)
            if final_url != url:
                redirected = True
                reasons.append("Redirect mavjud")
            elif status_code >= 400 and host in SHORTENER_DOMAINS:
                reasons.append(f"Short link server xatosi qaytardi: HTTP {status_code}")
            return final_url, reasons, redirected, status_code
        except Exception:
            try:
                resp = await client.get(url)
                status_code = resp.status_code
                final_url = str(resp.url)
                if final_url != url:
                    redirected = True
                    reasons.append("Redirect mavjud")
                elif status_code >= 400 and host in SHORTENER_DOMAINS:
                    reasons.append(f"Short link server xatosi qaytardi: HTTP {status_code}")
                return final_url, reasons, redirected, status_code
            except Exception:
                if host in SHORTENER_DOMAINS:
                    reasons.append("Short link ochib bo‘lmadi")
                return url, reasons, False, None


async def fetch_page(url: str):
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(8.0, connect=6.0),
            headers=DEFAULT_HEADERS,
        ) as client:
            resp = await client.get(url)
            ctype = (resp.headers.get("content-type") or "").lower()
            text = ""
            if "text/html" in ctype or "text/plain" in ctype:
                text = resp.text[:120000]
            return text, resp.status_code
    except Exception:
        return "", None


async def analyze_url(text: str):
    raw_url = normalize_to_url(text)
    if not raw_url:
        return {
            "input_url": text.strip(),
            "final_url": text.strip(),
            "risk_score": 95,
            "verdict": "danger",
            "reasons": ["URL topilmadi yoki format noto‘g‘ri"],
        }

    final_url, expand_reasons, redirected, expand_status = await expand_url(raw_url)
    parsed = urlparse(final_url)
    host = (parsed.hostname or "").lower()
    full_url = final_url.lower()
    path_qs = f"{parsed.path or ''}?{parsed.query or ''}".lower()

    reasons = []
    risk = 0

    def add(points: int, reason: str):
        nonlocal risk
        risk += points
        if reason not in reasons:
            reasons.append(reason)

    is_short = host in SHORTENER_DOMAINS

    if is_short:
        add(35, "Short link")

    for r in expand_reasons:
        if r not in reasons:
            reasons.append(r)

    if redirected:
        add(15, "Redirect mavjud")

    if expand_status and expand_status >= 400:
        add(22, f"Server xatosi: HTTP {expand_status}")

    if is_short and expand_status and expand_status >= 400:
        add(18, "Short link ochilmadi, yashirin manzil bo‘lishi mumkin")

    if parsed.scheme != "https":
        add(15, "HTTPS ishlatilmagan")

    if host and not await dns_resolves(host):
        add(20, "DNS resolve bo‘lmadi")

    try:
        ipaddress.ip_address(host)
        add(30, "Domen o‘rniga IP manzil ishlatilgan")
    except Exception:
        pass

    if "xn--" in host:
        add(20, "Punycode domen aniqlangan")

    ext = tldextract.extract(host)
    tld = (ext.suffix or "").split(".")[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        add(16, f"Shubhali TLD: .{tld}")

    if len(final_url) > 120:
        add(8, "URL juda uzun")

    if host.count(".") >= 4:
        add(12, "Subdomainlar juda ko‘p")

    if host.count("-") >= 3:
        add(8, "Domen ichida tire juda ko‘p")

    if "@" in final_url:
        add(18, "URL ichida '@' belgisi bor")

    if any(k in path_qs for k in ["redirect=", "url=", "next=", "target=", "dest="]):
        add(10, "Redirect parametrlari bor")

    url_hits = [w for w in PHISH_WORDS if w in full_url]
    if url_hits:
        add(20, "URL ichida phishing kalit so‘zlar bor")

    brand_hits = [w for w in BRAND_WORDS if w in full_url]
    if len(brand_hits) >= 2:
        add(10, "URL ichida brendga o‘xshash aldov so‘zlari bor")

    qs = parse_qs(parsed.query)
    if len(qs) >= 6:
        add(8, "So‘rov parametrlari juda ko‘p")

    page_text, page_status = await fetch_page(final_url)

    if page_status and page_status >= 400:
        add(8, f"Sahifa HTTP {page_status} qaytardi")

    if page_text:
        lower_page = page_text.lower()
        page_hits = [w for w in PHISH_WORDS if w in lower_page]
        if len(page_hits) >= 2:
            add(14, "Sahifa ichida phishingga xos so‘zlar topildi")
        if "password" in lower_page and "login" in lower_page:
            add(12, "Sahifa login/parol so‘rayotganga o‘xshaydi")
        if "otp" in lower_page or "verification code" in lower_page:
            add(10, "Sahifa tasdiqlash kodi so‘rayotganga o‘xshaydi")

    # Maxsus qoida: short link + 4xx => juda xavfli
    if is_short and expand_status and expand_status >= 400:
        risk = max(risk, 72)

    risk = max(0, min(100, risk))

    if risk >= 60:
        verdict = "danger"
    elif risk >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"

    if not reasons:
        reasons.append("Kuchli shubha topilmadi")

    return {
        "input_url": raw_url,
        "final_url": final_url,
        "risk_score": risk,
        "verdict": verdict,
        "reasons": reasons,
    }


def safe_md(text: str) -> str:
    if text is None:
        return ""
    escape_chars = r"_*[]()~`>#+-=|{}.!"
    out = str(text)
    for ch in escape_chars:
        out = out.replace(ch, "\\" + ch)
    return out


def format_result_message(result: dict) -> str:
    risk = int(result["risk_score"])
    safety_score = max(0, 100 - risk)

    if result["verdict"] == "safe":
        status_line = "🟢 *Xavfsizroq*"
        detection = "0 / 10"
    elif result["verdict"] == "suspicious":
        status_line = "🟡 *Shubhali*"
        detection = "5 / 10"
    else:
        status_line = "🔴 *Xavfli*"
        detection = "9 / 10"

    reasons_text = "\n".join(f"• {safe_md(r)}" for r in result["reasons"])

    return (
        "🔍 *Havola tekshiruvi*\n\n"
        f"🔗 *Link:* `{safe_md(result['input_url'])}`\n"
        f"➡️ *Asl manzil:* `{safe_md(result['final_url'])}`\n\n"
        f"📊 *Xavfsizlik balli:* `{safety_score}/100`\n"
        f"🧪 *Aniqlash darajasi:* `{detection}`\n"
        f"⚠️ *Holat:* {status_line}\n\n"
        f"🧠 *Aniqlangan sabablar:*\n{reasons_text}\n\n"
        "📌 *Tavsiya:*\n"
        "Havola shubhali bo‘lsa uni ochmang, parol, karta ma'lumoti yoki OTP kiritmang."
    )