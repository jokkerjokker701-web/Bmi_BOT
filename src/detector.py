import re
from urllib.parse import urlparse
import ipaddress
import httpx

PHISH_WORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "secure", "security", "update", "unlock", "bonus", "free", "airdrop",
    "wallet", "claim", "password", "support", "restore", "confirm"
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "cam", "lol", "icu", "work", "party"
}

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "cutt.ly", "shorturl.at", "rebrand.ly"
}

URL_RE = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)


def extract_urls(text: str) -> list[str]:
    if not text:
        return []
    return URL_RE.findall(text)


def normalize_to_url(text: str) -> str | None:
    """
    'kun.uz' -> 'https://kun.uz'
    'tvcom.uz/uzb' -> 'https://tvcom.uz/uzb'
    """
    t = (text or "").strip()
    if not t:
        return None

    urls = extract_urls(t)
    if urls:
        return urls[0]

    if "." in t and " " not in t:
        if not t.startswith(("http://", "https://")):
            return "https://" + t
        return t

    return None


async def expand_url(url: str) -> tuple[str, list[str]]:
    """
    Qisqartirilgan bo'lishi mumkin bo'lgan linkni HEAD/GET bilan ochib ko'ramiz.
    Kontentni yuklamaymiz, faqat redirectlarni kuzatamiz.
    """
    reasons = []
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except Exception:
        return url, ["URL format noto‘g‘ri"]

    if host in SHORTENERS:
        reasons.append("Qisqartirilgan (short) link aniqlandi")

    # shortener bo'lmasa ham, ba'zan redirect bo'lishi mumkin - ammo resursni zo'rlab ochmaymiz.
    # Faqat shortener bo'lsa agressivroq qilamiz.
    if host not in SHORTENERS:
        return url, reasons

    timeout = httpx.Timeout(6.0, connect=6.0)
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
        try:
            r = await client.head(url)
            final_url = str(r.url)
            if final_url != url:
                reasons.append("Short link ochildi (HEAD redirect)")
            return final_url, reasons
        except Exception:
            # HEAD ba'zida blok bo'ladi, GET bilan urinamiz
            try:
                r = await client.get(url)
                final_url = str(r.url)
                if final_url != url:
                    reasons.append("Short link ochildi (GET redirect)")
                return final_url, reasons
            except Exception:
                reasons.append("Short linkni ochib bo‘lmadi (timeout yoki blok)")
                return url, reasons


def score_url(url: str, final_url: str, expand_reasons: list[str]) -> dict:
    reasons: list[str] = []
    score = 0

    # URL parse
    try:
        p = urlparse(final_url)
        host = p.hostname or ""
        scheme = (p.scheme or "").lower()
        path = (p.path or "").lower()
        query = (p.query or "").lower()
        full = (final_url or "").lower()
    except Exception:
        return {
            "score": 90,
            "level_name": "HIGH",
            "level_emoji": "🔴",
            "reasons": ["URL format noto‘g‘ri"],
        }

    if not host:
        return {
            "score": 90,
            "level_name": "HIGH",
            "level_emoji": "🔴",
            "reasons": ["Domen topilmadi"],
        }

    # 1) HTTPS yo'q
    if scheme != "https":
        score += 20
        reasons.append("HTTPS ishlatilmagan")

    # 2) IP manzil bilan domen (juda shubhali)
    try:
        ipaddress.ip_address(host)
        score += 35
        reasons.append("Domen o‘rniga IP manzil ishlatilgan")
    except Exception:
        pass

    # 3) URL ichida @ (phishing usuli)
    if "@" in final_url:
        score += 25
        reasons.append("URL ichida '@' bor (yashirish usuli bo‘lishi mumkin)")

    # 4) Punycode / xn-- (IDN spoof bo'lishi mumkin)
    if "xn--" in host:
        score += 20
        reasons.append("Punycode domen (xn--) aniqlangan")

    # 5) Shubhali so'zlar
    if any(w in full for w in PHISH_WORDS):
        score += 20
        reasons.append("Phishingga xos so‘zlar bor (login/verify/claim/...)")

    # 6) Juda uzun URL
    if len(final_url) > 110:
        score += 10
        reasons.append("URL juda uzun")

    # 7) Juda ko‘p subdomain
    if host.count(".") >= 4:
        score += 10
        reasons.append("Subdomainlar juda ko‘p")

    # 8) Domen ichida juda ko‘p '-'
    if host.count("-") >= 3:
        score += 10
        reasons.append("Domen ichida juda ko‘p '-' bor")

    # 9) Shubhali TLD
    tld = host.rsplit(".", 1)[-1].lower() if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        score += 10
        reasons.append(f"Shubhali TLD: .{tld}")

    # 10) Redirect parametrlari
    if any(k in query for k in ["redirect=", "url=", "next=", "target=", "dest="]):
        score += 10
        reasons.append("Redirect parametrlari bor (redirect/url/next/...)")

    # expand sabablarini ham qo'shamiz
    for r in expand_reasons:
        reasons.append(r)
        # short link bo'lsa riskni biroz oshiramiz
        if "Qisqartirilgan" in r:
            score += 10
        if "ochib bo‘lmadi" in r:
            score += 10

    # Score 0..100
    score = max(0, min(100, score))

    # Level
    if score >= 60:
        level_name, level_emoji = "HIGH", "🔴"
    elif score >= 35:
        level_name, level_emoji = "MEDIUM", "🟠"
    else:
        level_name, level_emoji = "LOW", "🟢"

    return {
        "score": score,
        "level_name": level_name,
        "level_emoji": level_emoji,
        "reasons": reasons,
    }


async def analyze_text(text: str) -> list[dict]:
    """
    main.py shu funksiyani chaqiradi.
    Natija list[dict] (1-3 link).
    """
    raw = normalize_to_url(text)
    if not raw:
        return []

    final_url, expand_reasons = await expand_url(raw)
    scored = score_url(raw, final_url, expand_reasons)

    return [{
        "input_url": raw,
        "final_url": final_url,
        "score": scored["score"],
        "level_name": scored["level_name"],
        "level_emoji": scored["level_emoji"],
        "reasons": scored["reasons"],
    }]
