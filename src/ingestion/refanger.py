"""Defang / Refang utility to normalize obfuscated indicators.

Handles patterns commonly found in threat reports:
- hxxp:// -> http://, hxxps:// -> https://
- domain[.]com, 192[.]168[.]1[.]1 -> domain.com, 192.168.1.1
- admin[@]phish[.]com, admin[at]phish[.]com -> admin@phish.com
- [:] -> :
"""

import re


def refang(text: str) -> str:
    """Converts a defanged indicator or URL into its canonical executable form."""
    if not text or not isinstance(text, str):
        return ""

    refanged = text.strip()

    # Protocol refanging
    refanged = re.sub(r"^hxxps?://", lambda m: "https://" if "s" in m.group(0).lower() else "http://", refanged, flags=re.IGNORECASE)
    refanged = re.sub(r"^h[xX]{2}p://", "http://", refanged)
    refanged = re.sub(r"^h[xX]{2}ps://", "https://", refanged)
    refanged = re.sub(r"^me?://", "http://", refanged)  # rare typo in feeds

    # Bracket dots: [.], (.), {.}, [dot], (dot)
    refanged = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", refanged)
    refanged = re.sub(r"\[dot\]|\(dot\)|\{dot\}", ".", refanged, flags=re.IGNORECASE)

    # Bracket at: [@], (@), {@}, [at], (at)
    refanged = re.sub(r"\[@\]|\(@\)|\{@\}", "@", refanged)
    refanged = re.sub(r"\[at\]|\(at\)|\{at\}", "@", refanged, flags=re.IGNORECASE)

    # Bracket colons and slashes: [:], [//]
    refanged = re.sub(r"\[:\]|\(:\)", ":", refanged)
    refanged = re.sub(r"\[//\]|\(//\)", "//", refanged)

    # Strip surrounding brackets/quotes often left in feeds: "[192.168.1.1]" or "'bad.com'"
    refanged = refanged.strip("[]'\"<>()")

    return refanged
