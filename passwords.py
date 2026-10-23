import math
import re
import string

COMMON_PASSWORDS = {
    "password", "password123", "123456", "123456789", "qwerty",
    "admin", "letmein", "welcome", "iloveyou", "abc123"
}

def analyze_password(password: str) -> dict:
    checks = {
        "At least 12 characters": len(password) >= 12,
        "Contains lowercase and uppercase letters": any(c.islower() for c in password) and any(c.isupper() for c in password),
        "Contains a number": any(c.isdigit() for c in password),
        "Contains a symbol": any(c in string.punctuation for c in password),
        "Not a common password": password.lower() not in COMMON_PASSWORDS,
        "Avoids long repeated-character runs": not re.search(r"(.)\1{3,}", password),
    }
    score = int(100 * sum(checks.values()) / len(checks))
    if password.lower() in COMMON_PASSWORDS or len(password) < 8:
        score = min(score, 25)
    label = "Strong" if score >= 84 else "Moderate" if score >= 50 else "Weak"
    tips = [name for name, passed in checks.items() if not passed]
    if len(password) < 16:
        tips.append("Consider using a longer passphrase (16+ characters).")
    return {"score": score, "label": label, "checks": checks, "tips": tips}
