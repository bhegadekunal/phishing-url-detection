import re
import tkinter as tk
from tkinter import messagebox
from urllib.parse import urlparse


def analyze_url(url):
    score = 0
    warnings = []

    # Add http if user does not enter a scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # 1. HTTPS check
    if parsed.scheme == "https":
        https_status = "YES"
    else:
        https_status = "NO"
        score += 1
        warnings.append("Website does not use HTTPS")

    # 2. URL length
    if len(url) > 75:
        length_status = "LONG"
        score += 1
        warnings.append("URL is unusually long")
    else:
        length_status = "NORMAL"

    # 3. IP address check
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, domain.split(":")[0]):
        ip_status = "YES"
        score += 2
        warnings.append("URL uses an IP address instead of a domain")
    else:
        ip_status = "NO"

    # 4. @ symbol
    if "@" in url:
        at_status = "YES"
        score += 2
        warnings.append("URL contains @ symbol")
    else:
        at_status = "NO"

    # 5. Suspicious keywords
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "update",
        "secure",
        "account",
        "password",
        "signin",
        "confirm",
        "banking",
        "wallet"
    ]

    found_words = []

    for word in suspicious_words:
        if word in url.lower():
            found_words.append(word)

    if found_words:
        keyword_status = "YES"
        score += 1
        warnings.append(
            "Suspicious keywords: " + ", ".join(found_words)
        )
    else:
        keyword_status = "NO"

    # 6. Subdomain check
    hostname = parsed.hostname or ""
    subdomain_count = len(hostname.split("."))

    if subdomain_count > 3:
        subdomain_status = "YES"
        score += 1
        warnings.append("URL contains many subdomains")
    else:
        subdomain_status = "NO"

    # 7. URL shortener
    shortening_services = [
        "bit.ly",
        "tinyurl.com",
        "shorturl.at",
        "t.co",
        "goo.gl"
    ]

    if any(service in domain for service in shortening_services):
        shortener_status = "YES"
        score += 1
        warnings.append("URL uses a URL shortening service")
    else:
        shortener_status = "NO"

    # Result
    if score >= 4:
        result = "HIGH RISK - POSSIBLE PHISHING"
    elif score >= 2:
        result = "SUSPICIOUS"
    else:
        result = "LOW RISK"

    return {
        "https": https_status,
        "ip": ip_status,
        "at": at_status,
        "length": length_status,
        "keywords": keyword_status,
        "subdomains": subdomain_status,
        "shortener": shortener_status,
        "score": score,
        "result": result,
        "warnings": warnings
    }


def check_url():
    url = url_entry.get().strip()

    if not url:
        messagebox.showwarning(
            "Input Required",
            "Please enter a URL."
        )
        return

    data = analyze_url(url)

    result_box.config(state="normal")
    result_box.delete("1.0", tk.END)

    result_box.insert(tk.END, "URL ANALYSIS\n")
    result_box.insert(tk.END, "-" * 45 + "\n\n")

    result_box.insert(
        tk.END,
        f"HTTPS Used           : {data['https']}\n"
    )

    result_box.insert(
        tk.END,
        f"IP Address Used      : {data['ip']}\n"
    )

    result_box.insert(
        tk.END,
        f"@ Symbol Present     : {data['at']}\n"
    )

    result_box.insert(
        tk.END,
        f"URL Length           : {data['length']}\n"
    )

    result_box.insert(
        tk.END,
        f"Suspicious Keywords  : {data['keywords']}\n"
    )

    result_box.insert(
        tk.END,
        f"Excessive Subdomains : {data['subdomains']}\n"
    )

    result_box.insert(
        tk.END,
        f"URL Shortener        : {data['shortener']}\n\n"
    )

    result_box.insert(tk.END, "-" * 45 + "\n")

    result_box.insert(
        tk.END,
        f"Risk Score           : {data['score']}\n"
    )

    result_box.insert(
        tk.END,
        f"RESULT               : {data['result']}\n"
    )

    result_box.insert(tk.END, "-" * 45 + "\n\n")

    if data["warnings"]:
        result_box.insert(tk.END, "Reasons:\n")

        for warning in data["warnings"]:
            result_box.insert(
                tk.END,
                "• " + warning + "\n"
            )
    else:
        result_box.insert(
            tk.END,
            "No obvious phishing indicators detected."
        )

    result_box.config(state="disabled")


def clear_result():
    url_entry.delete(0, tk.END)

    result_box.config(state="normal")
    result_box.delete("1.0", tk.END)
    result_box.config(state="disabled")


# ---------------- GUI ----------------

window = tk.Tk()

window.title("PhishGuard - Phishing URL Detection System")
window.geometry("700x650")
window.resizable(False, False)

# Title
title = tk.Label(
    window,
    text="PHISHGUARD",
    font=("Arial", 26, "bold")
)

title.pack(pady=(25, 5))

subtitle = tk.Label(
    window,
    text="Phishing URL Detection System",
    font=("Arial", 13)
)

subtitle.pack(pady=(0, 25))

# URL label
url_label = tk.Label(
    window,
    text="Enter URL:",
    font=("Arial", 12, "bold")
)

url_label.pack(anchor="w", padx=50)

# URL entry
url_entry = tk.Entry(
    window,
    font=("Arial", 12),
    width=70
)

url_entry.pack(
    padx=50,
    pady=10,
    ipady=8
)

# Buttons
button_frame = tk.Frame(window)
button_frame.pack(pady=10)

check_button = tk.Button(
    button_frame,
    text="CHECK URL",
    command=check_url,
    font=("Arial", 12, "bold"),
    padx=25,
    pady=10
)

check_button.pack(side="left", padx=10)

clear_button = tk.Button(
    button_frame,
    text="CLEAR",
    command=clear_result,
    font=("Arial", 12, "bold"),
    padx=25,
    pady=10
)

clear_button.pack(side="left", padx=10)

# Result box
result_box = tk.Text(
    window,
    height=20,
    width=70,
    font=("Consolas", 11),
    wrap="word"
)

result_box.pack(
    padx=40,
    pady=20
)

result_box.config(state="disabled")

# Start application
window.mainloop()