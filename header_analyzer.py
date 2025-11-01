# header_analyzer.py
import requests
import sys

def analyze_security_headers(url):
    print(f"Analyzing headers for: {url}")
    try:
        response = requests.get(url, timeout=10) # Set a timeout
        headers = response.headers
        
        print("\n--- Received Headers ---")
        for key, value in headers.items():
            print(f"{key}: {value}")
        
        print("\n--- Security Analysis ---")
        findings = []

        # X-Frame-Options
        x_frame_options = headers.get('X-Frame-Options')
        if not x_frame_options:
            findings.append("Missing 'X-Frame-Options' header: Vulnerable to Clickjacking.")
        elif x_frame_options.upper() not in ['DENY', 'SAMEORIGIN']:
            findings.append(f"Insecure 'X-Frame-Options' ({x_frame_options}): Consider 'DENY' or 'SAMEORIGIN'.")
        else:
            findings.append(f"Secure 'X-Frame-Options': {x_frame_options}")

        # Strict-Transport-Security (HSTS)
        hsts = headers.get('Strict-Transport-Security')
        if not hsts:
            findings.append("Missing 'Strict-Transport-Security' (HSTS) header: Vulnerable to SSL stripping/downgrade attacks.")
        else:
            findings.append(f"Secure 'Strict-Transport-Security' (HSTS) header: {hsts}")

        # Content-Security-Policy (CSP)
        csp = headers.get('Content-Security-Policy')
        if not csp:
            findings.append("Missing 'Content-Security-Policy' (CSP) header: Vulnerable to XSS and data injection attacks.")
        else:
            # A full CSP analysis is complex, just checking presence for this simple tool
            findings.append(f"Present 'Content-Security-Policy' header: {csp} (manual review recommended for effectiveness).")

        # X-Content-Type-Options
        x_content_type_options = headers.get('X-Content-Type-Options')
        if not x_content_type_options or x_content_type_options.lower() != 'nosniff':
            findings.append("Missing or insecure 'X-Content-Type-Options' header: Vulnerable to MIME-sniffing attacks. Should be 'nosniff'.")
        else:
            findings.append(f"Secure 'X-Content-Type-Options': {x_content_type_options}")

        # Referrer-Policy
        referrer_policy = headers.get('Referrer-Policy')
        if not referrer_policy:
            findings.append("Missing 'Referrer-Policy' header: May leak sensitive referrer information.")
        elif referrer_policy.lower() not in ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']:
            findings.append(f"Potentially insecure 'Referrer-Policy' ({referrer_policy}): Consider stricter options.")
        else:
            findings.append(f"Secure 'Referrer-Policy': {referrer_policy}")

        # X-XSS-Protection (mostly deprecated by CSP, but good to check for old systems)
        x_xss_protection = headers.get('X-XSS-Protection')
        if x_xss_protection and x_xss_protection != '0':
            findings.append(f"Legacy 'X-XSS-Protection' header found ({x_xss_protection}): Consider relying on CSP instead.")

        print("\n--- Summary of Findings ---")
        for finding in findings:
            print(f"- {finding}")

    except requests.exceptions.Timeout:
        print(f"Error: Request timed out for {url}. The server might be slow or unreachable.")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    print("--- Basic HTTP Header Security Analyzer ---")
    target_url = input("Enter the full URL (e.g., https://www.google.com): ")

    if not target_url.strip():
        print("No URL entered. Exiting.")
        sys.exit(1)

    # Ensure URL starts with http:// or https://
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        print("Warning: URL should start with 'http://' or 'https://'. Attempting with https://")
        target_url = "https://" + target_url

    analyze_security_headers(target_url)