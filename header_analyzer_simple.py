# header_analyzer_simple.py
import requests
import sys

def analyze_security_headers_simple(url):
    print(f"--- Website Security Check for: {url} ---\n")
    print("This tool checks your website's 'security bodyguard' (HTTP headers) to see how well it's protecting visitors.\n")

    try:
        response = requests.get(url, timeout=10) # Set a timeout
        headers = response.headers
        
        # We'll skip printing all raw headers here to keep it simple, 
        # but could add it back as an "advanced details" option.
        # print("--- All Headers Received (for advanced users) ---")
        # for key, value in headers.items():
        #     print(f"{key}: {value}")
        
        print("--- Security Report ---\n")
        overall_status = "Good" # Assume good until a problem is found
        
        # --- 1. X-Frame-Options: Prevents Clickjacking ---
        print("1. Clickjacking Protection (X-Frame-Options):")
        x_frame_options = headers.get('X-Frame-Options')
        if not x_frame_options:
            print("   - STATUS: Needs Attention 🟠")
            print("   - WHAT IT DOES: This header is like a sign telling other websites 'Don't put me in your frame!'")
            print("   - THE RISK: Without it, a tricky attacker could embed your website into theirs. They might overlay invisible buttons to trick your visitors into clicking something on *your* site while thinking they're on the attacker's site (this is called 'Clickjacking'). Imagine someone putting a transparent sticker over your car's 'open door' button that actually activates the 'eject' seat.")
            overall_status = "Needs Attention"
        elif x_frame_options.upper() not in ['DENY', 'SAMEORIGIN']:
            print(f"   - STATUS: Needs Attention 🟠 (Value: {x_frame_options})")
            print("   - WHAT IT DOES: This header is present, but its setting is not as strong as it could be.")
            print("   - THE RISK: It might allow your site to be embedded in frames more openly than is safe, still leaving room for Clickjacking attacks. Best settings are 'DENY' (no one can embed) or 'SAMEORIGIN' (only your own website can embed itself).")
            overall_status = "Needs Attention"
        else:
            print(f"   - STATUS: Good ✅ (Value: {x_frame_options})")
            print("   - WHAT IT DOES: This header helps prevent other websites from embedding your pages in their own, protecting your visitors from 'Clickjacking' attacks.")
            print("   - THE BENEFIT: Visitors can trust that clicks on your site are happening on your site.")
        print("-" * 30)

        # --- 2. Strict-Transport-Security (HSTS): Enforces HTTPS ---
        print("2. Secure Connection Enforcement (Strict-Transport-Security - HSTS):")
        hsts = headers.get('Strict-Transport-Security')
        if not hsts:
            print("   - STATUS: Critical 🔴 (Missing)")
            print("   - WHAT IT DOES: This header is like a strict rule that tells browsers, 'Only talk to me over a secure, encrypted connection (HTTPS)! No exceptions!'")
            print("   - THE RISK: Without it, if someone tries to visit your site using an old, insecure `http://` link, their browser might briefly connect insecurely, even if your site supports `https://`. Attackers could use this brief window to intercept information or redirect them to a fake site (SSL stripping).")
            overall_status = "Critical"
        else:
            print(f"   - STATUS: Good ✅ (Value: {hsts})")
            print("   - WHAT IT DOES: This header ensures that visitors' browsers *always* connect to your website using a secure, encrypted connection (HTTPS), even if they type `http://`.")
            print("   - THE BENEFIT: Protects against interception and ensures visitor data is always encrypted.")
        print("-" * 30)

        # --- 3. Content-Security-Policy (CSP): Prevents XSS & Injection ---
        print("3. Content Control (Content-Security-Policy - CSP):")
        csp = headers.get('Content-Security-Policy')
        if not csp:
            print("   - STATUS: Critical 🔴 (Missing)")
            print("   - WHAT IT DOES: This header is a detailed instruction manual for your browser, telling it exactly *which* types of content (like scripts, images, videos) are allowed to load on your page, and from *where* they are allowed to load.")
            print("   - THE RISK: Without it, an attacker could potentially inject malicious code (like JavaScript) into your website that steals visitor information or defaces your site (this is called Cross-Site Scripting or XSS). It's like having no bouncer at a club, letting anyone in.")
            overall_status = "Critical"
        else:
            print(f"   - STATUS: Good ✅ (Present - but complex, often needs expert review)")
            print("   - WHAT IT DOES: This header acts as a powerful security shield, limiting where your website can load content from. This vastly reduces the risk of malicious code injection (like XSS attacks).")
            print("   - THE BENEFIT: Helps protect visitors from malware and data theft through injected scripts. While present, a very complex CSP might still have tiny gaps, so experts often review them manually.")
        print("-" * 30)

        # --- 4. X-Content-Type-Options: Prevents MIME-Sniffing ---
        print("4. Content Type Enforcement (X-Content-Type-Options):")
        x_content_type_options = headers.get('X-Content-Type-Options')
        if not x_content_type_options or x_content_type_options.lower() != 'nosniff':
            print("   - STATUS: Needs Attention 🟠")
            print("   - WHAT IT DOES: This header is a clear label saying, 'This is a picture, not a script!'")
            print("   - THE RISK: Without 'nosniff', a browser might try to 'guess' what a file is. An attacker could upload a harmless picture file, but trick the browser into thinking it's a dangerous script and run it, causing harm.")
            overall_status = "Needs Attention"
        else:
            print(f"   - STATUS: Good ✅ (Value: {x_content_type_options})")
            print("   - WHAT IT DOES: This header prevents browsers from guessing the type of content your website sends. It ensures that a file labeled as an image is treated *only* as an image, not potentially a harmful script.")
            print("   - THE BENEFIT: Reduces the risk of certain types of malware injection.")
        print("-" * 30)

        # --- 5. Referrer-Policy: Controls Information Leakage ---
        print("5. Referrer Information Control (Referrer-Policy):")
        referrer_policy = headers.get('Referrer-Policy')
        if not referrer_policy:
            print("   - STATUS: Needs Attention 🟠 (Missing)")
            print("   - WHAT IT DOES: This header controls how much information your browser sends to other websites about *where* you came from when you click a link on your site.")
            print("   - THE RISK: Without it, your site might accidentally send the full address of a visitor's current page to external sites. This could unintentionally reveal sensitive information in the URL (like order numbers, session IDs) if your URLs contain them.")
            overall_status = "Needs Attention"
        elif referrer_policy.lower() not in ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']:
            print(f"   - STATUS: Needs Attention 🟠 (Value: {referrer_policy})")
            print("   - WHAT IT DOES: This header is present, but its setting might be too generous.")
            print("   - THE RISK: It could still reveal more of your visitors' browsing history to other sites than necessary, potentially leaking sensitive data if your URLs contain it.")
            overall_status = "Needs Attention"
        else:
            print(f"   - STATUS: Good ✅ (Value: {referrer_policy})")
            print("   - WHAT IT DOES: This header helps protect visitor privacy by controlling how much of their previous page address (referrer information) is sent to other websites when they click a link.")
            print("   - THE BENEFIT: Prevents accidental leakage of potentially sensitive information through URLs.")
        print("-" * 30)
        
        # --- Overall Summary ---
        print("\n--- Overall Assessment ---")
        if overall_status == "Critical":
            print(f"Your website's security headers have a {overall_status} 🔴 rating. Some very important protections are missing or weak.")
            print("   - RECOMMENDATION: Focus immediately on adding or correcting the headers marked 'Critical 🔴'.")
        elif overall_status == "Needs Attention":
            print(f"Your website's security headers have a {overall_status} 🟠 rating. There are areas for improvement.")
            print("   - RECOMMENDATION: Review the headers marked 'Needs Attention 🟠' to strengthen your website's defenses.")
        else:
            print(f"Your website's security headers have a {overall_status} ✅ rating. Good job on these foundational protections!")
            print("   - RECOMMENDATION: Continue to review your security posture regularly as threats evolve.")


    except requests.exceptions.Timeout:
        print(f"ERROR: The website took too long to respond ({url}). It might be slow or temporarily down.")
        print("   - This isn't a header security issue, but indicates a connectivity problem.")
    except requests.exceptions.ConnectionError:
        print(f"ERROR: Could not connect to the website ({url}). Please check the URL and your internet connection.")
        print("   - This isn't a header security issue, but indicates a connection problem.")
    except requests.exceptions.RequestException as e:
        print(f"ERROR: An issue occurred while fetching the website ({url}): {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    print("--- Simple Website Security Header Analyzer ---")
    print("This tool checks key 'security bodyguard' settings for any website.")
    print("Just enter the website address (URL) and I'll tell you how well protected it is!")
    
    target_url = input("\nEnter the full website address (e.g., https://www.google.com): ")

    if not target_url.strip():
        print("No website address entered. Exiting.")
        sys.exit(1)

    # Ensure URL starts with http:// or https://
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        print("Warning: Website address should start with 'http://' or 'https://'. Attempting with https://")
        target_url = "https://" + target_url

    analyze_security_headers_simple(target_url)