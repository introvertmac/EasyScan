import requests
from bs4 import BeautifulSoup
import dns.resolver
import dns.exception

def analyze_headers(url):
    try:
        response = requests.get(url)
    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to fetch the URL: {e}")
        return

    security_report = []
    headers = response.headers

    def check_dns_record(record_type, domain):
        try:
            answers = dns.resolver.resolve(domain, record_type)
            return True if answers else False
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            return False

    # 1. Same Site Scripting
    soup = BeautifulSoup(response.content, "html.parser")
    if not soup.find("meta", {"name": "referrer", "content": "no-referrer"}):
        security_report.append(("Meta Referrer", "Missing", "Low", "Add a 'referrer' META tag with 'no-referrer' to prevent Same Site Scripting."))

    # 2. SPF records
    domain = url.split('/')[2]
    if not check_dns_record("TXT", domain):
        security_report.append(("SPF Record", "Missing", "Low", "Add an SPF record to your domain's DNS settings to help prevent email spoofing."))

    # 3. DMARC records
    if not check_dns_record("TXT", f"_dmarc.{domain}"):
        security_report.append(("DMARC Record", "Missing", "Low", "Add a DMARC record to your domain's DNS settings to help protect against email spoofing and phishing."))

    # 4. Public Admin Page
    admin_page = f"{url}/admin"
    try:
        admin_response = requests.get(admin_page)
        if admin_response.status_code == 200:
            security_report.append(("Public Admin Page", "Accessible", "High", "Restrict access to your admin page to specific IP addresses and/or enable authentication."))
    except requests.exceptions.RequestException:
        pass

    # 5. Directory Listing
    try:
        dir_response = requests.get(url + "/test_non_existent_directory")
        if "Index of" in dir_response.text:
            security_report.append(("Directory Listing", "Enabled", "Medium", "Disable directory listing to prevent unauthorized access to your website's files and folders."))
    except requests.exceptions.RequestException:
        pass

    # 6. Missing security headers
    security_headers = [
        ("Content-Security-Policy", "Implement a Content Security Policy (CSP) to prevent Cross-Site Scripting (XSS) and other code injection attacks."),
        ("X-Content-Type-Options", "Set the 'X-Content-Type-Options' header to 'nosniff' to prevent MIME type sniffing."),
        ("X-Frame-Options", "Set the 'X-Frame-Options' header to 'DENY' or 'SAMEORIGIN' to protect against clickjacking."),
        ("X-XSS-Protection", "Set the 'X-XSS-Protection' header to '1; mode=block' to enable XSS protection in older browsers."),
        ("Strict-Transport-Security", "Implement Strict Transport Security (HSTS) to enforce secure connections."),
    ]

    for header, fix in security_headers:
        if header not in headers:
            security_report.append((header, "Missing", "Medium", fix))

    # 7. Insecure cookie settings
    set_cookie = headers.get("Set-Cookie", "")
    if "Secure" not in set_cookie or "HttpOnly" not in set_cookie:
        security_report.append(("Set-Cookie", "Insecure", "High", "Set the 'Secure' and 'HttpOnly' flags for cookies to protect them from interception and access by JavaScript."))

    # 8. Information disclosure
    info_disclosure_headers = [
        ("Server", "Remove or obfuscate the 'Server' header to avoid revealing server information."),
        ("X-Powered-By", "Remove or obfuscate the 'X-Powered-By' header to avoid revealing technology stack information."),
        ("X-AspNet-Version", "Remove or obfuscate the 'X-AspNet-Version' header to avoid revealing ASP.NET version information."),
    ]

    for header, fix in info_disclosure_headers:
        if header in headers:
            security_report.append((header, f"Value: {headers[header]}", "Low", fix))

    # 9. Cross-Origin Resource Sharing (CORS) misconfigurations
    access_control_allow_origin = headers.get("Access-Control-Allow-Origin", "")
    if access_control_allow_origin == "*":
        security_report.append(("Access-Control-Allow-Origin", "Misconfigured", "High", "Restrict the 'Access-Control-Allow-Origin' header to specific trusted domains or avoid using the wildcard '*'."))

    # 10. Content-Type sniffing
    content_type = headers.get("Content-Type", "")
    x_content_type_options = headers.get("X-Content-Type-Options", "")
    if content_type.startswith("text/html") and x_content_type_options != "nosniff":
        security_report.append(("Content-Type/X-Content-Type-Options", "Insecure", "Medium", "Set the 'X-Content-Type-Options' header to 'nosniff' when serving HTML content to prevent MIME type sniffing."))

    # 11. Cache control
    cache_control = headers.get("Cache-Control", "")
    if "no-store" not in cache_control.lower() or "private" not in cache_control.lower():
        security_report.append(("Cache-Control", "Insecure", "Medium", "Set 'Cache-Control' header to 'no-store, private' for sensitive resources to prevent caching."))

    
    return security_report

def format_security_report(security_report):
    output = f"{'Header':<30} {'Status':<15} {'Severity':<10} {'Recommendation'}\n"
    output += "-" * 80 + "\n"

    for header, status, severity, recommendation in security_report:
        output += f"{header:<30} {status:<15} {severity:<10} {recommendation}\n"

    return output

if __name__ == "__main__":
    url = input("Enter the URL to analyze:")
    security_report = analyze_headers(url)
    if security_report:
        print("\nSecurity Report:")
        print(format_security_report(security_report))
    else:
        print("No security issues found in the request and response headers.")
