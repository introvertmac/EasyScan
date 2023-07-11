# EasyScan

EasyScan is a Python script that analyzes the security of a given website by inspecting its HTTP headers and DNS records. The script generates a security report with recommendations for addressing potential vulnerabilities.

## Test Cases

The script covers the following test cases:

1. Same Site Scripting
2. SPF records
3. DMARC records
4. Public Admin Page
5. Directory Listing
6. Missing security headers
7. Insecure cookie settings
8. Information disclosure
9. Cross-Origin Resource Sharing (CORS) misconfigurations
10. Content-Type sniffing
11. Cache-control

## Dependencies

EasyScan has the following dependencies:

- Python 3.6 or higher
- `requests` library
- `beautifulsoup4` library
- `dnspython` library

You can install these dependencies using `pip`:

```
pip install requests beautifulsoup4 dnspython
```

## Usage

To use the EasyScan script, follow these steps:

1. Save the code to a file named `easyscan.py`.
2. Open a terminal or command prompt and navigate to the directory containing the script.
3. Run the script using Python:

```
python3 easyscan.py
```

4. Enter the URL of the website you want to analyze when prompted.
5. Review the generated security report for any potential vulnerabilities and recommendations.

The security report will display the header or test case, the status (Missing, Accessible, Enabled, etc.), the severity (Low, Medium, or High), and the recommendation for addressing the issue.

## Example

```
Enter the URL to analyze: https://example.com

Security Report:
Header                       Status          Severity   Recommendation
--------------------------------------------------------------------------------
Meta Referrer                Missing         Low        Add a 'referrer' META tag with 'no-referrer' to prevent Same Site Scripting.
SPF Record                   Missing         Low        Add an SPF record to your domain's DNS settings to help prevent email spoofing.
DMARC Record                 Missing         Low        Add a DMARC record to your domain's DNS settings to help protect against email spoofing and phishing.
Public Admin Page            Accessible      High       Restrict access to your admin page to specific IP addresses and/or enable authentication.
Directory Listing            Enabled         Medium     Disable directory listing to prevent unauthorized access to your website's files and folders.
Content-Security-Policy      Missing         Medium     Implement a Content Security Policy (CSP) to prevent Cross-Site Scripting (XSS) and other code injection attacks.
X-Content-Type-Options       Missing         Medium     Set the 'X-Content-Type-Options' header to 'nosniff' to prevent MIME type sniffing.
X-Frame-Options              Missing         Medium     Set the 'X-Frame-Options' header to 'DENY' or 'SAMEORIGIN' to protect against clickjacking.
X-XSS-Protection             Missing         Medium     Set the 'X-XSS-Protection' header to '1; mode=block' to enable XSS protection in older browsers.
Strict-Transport-Security    Missing         Medium     Implement Strict Transport Security (HSTS) to enforce secure connections.
Set-Cookie                   Insecure        High       Set the 'Secure' and 'HttpOnly' flags for cookies to protect them from interception and access by JavaScript.
Server                       Value: nginx    Low        Remove or obfuscate the 'Server' header to avoid revealing server information.
X-Powered-By                 Value: PHP/7.4  Low        Remove or obfuscate the 'X-Powered-By' header to avoid revealing technology stack information.
Access-Control-Allow-Origin  Misconfigured   High       Restrict the 'Access-Control-Allow-Origin' header to specific trusted domains or avoid using the wildcard '*'.
Cache-Control                Insecure        Medium     Set 'Cache-Control' header to 'no-store, private' for sensitive resources to prevent caching.
```

Keep in mind that the script may not cover all possible security scenarios, and it's recommended to perform a thorough security assessment for your website.

EasyScan is also available at https://easyscan.onrender.com/

If you have any questions or need a full security audit, please reach out on Twitter [@introvertmac007](https://twitter.com/introvertmac007).
