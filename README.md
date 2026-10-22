# php2shell-diagnostic
Non-destructive PHP2Shell Exposure and Multipart Filtering Diagnostic toolkit (CVE-2026-109618 / CVE-2026-109619) - Compatible with PHP 5.2+

PHP2Shell Benign Server Diagnostic — PHP 5.2+
================================================

FILES
- php2shell-diagnostic.php : password-protected controller
- php2shell-target.php     : benign test endpoint
- php2shell-config.php     : shared configuration

SETUP
1. Upload all three files to the same directory on a server you administer.
2. Edit php2shell-config.php:
   - Set diagnostic_secret to a NEW, random, unique string of at least 32 characters.
     Do not reuse the placeholder or a secret from someone else's installation.
   - Set diagnostic_enabled = true.
3. Protect the directory or controller with hosting access controls or IP allowlisting
   in addition to the controller's HTTP Basic authentication. Use HTTPS only.
4. Open php2shell-diagnostic.php and enter ANY username and the configured secret
   as the HTTP Basic password.
5. Read the report. It checks GET, URL-encoded FORM, MULTIPART, and UPLOAD.
6. Remove ALL THREE files immediately after testing.

COMPATIBILITY
- Intended for PHP 5.2+ with cURL, JSON and hash extensions.
- HTTPS requires a working CA trust store and SSL-capable cURL.
- Older PHP/cURL builds may lack modern TLS support even when the PHP syntax works.
- Requires public IPv4 DNS for the configured hostname; IPv6-only hosts are not supported.
- Basic authentication can be stripped by some CGI/FastCGI configurations; in that
  case use hosting-level authentication or IP restrictions instead. Never disable
  authentication to work around this.

SECURITY AND INTERPRETATION
- Only use on infrastructure you administer or have permission to test.
- This is a benign HTTP diagnostic, NOT a proof-of-concept exploit.
- HTTP 403/418 and WAF/RASP indicators do not establish PHP2Shell protection.
- Successful PHP execution does not establish vulnerability.
- Consult your hosting provider and vendor advisories for patch status.
- The hostname is explicitly configured and redirects are disabled. DNS is checked
  for public IPv4 before the request, but old cURL cannot reliably pin DNS; this
  is not a complete DNS-rebinding defense. Keep the URL under administrator control.
- Do not post complete reports publicly without reviewing potentially sensitive data.
- HTTP Basic authentication sends credentials to your HTTPS origin; do not use HTTP.
