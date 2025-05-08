# vuln-toolkit

 Simple XSS, CSRF, and CRLF Detection Toolkit

This is a lightweight and easy-to-use toolkit designed to detect three common web vulnerabilities:

    XSS (Cross-Site Scripting)

    CSRF (Cross-Site Request Forgery)

    CRLF Injection (Carriage Return Line Feed)

It combines Python and Bash scripting to automate vulnerability detection, making it useful for bug bounty hunters, penetration testers, and developers who want to quickly test their web applications for these issues.
 Features

    Scan URLs and forms for reflected and stored XSS

    Detect potential CSRF vulnerabilities through request analysis

    Identify CRLF injection points in HTTP headers

    Simple CLI interface for quick tests

    Easily integratable into automation pipelines

 Requirements

    Python 3.x

    curl, grep, and basic UNIX utilities

    (Optional) requests and beautifulsoup4 for enhanced scanning
