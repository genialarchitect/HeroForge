// Builtin Nuclei Templates
// A collection of essential security scanning templates bundled with HeroForge

use anyhow::Result;
use log::info;
use std::path::Path;
use tokio::fs;

/// Template definition with ID and YAML content
pub struct BuiltinTemplate {
    pub id: &'static str,
    pub category: &'static str,
    pub content: &'static str,
}

/// Get all builtin templates
pub fn get_builtin_templates() -> Vec<BuiltinTemplate> {
    vec![
        // ============== HTTP Security Headers ==============
        BuiltinTemplate {
            id: "missing-x-frame-options",
            category: "http/headers",
            content: r#"id: missing-x-frame-options

info:
  name: Missing X-Frame-Options Header
  author: HeroForge
  severity: medium
  description: |
    The X-Frame-Options header is not present, which could allow clickjacking attacks.
    This header tells the browser whether to allow the page to be rendered in a frame.
  tags: headers,security,clickjacking,misconfig
  reference:
    - https://owasp.org/www-project-secure-headers/
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
  classification:
    cwe-id: CWE-1021

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "X-Frame-Options"
        part: header
        negative: true
"#,
        },
        BuiltinTemplate {
            id: "missing-content-security-policy",
            category: "http/headers",
            content: r#"id: missing-content-security-policy

info:
  name: Missing Content-Security-Policy Header
  author: HeroForge
  severity: medium
  description: |
    The Content-Security-Policy header is not present, which could allow XSS attacks.
    CSP helps prevent cross-site scripting and other code injection attacks.
  tags: headers,security,xss,csp,misconfig
  reference:
    - https://owasp.org/www-project-secure-headers/
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
  classification:
    cwe-id: CWE-693

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Content-Security-Policy"
        part: header
        negative: true
"#,
        },
        BuiltinTemplate {
            id: "missing-strict-transport-security",
            category: "http/headers",
            content: r#"id: missing-strict-transport-security

info:
  name: Missing Strict-Transport-Security Header
  author: HeroForge
  severity: medium
  description: |
    The Strict-Transport-Security (HSTS) header is not present.
    HSTS ensures browsers only connect via HTTPS, preventing protocol downgrade attacks.
  tags: headers,security,hsts,ssl,misconfig
  reference:
    - https://owasp.org/www-project-secure-headers/
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
  classification:
    cwe-id: CWE-319

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Strict-Transport-Security"
        part: header
        negative: true
"#,
        },
        BuiltinTemplate {
            id: "missing-x-content-type-options",
            category: "http/headers",
            content: r#"id: missing-x-content-type-options

info:
  name: Missing X-Content-Type-Options Header
  author: HeroForge
  severity: low
  description: |
    The X-Content-Type-Options header is not present.
    This header prevents MIME type sniffing which can lead to security vulnerabilities.
  tags: headers,security,mime,misconfig
  reference:
    - https://owasp.org/www-project-secure-headers/
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
  classification:
    cwe-id: CWE-693

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "X-Content-Type-Options"
        part: header
        negative: true
"#,
        },
        BuiltinTemplate {
            id: "missing-referrer-policy",
            category: "http/headers",
            content: r#"id: missing-referrer-policy

info:
  name: Missing Referrer-Policy Header
  author: HeroForge
  severity: info
  description: |
    The Referrer-Policy header is not present.
    This header controls how much referrer information should be included with requests.
  tags: headers,security,privacy,misconfig
  reference:
    - https://owasp.org/www-project-secure-headers/
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Referrer-Policy"
        part: header
        negative: true
"#,
        },
        BuiltinTemplate {
            id: "missing-permissions-policy",
            category: "http/headers",
            content: r#"id: missing-permissions-policy

info:
  name: Missing Permissions-Policy Header
  author: HeroForge
  severity: info
  description: |
    The Permissions-Policy header is not present.
    This header controls which browser features can be used in the current document.
  tags: headers,security,permissions,misconfig
  reference:
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
  classification:
    cwe-id: CWE-693

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Permissions-Policy"
        part: header
        negative: true
"#,
        },
        // ============== Information Disclosure ==============
        BuiltinTemplate {
            id: "server-header-disclosure",
            category: "http/info-disclosure",
            content: r#"id: server-header-disclosure

info:
  name: Server Header Information Disclosure
  author: HeroForge
  severity: info
  description: |
    The server header reveals information about the web server software and version.
    This information can help attackers identify known vulnerabilities.
  tags: info-disclosure,server,headers
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        regex:
          - "Server:\\s*(Apache|nginx|IIS|Tomcat|Express|Kestrel|gunicorn|Jetty|LiteSpeed)[/\\s]?[\\d\\.]*"
    extractors:
      - type: regex
        part: header
        group: 0
        regex:
          - "Server:\\s*([^\\r\\n]+)"
"#,
        },
        BuiltinTemplate {
            id: "x-powered-by-disclosure",
            category: "http/info-disclosure",
            content: r#"id: x-powered-by-disclosure

info:
  name: X-Powered-By Header Information Disclosure
  author: HeroForge
  severity: info
  description: |
    The X-Powered-By header reveals information about the server-side technology.
    This information can help attackers identify known vulnerabilities.
  tags: info-disclosure,headers,technology
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        regex:
          - "X-Powered-By:\\s*.+"
    extractors:
      - type: regex
        part: header
        group: 0
        regex:
          - "X-Powered-By:\\s*([^\\r\\n]+)"
"#,
        },
        BuiltinTemplate {
            id: "asp-net-version-disclosure",
            category: "http/info-disclosure",
            content: r#"id: asp-net-version-disclosure

info:
  name: ASP.NET Version Disclosure
  author: HeroForge
  severity: info
  description: |
    The X-AspNet-Version header reveals the ASP.NET version.
    This information can help attackers identify known vulnerabilities.
  tags: info-disclosure,asp.net,headers,technology
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        regex:
          - "X-AspNet-Version:\\s*[\\d\\.]+"
    extractors:
      - type: regex
        part: header
        group: 0
        regex:
          - "X-AspNet-Version:\\s*([\\d\\.]+)"
"#,
        },
        BuiltinTemplate {
            id: "php-version-disclosure",
            category: "http/info-disclosure",
            content: r#"id: php-version-disclosure

info:
  name: PHP Version Disclosure
  author: HeroForge
  severity: info
  description: |
    The X-Powered-By header reveals the PHP version.
    This information can help attackers identify known vulnerabilities.
  tags: info-disclosure,php,headers,technology
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        regex:
          - "X-Powered-By:\\s*PHP/[\\d\\.]+"
    extractors:
      - type: regex
        part: header
        group: 1
        regex:
          - "X-Powered-By:\\s*PHP/([\\d\\.]+)"
"#,
        },
        BuiltinTemplate {
            id: "directory-listing",
            category: "http/info-disclosure",
            content: r#"id: directory-listing

info:
  name: Directory Listing Enabled
  author: HeroForge
  severity: medium
  description: |
    Directory listing is enabled on the web server, exposing file and folder names.
    This can reveal sensitive information and help attackers map the application structure.
  tags: info-disclosure,misconfig,directory-listing
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
  classification:
    cwe-id: CWE-548

http:
  - method: GET
    path:
      - "{{BaseURL}}"
      - "{{BaseURL}}/images/"
      - "{{BaseURL}}/css/"
      - "{{BaseURL}}/js/"
      - "{{BaseURL}}/assets/"
      - "{{BaseURL}}/uploads/"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Index of /"
          - "Directory listing for"
          - "<title>Index of"
          - "Parent Directory</a>"
        condition: or
"#,
        },
        BuiltinTemplate {
            id: "git-directory-exposure",
            category: "http/info-disclosure",
            content: r#"id: git-directory-exposure

info:
  name: Git Directory Exposure
  author: HeroForge
  severity: high
  description: |
    The .git directory is exposed, potentially leaking source code and sensitive information.
    An attacker could download the entire repository history.
  tags: info-disclosure,git,exposure,misconfig
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/
  classification:
    cwe-id: CWE-538

http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
      - "{{BaseURL}}/.git/HEAD"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "[core]"
          - "ref: refs/"
        condition: or
"#,
        },
        BuiltinTemplate {
            id: "env-file-exposure",
            category: "http/info-disclosure",
            content: r#"id: env-file-exposure

info:
  name: Environment File Exposure
  author: HeroForge
  severity: critical
  description: |
    The .env file is exposed, potentially leaking sensitive configuration data,
    API keys, database credentials, and other secrets.
  tags: info-disclosure,env,exposure,misconfig,credentials
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/
  classification:
    cwe-id: CWE-538

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.env.local"
      - "{{BaseURL}}/.env.production"
      - "{{BaseURL}}/.env.development"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: regex
        regex:
          - "(?i)(DB_|DATABASE_|MYSQL_|POSTGRES_|API_KEY|SECRET|PASSWORD|AWS_|AZURE_).*="
"#,
        },
        BuiltinTemplate {
            id: "backup-files-exposure",
            category: "http/info-disclosure",
            content: r#"id: backup-files-exposure

info:
  name: Backup Files Exposure
  author: HeroForge
  severity: medium
  description: |
    Backup files are accessible, potentially exposing source code or sensitive data.
  tags: info-disclosure,backup,exposure,misconfig
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/
  classification:
    cwe-id: CWE-530

http:
  - method: GET
    path:
      - "{{BaseURL}}/index.php.bak"
      - "{{BaseURL}}/index.php.old"
      - "{{BaseURL}}/index.php~"
      - "{{BaseURL}}/backup.zip"
      - "{{BaseURL}}/backup.sql"
      - "{{BaseURL}}/database.sql"
      - "{{BaseURL}}/db.sql"
      - "{{BaseURL}}/dump.sql"
      - "{{BaseURL}}/config.php.bak"
      - "{{BaseURL}}/wp-config.php.bak"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: dsl
        dsl:
          - "len(body) > 100"
"#,
        },
        BuiltinTemplate {
            id: "robots-txt",
            category: "http/info-disclosure",
            content: r#"id: robots-txt

info:
  name: Robots.txt File Detection
  author: HeroForge
  severity: info
  description: |
    The robots.txt file is present and may reveal hidden directories or sensitive paths.
  tags: info-disclosure,robots,recon
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}/robots.txt"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Disallow:"
          - "Allow:"
          - "User-agent:"
        condition: or
    extractors:
      - type: regex
        part: body
        regex:
          - "Disallow:\\s*([^\\r\\n]+)"
"#,
        },
        // ============== Common Misconfigurations ==============
        BuiltinTemplate {
            id: "cors-misconfiguration",
            category: "http/misconfiguration",
            content: r#"id: cors-misconfiguration

info:
  name: CORS Misconfiguration
  author: HeroForge
  severity: high
  description: |
    The server reflects the Origin header in Access-Control-Allow-Origin,
    potentially allowing any website to make authenticated requests.
  tags: cors,misconfig,security
  reference:
    - https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny
    - https://portswigger.net/web-security/cors
  classification:
    cwe-id: CWE-942

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      Origin: "https://evil.com"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Origin: https://evil.com"
          - "Access-Control-Allow-Origin: *"
        condition: or
"#,
        },
        BuiltinTemplate {
            id: "http-trace-method",
            category: "http/misconfiguration",
            content: r#"id: http-trace-method

info:
  name: HTTP TRACE Method Enabled
  author: HeroForge
  severity: medium
  description: |
    The HTTP TRACE method is enabled on the server.
    This can be used for cross-site tracing (XST) attacks.
  tags: trace,xst,misconfig,security
  reference:
    - https://owasp.org/www-community/attacks/Cross_Site_Tracing
  classification:
    cwe-id: CWE-693

http:
  - method: TRACE
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "TRACE /"
"#,
        },
        BuiltinTemplate {
            id: "options-method",
            category: "http/misconfiguration",
            content: r#"id: options-method

info:
  name: HTTP OPTIONS Method Detection
  author: HeroForge
  severity: info
  description: |
    The HTTP OPTIONS method reveals allowed HTTP methods on the server.
  tags: options,methods,recon
  reference:
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS
  classification:
    cwe-id: CWE-200

http:
  - method: OPTIONS
    path:
      - "{{BaseURL}}"
    matchers:
      - type: status
        status:
          - 200
          - 204
    extractors:
      - type: regex
        part: header
        regex:
          - "Allow:\\s*([^\\r\\n]+)"
"#,
        },
        BuiltinTemplate {
            id: "insecure-cookie-flags",
            category: "http/misconfiguration",
            content: r#"id: insecure-cookie-flags

info:
  name: Insecure Cookie Configuration
  author: HeroForge
  severity: medium
  description: |
    Cookies are set without Secure or HttpOnly flags,
    making them vulnerable to theft via XSS or interception.
  tags: cookie,security,misconfig
  reference:
    - https://owasp.org/www-community/controls/SecureCookieAttribute
  classification:
    cwe-id: CWE-614

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "Set-Cookie:"
      - type: word
        part: header
        words:
          - "Secure"
          - "HttpOnly"
        negative: true
        condition: and
"#,
        },
        // ============== Default Credentials & Admin Panels ==============
        BuiltinTemplate {
            id: "default-apache-page",
            category: "http/default-pages",
            content: r#"id: default-apache-page

info:
  name: Apache Default Page
  author: HeroForge
  severity: info
  description: |
    The default Apache HTTP Server test page is exposed.
  tags: apache,default,recon
  reference:
    - https://httpd.apache.org/
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Apache2 Ubuntu Default Page"
          - "Apache2 Debian Default Page"
          - "It works!"
          - "Test Page for Apache"
        condition: or
"#,
        },
        BuiltinTemplate {
            id: "default-nginx-page",
            category: "http/default-pages",
            content: r#"id: default-nginx-page

info:
  name: Nginx Default Page
  author: HeroForge
  severity: info
  description: |
    The default Nginx welcome page is exposed.
  tags: nginx,default,recon
  reference:
    - https://nginx.org/
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Welcome to nginx!"
          - "Thank you for using nginx"
        condition: or
"#,
        },
        BuiltinTemplate {
            id: "phpmyadmin-panel",
            category: "http/exposed-panels",
            content: r#"id: phpmyadmin-panel

info:
  name: phpMyAdmin Panel Detection
  author: HeroForge
  severity: medium
  description: |
    phpMyAdmin administration panel is exposed.
  tags: phpmyadmin,admin,panel,database
  reference:
    - https://www.phpmyadmin.net/
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}/phpmyadmin/"
      - "{{BaseURL}}/phpMyAdmin/"
      - "{{BaseURL}}/pma/"
      - "{{BaseURL}}/mysql/"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "phpMyAdmin"
          - "pma_password"
        condition: or
"#,
        },
        BuiltinTemplate {
            id: "wordpress-login",
            category: "http/exposed-panels",
            content: r#"id: wordpress-login

info:
  name: WordPress Login Panel
  author: HeroForge
  severity: info
  description: |
    WordPress login panel is exposed.
  tags: wordpress,cms,panel,login
  reference:
    - https://wordpress.org/
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-login.php"
      - "{{BaseURL}}/wp-admin/"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 302
      - type: word
        words:
          - "wp-login"
          - "WordPress"
        condition: or
"#,
        },
        BuiltinTemplate {
            id: "jenkins-panel",
            category: "http/exposed-panels",
            content: r#"id: jenkins-panel

info:
  name: Jenkins Panel Detection
  author: HeroForge
  severity: medium
  description: |
    Jenkins CI/CD panel is exposed.
  tags: jenkins,ci,cd,panel,devops
  reference:
    - https://www.jenkins.io/
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}"
      - "{{BaseURL}}/login"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Jenkins"
          - "Dashboard [Jenkins]"
        condition: or
    extractors:
      - type: regex
        part: body
        regex:
          - "Jenkins ver\\. ([\\d\\.]+)"
"#,
        },
        BuiltinTemplate {
            id: "grafana-panel",
            category: "http/exposed-panels",
            content: r#"id: grafana-panel

info:
  name: Grafana Panel Detection
  author: HeroForge
  severity: info
  description: |
    Grafana monitoring panel is exposed.
  tags: grafana,monitoring,panel
  reference:
    - https://grafana.com/
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}/login"
      - "{{BaseURL}}/api/health"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Grafana"
          - "grafana"
        condition: or
"#,
        },
        BuiltinTemplate {
            id: "kibana-panel",
            category: "http/exposed-panels",
            content: r#"id: kibana-panel

info:
  name: Kibana Panel Detection
  author: HeroForge
  severity: medium
  description: |
    Kibana panel is exposed, potentially allowing access to Elasticsearch data.
  tags: kibana,elasticsearch,panel,monitoring
  reference:
    - https://www.elastic.co/kibana/
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}/app/kibana"
      - "{{BaseURL}}/api/status"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "kibana"
          - "Kibana"
        condition: or
"#,
        },
        // ============== Technology Detection ==============
        BuiltinTemplate {
            id: "waf-detection",
            category: "http/technology",
            content: r#"id: waf-detection

info:
  name: WAF Detection
  author: HeroForge
  severity: info
  description: |
    Detects the presence of Web Application Firewalls.
  tags: waf,firewall,detection,recon
  reference:
    - https://owasp.org/www-community/Web_Application_Firewall
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}/?test=<script>alert(1)</script>"
    matchers-condition: or
    matchers:
      - type: word
        part: header
        words:
          - "cloudflare"
          - "cf-ray"
          - "cf-cache-status"
        condition: or
      - type: word
        part: header
        words:
          - "x-sucuri"
          - "x-sucuri-id"
        condition: or
      - type: word
        part: header
        words:
          - "x-aws-waf"
          - "awselb"
        condition: or
      - type: word
        part: body
        words:
          - "Access Denied"
          - "Request blocked"
          - "Forbidden"
        condition: or
"#,
        },
        BuiltinTemplate {
            id: "cms-detection",
            category: "http/technology",
            content: r#"id: cms-detection

info:
  name: CMS Detection
  author: HeroForge
  severity: info
  description: |
    Detects common Content Management Systems.
  tags: cms,technology,detection,recon
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "wp-content"
          - "wp-includes"
        name: wordpress
      - type: word
        words:
          - "Joomla!"
          - "/media/jui/"
        name: joomla
      - type: word
        words:
          - "Drupal"
          - "sites/all/"
          - "sites/default/"
        name: drupal
      - type: word
        words:
          - "content=\"Magento"
        name: magento
"#,
        },
        // ============== Common Vulnerabilities ==============
        BuiltinTemplate {
            id: "open-redirect",
            category: "http/vulnerabilities",
            content: r#"id: open-redirect

info:
  name: Open Redirect Detection
  author: HeroForge
  severity: medium
  description: |
    The application may be vulnerable to open redirect attacks.
  tags: redirect,vulnerability
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect
  classification:
    cwe-id: CWE-601

http:
  - method: GET
    path:
      - "{{BaseURL}}?url=https://evil.com"
      - "{{BaseURL}}?redirect=https://evil.com"
      - "{{BaseURL}}?next=https://evil.com"
      - "{{BaseURL}}?return=https://evil.com"
      - "{{BaseURL}}?returnUrl=https://evil.com"
      - "{{BaseURL}}?goto=https://evil.com"
    stop-at-first-match: true
    matchers:
      - type: regex
        part: header
        regex:
          - "(?i)Location:\\s*https?://evil\\.com"
"#,
        },
        BuiltinTemplate {
            id: "xss-reflected",
            category: "http/vulnerabilities",
            content: r#"id: xss-reflected

info:
  name: Reflected XSS Detection
  author: HeroForge
  severity: high
  description: |
    The application may be vulnerable to reflected cross-site scripting (XSS).
  tags: xss,vulnerability
  reference:
    - https://owasp.org/www-community/attacks/xss/
  classification:
    cwe-id: CWE-79

http:
  - method: GET
    path:
      - "{{BaseURL}}?search=<script>alert(1)</script>"
      - "{{BaseURL}}?q=<img src=x onerror=alert(1)>"
      - "{{BaseURL}}?id=<svg onload=alert(1)>"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "<script>alert(1)</script>"
          - "<img src=x onerror=alert(1)>"
          - "<svg onload=alert(1)>"
        condition: or
"#,
        },
        BuiltinTemplate {
            id: "sql-injection-error",
            category: "http/vulnerabilities",
            content: r#"id: sql-injection-error

info:
  name: SQL Injection Error-Based Detection
  author: HeroForge
  severity: critical
  description: |
    The application may be vulnerable to SQL injection based on error messages.
  tags: sqli,vulnerability,database
  reference:
    - https://owasp.org/www-community/attacks/SQL_Injection
  classification:
    cwe-id: CWE-89

http:
  - method: GET
    path:
      - "{{BaseURL}}?id=1'"
      - "{{BaseURL}}?id=1\""
      - "{{BaseURL}}?id=1;--"
    stop-at-first-match: true
    matchers:
      - type: word
        words:
          - "SQL syntax"
          - "mysql_fetch"
          - "ORA-01756"
          - "SQLite3::query"
          - "pg_query"
          - "Warning: mysql"
          - "Unclosed quotation mark"
          - "SQLSTATE"
        condition: or
"#,
        },
        BuiltinTemplate {
            id: "lfi-basic",
            category: "http/vulnerabilities",
            content: r#"id: lfi-basic

info:
  name: Local File Inclusion Detection
  author: HeroForge
  severity: high
  description: |
    The application may be vulnerable to Local File Inclusion (LFI).
  tags: lfi,vulnerability,file-inclusion
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
  classification:
    cwe-id: CWE-98

http:
  - method: GET
    path:
      - "{{BaseURL}}?file=../../../etc/passwd"
      - "{{BaseURL}}?page=../../../etc/passwd"
      - "{{BaseURL}}?path=../../../etc/passwd"
      - "{{BaseURL}}?include=../../../etc/passwd"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: regex
        regex:
          - "root:.*:0:0:"
"#,
        },
        BuiltinTemplate {
            id: "ssrf-basic",
            category: "http/vulnerabilities",
            content: r#"id: ssrf-basic

info:
  name: Server-Side Request Forgery Detection
  author: HeroForge
  severity: high
  description: |
    The application may be vulnerable to Server-Side Request Forgery (SSRF).
  tags: ssrf,vulnerability
  reference:
    - https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
  classification:
    cwe-id: CWE-918

http:
  - method: GET
    path:
      - "{{BaseURL}}?url=http://localhost"
      - "{{BaseURL}}?url=http://127.0.0.1"
      - "{{BaseURL}}?url=http://[::1]"
      - "{{BaseURL}}?url=http://169.254.169.254"
    stop-at-first-match: true
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "localhost"
          - "127.0.0.1"
          - "ami-id"
          - "instance-id"
        condition: or
"#,
        },
        // ============== SSL/TLS Issues ==============
        BuiltinTemplate {
            id: "ssl-certificate-info",
            category: "ssl",
            content: r#"id: ssl-certificate-info

info:
  name: SSL Certificate Information
  author: HeroForge
  severity: info
  description: |
    Extracts SSL/TLS certificate information from the target.
  tags: ssl,tls,certificate,recon

ssl:
  - address: "{{Host}}:{{Port}}"
    extractors:
      - type: json
        json:
          - ".subject_cn"
          - ".issuer_cn"
          - ".not_after"
          - ".serial"
"#,
        },
        BuiltinTemplate {
            id: "expired-ssl-certificate",
            category: "ssl",
            content: r#"id: expired-ssl-certificate

info:
  name: Expired SSL Certificate
  author: HeroForge
  severity: high
  description: |
    The SSL/TLS certificate has expired.
  tags: ssl,tls,certificate,expired
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/
  classification:
    cwe-id: CWE-295

ssl:
  - address: "{{Host}}:{{Port}}"
    matchers:
      - type: dsl
        dsl:
          - "not_after < now"
"#,
        },
        BuiltinTemplate {
            id: "self-signed-certificate",
            category: "ssl",
            content: r#"id: self-signed-certificate

info:
  name: Self-Signed SSL Certificate
  author: HeroForge
  severity: medium
  description: |
    The SSL/TLS certificate is self-signed.
  tags: ssl,tls,certificate,self-signed
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/
  classification:
    cwe-id: CWE-295

ssl:
  - address: "{{Host}}:{{Port}}"
    matchers:
      - type: dsl
        dsl:
          - "subject_cn == issuer_cn"
"#,
        },
        // ============== Network Services ==============
        BuiltinTemplate {
            id: "ssh-banner",
            category: "network",
            content: r#"id: ssh-banner

info:
  name: SSH Banner Detection
  author: HeroForge
  severity: info
  description: |
    Detects SSH service and extracts version information.
  tags: ssh,network,banner,recon

tcp:
  - inputs:
      - data: "\n"
    host:
      - "{{Hostname}}"
    port: 22
    read-size: 2048
    matchers:
      - type: word
        words:
          - "SSH-"
    extractors:
      - type: regex
        regex:
          - "SSH-[\\d\\.]+-([^\\r\\n]+)"
"#,
        },
        BuiltinTemplate {
            id: "ftp-banner",
            category: "network",
            content: r#"id: ftp-banner

info:
  name: FTP Banner Detection
  author: HeroForge
  severity: info
  description: |
    Detects FTP service and extracts banner information.
  tags: ftp,network,banner,recon

tcp:
  - inputs:
      - data: ""
    host:
      - "{{Hostname}}"
    port: 21
    read-size: 2048
    matchers:
      - type: regex
        regex:
          - "^220[\\s-]"
    extractors:
      - type: regex
        regex:
          - "220[\\s-]([^\\r\\n]+)"
"#,
        },
        BuiltinTemplate {
            id: "smtp-banner",
            category: "network",
            content: r#"id: smtp-banner

info:
  name: SMTP Banner Detection
  author: HeroForge
  severity: info
  description: |
    Detects SMTP service and extracts banner information.
  tags: smtp,mail,network,banner,recon

tcp:
  - inputs:
      - data: ""
    host:
      - "{{Hostname}}"
    port: 25
    read-size: 2048
    matchers:
      - type: regex
        regex:
          - "^220[\\s-]"
    extractors:
      - type: regex
        regex:
          - "220[\\s-]([^\\r\\n]+)"
"#,
        },
        BuiltinTemplate {
            id: "mysql-detect",
            category: "network",
            content: r#"id: mysql-detect

info:
  name: MySQL Service Detection
  author: HeroForge
  severity: info
  description: |
    Detects MySQL service and extracts version information.
  tags: mysql,database,network,recon

tcp:
  - inputs:
      - data: ""
    host:
      - "{{Hostname}}"
    port: 3306
    read-size: 2048
    matchers:
      - type: word
        words:
          - "mysql"
          - "MariaDB"
        condition: or
    extractors:
      - type: regex
        regex:
          - "([\\d\\.]+)-([^\\x00]+)"
"#,
        },
        BuiltinTemplate {
            id: "redis-detect",
            category: "network",
            content: r#"id: redis-detect

info:
  name: Redis Service Detection
  author: HeroForge
  severity: medium
  description: |
    Detects Redis service. If accessible without authentication, this is a critical finding.
  tags: redis,database,network,recon
  classification:
    cwe-id: CWE-306

tcp:
  - inputs:
      - data: "INFO\r\n"
    host:
      - "{{Hostname}}"
    port: 6379
    read-size: 4096
    matchers:
      - type: word
        words:
          - "redis_version"
    extractors:
      - type: regex
        regex:
          - "redis_version:([\\d\\.]+)"
"#,
        },
        BuiltinTemplate {
            id: "mongodb-detect",
            category: "network",
            content: r#"id: mongodb-detect

info:
  name: MongoDB Service Detection
  author: HeroForge
  severity: medium
  description: |
    Detects MongoDB service. If accessible without authentication, this is a critical finding.
  tags: mongodb,database,network,recon
  classification:
    cwe-id: CWE-306

tcp:
  - inputs:
      - data: ""
    host:
      - "{{Hostname}}"
    port: 27017
    read-size: 2048
    matchers:
      - type: word
        words:
          - "MongoDB"
          - "ismaster"
          - "maxWireVersion"
        condition: or
"#,
        },
    ]
}

/// Initialize builtin templates in the templates directory
pub async fn init_builtin_templates(templates_path: &Path) -> Result<usize> {
    let templates = get_builtin_templates();
    let mut created_count = 0;

    // Create the templates directory if it doesn't exist
    if !templates_path.exists() {
        fs::create_dir_all(templates_path).await?;
        info!("Created templates directory at {:?}", templates_path);
    }

    // Create heroforge subdirectory for our templates
    let heroforge_path = templates_path.join("heroforge");
    if !heroforge_path.exists() {
        fs::create_dir_all(&heroforge_path).await?;
    }

    for template in templates {
        // Create category subdirectory
        let category_path = heroforge_path.join(template.category);
        if !category_path.exists() {
            fs::create_dir_all(&category_path).await?;
        }

        // Write template file
        let template_file = category_path.join(format!("{}.yaml", template.id));

        // Only create if doesn't exist (don't overwrite user modifications)
        if !template_file.exists() {
            fs::write(&template_file, template.content).await?;
            created_count += 1;
        }
    }

    if created_count > 0 {
        info!(
            "Initialized {} builtin templates in {:?}",
            created_count, heroforge_path
        );
    }

    Ok(created_count)
}

/// Check if builtin templates are initialized
pub async fn are_builtin_templates_initialized(templates_path: &Path) -> bool {
    let heroforge_path = templates_path.join("heroforge");
    heroforge_path.exists()
}

/// Get count of builtin templates
pub fn get_builtin_template_count() -> usize {
    get_builtin_templates().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_templates_valid() {
        let templates = get_builtin_templates();
        assert!(!templates.is_empty());

        for template in templates {
            // Each template should have an ID
            assert!(!template.id.is_empty());
            // Each template should have content
            assert!(!template.content.is_empty());
            // Content should contain the ID
            assert!(template.content.contains(&format!("id: {}", template.id)));
        }
    }

    #[test]
    fn test_builtin_template_count() {
        let count = get_builtin_template_count();
        // Should have a reasonable number of templates
        assert!(count >= 30);
    }
}
