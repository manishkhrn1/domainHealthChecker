import requests

def fetch_page(domain, path=""):
    try:
        url = f"https://{domain}/{path}"
        r = requests.get(url, timeout=5)
        return r
    except Exception as e:
        print(f"[!] Error fetching {path or 'homepage'}: {e}")
        return None

def check_wordpress_and_meta(domain):
    r = fetch_page(domain)
    if not r:
        return False, None

    content = r.text.lower()
    is_wp = "wp-content" in content or "wp-includes" in content or "wordpress" in content

    # Try to extract version from meta tag
    if '<meta name="generator"' in content:
        lines = content.split('\n')
        for line in lines:
            if "wordpress" in line and "generator" in line:
                return is_wp, line.strip()
    return is_wp, None

def detect_wp_plugins(domain):
    r = fetch_page(domain)
    if not r:
        return []

    content = r.text.lower()
    plugins = []

    if "wp-content/plugins/" in content:
        lines = content.split("wp-content/plugins/")
        for line in lines[1:]:
            plugin = line.split("/")[0]
            if plugin and plugin not in plugins:
                plugins.append(plugin)

    return plugins

def check_exposed_paths(domain):
    endpoints = {
        "readme.html": False,
        "wp-login.php": False,
    }
    for path in endpoints:
        r = fetch_page(domain, path)
        if r and r.status_code == 200:
            endpoints[path] = True
    return endpoints

def get_server_headers(domain):
    r = fetch_page(domain)
    if r:
        return r.headers
    return {}

def detect_php_version(headers):
    if "X-Powered-By" in headers:
        value = headers["X-Powered-By"]
        if "php" in value.lower():
            return value.split("/")[-1]
    return None

def check_security_headers(headers):
    expected = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]
    missing = [h for h in expected if h not in headers]
    return missing

def generate_summary(domain):
    print(f"\n🔍 Checking {domain}...\n")
    is_wp, meta = check_wordpress_and_meta(domain)
    plugins = detect_wp_plugins(domain)
    exposed = check_exposed_paths(domain)
    headers = get_server_headers(domain)
    php_version = detect_php_version(headers)
    missing_headers = check_security_headers(headers)

    summary = {
        "is_wordpress": is_wp,
        "wp_version_meta": meta,
        "plugin_count": len(plugins),
        "plugins": plugins,
        "exposed_readme": exposed.get("readme.html", False),
        "exposed_login": exposed.get("wp-login.php", False),
        "php_version": php_version,
        "missing_security_headers": missing_headers,
        "security_score": 0
    }

    # Scoring
    if is_wp:
        summary["security_score"] += 20
    if meta is None:
        summary["security_score"] += 10
    if not exposed.get("readme.html"):
        summary["security_score"] += 10
    if not exposed.get("wp-login.php"):
        summary["security_score"] += 10
    if len(plugins) <= 3:
        summary["security_score"] += 10
    if not php_version or php_version >= "8.1":
        summary["security_score"] += 20
    if len(missing_headers) <= 2:
        summary["security_score"] += 20

    return summary

if __name__ == "__main__":
    domain = input("Enter a domain (e.g., wpbeginner.com): ").strip()
    result = generate_summary(domain)

    if result["is_wordpress"]:
        print("✅ WordPress detected")
        print(f"🧩 Detected plugins: {', '.join(result['plugins']) or 'None'}")
    else:
        print("❌ WordPress not detected")

    if result["wp_version_meta"]:
        print(f"⚠️ WP version exposed: {result['wp_version_meta']}")
    else:
        print("✅ WP version is hidden")

    print(f"📦 Plugin count: {result['plugin_count']}")
    print(f"🔐 Exposed /readme.html: {'Yes' if result['exposed_readme'] else 'No'}")
    print(f"🔐 Exposed /wp-login.php: {'Yes' if result['exposed_login'] else 'No'}")
    print(f"⚙️ PHP Version: {result['php_version'] or 'Not Detected'}")
    print(f"🛡️ Missing security headers: {', '.join(result['missing_security_headers']) or 'None'}")
    print(f"✅ Security Score: {result['security_score']} / 100")
