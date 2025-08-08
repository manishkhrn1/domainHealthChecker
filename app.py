from flask import Flask, render_template, request
import dns.resolver
import socket
import requests
import os

app = Flask(__name__)

def get_txt_records(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Google + Cloudflare DNS
        return [r.to_text().strip('"') for r in resolver.resolve(domain, 'TXT')]
    except Exception as e:
        return [f"Error: {str(e)}"]

def check_ssl(domain):
    try:
        socket.create_connection((domain, 443), timeout=5)
        return True
    except Exception:
        return False

def check_wordpress(domain):
    try:
        url = f"https://{domain}"
        r = requests.get(url, timeout=5)
        content = r.text.lower()
        headers = r.headers

        is_wp = "wp-content" in content or "wp-includes" in content or "wordpress" in content

        plugins = []
        if "wp-content/plugins/" in content:
            lines = content.split("wp-content/plugins/")
            for line in lines[1:]:
                plugin = line.split("/")[0]
                if plugin and plugin not in plugins:
                    plugins.append(plugin)

        # WordPress version detection
        version = "Unknown"
        for line in content.splitlines():
            if 'name="generator"' in line and "wordpress" in line:
                try:
                    version = line.split('content="')[1].split('"')[0]
                except IndexError:
                    pass
                break

        # Server & X-Powered-By headers
        server = headers.get("Server", "Not exposed")
        powered_by = headers.get("X-Powered-By", "Not exposed")

        return is_wp, plugins, version, server, powered_by

    except Exception:
        return False, [], "Error", "Error", "Error"
@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        domain = request.form['domain'].strip()
        if not domain:
            return render_template('index.html', result={"error": "Please enter a domain."})

        # Use public resolver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']

        def safe_txt(d):
            try:
                return [r.to_text().strip('"') for r in resolver.resolve(d, 'TXT')]
            except Exception as e:
                return [f"Error: {str(e)}"]

        # Run lookups
        spf = safe_txt(domain)
        dmarc = safe_txt(f"_dmarc.{domain}")

        # Try DKIM with known working selector (for Google)
        dkim = safe_txt(f"google._domainkey.{domain}")  # Works for google.com

        ssl = check_ssl(domain)
        is_wp, plugins, version, server, powered_by = check_wordpress(domain)


        result = {
            "domain": domain,
            "SPF": spf,
            "DKIM": dkim,
            "DMARC": dmarc,
            "SSL": ssl,
            "WordPress": is_wp,
            "Plugins": plugins
        }

    return render_template('index.html', result=result)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
