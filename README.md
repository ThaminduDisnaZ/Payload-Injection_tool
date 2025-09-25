# Web Payload Injection Tester

A Python-based command-line tool designed to help security researchers and developers test web applications for common injection vulnerabilities. This tool automates the process of discovering web forms and injecting various payloads to identify security flaws.

## 📜 Description

This script targets a given URL, automatically detects all HTML forms, and attempts to inject payloads to test for the following vulnerabilities:

  * **Cross-Site Scripting (XSS)**
  * **SQL Injection (SQLi)**
  * **Command Injection**
  * **LDAP Injection**
  * **Server-Side Template Injection (SSTI)**

The tool provides options to specify the vulnerability type, use custom payload lists, adjust request delays, and generate a JSON report of the findings.

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized security testing only**. Using this tool on any web application without explicit permission from the owner is illegal. The author is not responsible for any misuse or damage caused by this script. **Always act ethically and legally.**

## ✨ Features

  * **Multi-Vulnerability Scanning:** Test for XSS, SQLi, Command Injection, LDAP, and Template Injection.
  * **Automatic Form Discovery:** Crawls the target URL to find all testable forms.
  * **Pre-defined Payloads:** Comes with a built-in set of common payloads for quick testing.
  * **Custom Payload Support:** Load your own payloads from a text file.
  * **Configurable Delay:** Set a delay between requests to avoid rate-limiting or overwhelming the server.
  * **Report Generation:** Output findings to the console or save them as a structured JSON file.

## ⚙️ Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/ThaminduDisnaZ/Payload-Injection_tool.git
    cd Payload-Injection_tool
    ```

2.  **Install the required Python libraries:**

    ```bash
    pip install requests beautifulsoup4
    ```

## 🚀 Usage

The script is run from the command line. The only required argument is the target URL.

### Basic Syntax

```bash
python payload_injector.py <target_url> [options]
```

### Command-Line Arguments

| Argument                | Short | Description                                                              | Default |
| ----------------------- | ----- | ------------------------------------------------------------------------ | ------- |
| `url`                   |       | **Required.** The full URL of the target web page to test.                 |         |
| `--type <type>`         | `-t`  | The type of vulnerability to test for.                                   | `all`   |
| `--payloads <file>`     | `-p`  | Path to a file containing custom payloads (one per line).                | `None`  |
| `--delay <seconds>`     | `-d`  | Delay in seconds between each HTTP request.                              | `1`     |
| `--output <file>`       | `-o`  | The file name to save the JSON report.                                   | `None`  |

**Available types for `--type`:** `xss`, `sql_injection`, `command_injection`, `template_injection`, `ldap_injection`, `all`.

-----

### Examples

1.  **Run a full scan on a target URL:**
    *This will test for all vulnerability types.*

    ```bash
    python payload_injector.py http://testsite.com/login.php
    ```

2.  **Test only for Cross-Site Scripting (XSS):**

    ```bash
    python payload_injector.py http://testsite.com/search.php -t xss
    ```

3.  **Test for SQL Injection with a custom payload file and a 2-second delay:**

    ```bash
    python payload_injector.py https://example.com/form.php -t sql_injection -p custom_sql_payloads.txt -d 2
    ```

4.  **Run a full scan and save the results to a JSON file:**

    ```bash
    python payload_injector.py http://testsite.com -o vulnerability_report.json
    ```

## 📝 How It Works

1.  **Fetch & Parse:** The tool sends a GET request to the target URL and parses the HTML content using BeautifulSoup.
2.  **Form Discovery:** It identifies all `<form>` tags on the page.
3.  **Payload Injection:** For each discovered form, it iterates through its input fields (`<input type="text">`, `<input type="password">`, etc.).
4.  **Submission:** It injects a payload into each input field and submits the form using the specified method (`GET` or `POST`).
5.  **Response Analysis:** It analyzes the server's response to check for indications of a vulnerability.
      * **XSS:** Checks if the payload is reflected in the response body.
      * **SQLi:** Checks for common SQL database error messages.
      * **Command Injection:** Looks for output from common system commands (e.g., `id`, `whoami`).
      * **Template Injection:** Checks if simple mathematical expressions in the payload (e.g., `{{7*7}}`) are evaluated to their result (`49`).
6.  **Reporting:** If a vulnerability is detected, the details (URL, payload, form info) are stored. Finally, a report is printed to the console or saved to a file.

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
