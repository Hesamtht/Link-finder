🔗 Link Finder
A Python tool for Pentesting to extract and analyze links from web pages, designed to uncover endpoints, hidden APIs, and potential vulnerabilities. 🚀
✨ Features

🔍 Extracts links from HTML, JavaScript, and other web content.
📁 Supports filtering by file extensions (e.g., .js, .php).
🔗 Integrates with Katana, GoSpider, GAU, Waybackurls, and HTTPX.
📋 Outputs results in a clean, actionable format.

🛠 Dependencies



Tool
Purpose
Installation Command



Katana
Web crawler for endpoint discovery
```go install github.com/projectdiscovery/katana/cmd/katana@latest```


GoSpider
Fast web crawler for link extraction
```go install github.com/jaeles-project/gospider@latest```


GAU
Fetches URLs from AlienVault OTX
```go install github.com/lc/gau/v2/cmd/gau@latest```


Waybackurls
Retrieves archived URLs
```go install github.com/tomnomnom/waybackurls@latest```


HTTPX
HTTP client for URL probing
```go install github.com/projectdiscovery/httpx/cmd/httpx@latest```


Python 3.x
Required for running the script
```pip install -r requirements.txt```


📦 Installation
```git clone https://github.com/Hesamtht/Link-finder.git```
```cd Link-finder```
# Install Go tools (see table above)
```pip install -r requirements.txt```

🚀 Usage
```python link-finder.py -u <target-url> -o <output-file>```


```-u: Target URL to scan.```
```-o: Output file for extracted links.```

Example:
```python link-finder.py -u https://example.com -o links.txt```

Enjoy🚀
