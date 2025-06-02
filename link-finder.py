#!/usr/bin/env python3
# pylint: disable=invalid-name, too-many-locals, too-many-arguments, too-many-statements

"""
URL Aggregator and Liveness Checker Script (v2 with Colors & Timer)
This script runs Katana, Gospider, Gau, and Waybackurls for a given list of domains,
collects all unique URLs, then uses Httpx to check for live URLs,
and saves only the live URLs to a specified output file.
Output to the terminal is colorized for better readability and includes total execution time.

Prerequisites:
- Python 3
- Katana (https://github.com/projectdiscovery/katana) installed and in PATH.
- Gospider (https://github.com/jaeles-project/gospider) installed and in PATH.
- Gau (https://github.com/lc/gau) installed and in PATH.
- Waybackurls (https://github.com/tomnomnom/waybackurls) installed and in PATH.
- Httpx (https://github.com/projectdiscovery/httpx) installed and in PATH.

Example Usage:
1. Single domain:
   python url_aggregator_v2_color_timer.py example.com -o live_urls.txt

2. Multiple domains:
   python url_aggregator_v2_color_timer.py example.com anotherexample.com -o live_urls.txt

3. From a file containing domains (one per line):
   python url_aggregator_v2_color_timer.py -tF domains.txt -o live_urls.txt
"""

import argparse
import subprocess
import json
import sys
from pathlib import Path
import shlex # For safely splitting command strings
import tempfile
import os
import time # Added for timing

class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'  # Magenta (for tool names)
    OKBLUE = '\033[94m'   # Blue (for titles/info)
    OKCYAN = '\033[96m'   # Cyan (for domains/URLs)
    OKGREEN = '\033[92m'  # Green (for success)
    WARNING = '\033[93m'  # Yellow (for warnings/steps)
    FAIL = '\033[91m'     # Red (for errors)
    ENDC = '\033[0m'      # Resets color
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @staticmethod
    def disable():
        """Disables color output."""
        Colors.HEADER = ''
        Colors.OKBLUE = ''
        Colors.OKCYAN = ''
        Colors.OKGREEN = ''
        Colors.WARNING = ''
        Colors.FAIL = ''
        Colors.ENDC = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''

# Check if the terminal supports color (basic check)
# Also, allow disabling via environment variable for non-interactive scripts
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    Colors.disable()


def cprint(message, color=Colors.ENDC, **kwargs):
    """Prints a message with a given color."""
    print(f"{color}{message}{Colors.ENDC}", **kwargs)

def setup_arg_parser():
    """Sets up the argument parser."""
    parser = argparse.ArgumentParser(
        description=f"{Colors.OKBLUE}Aggregate URLs from various tools, check liveness with Httpx, and time execution.{Colors.ENDC}",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "domains",
        nargs="*",
        help="One or more domains to scan (e.g., example.com another.org)."
    )
    parser.add_argument(
        "-tF",
        "--targets-file",
        type=Path,
        help="File containing a list of target domains (one per line)."
    )
    parser.add_argument(
        "-o",
        "--output-file",
        type=Path,
        required=True,
        help="File to save the aggregated LIVE URLs."
    )
    parser.add_argument(
        "--katana-flags",
        type=str,
        default="-silent -json -aff -ef css,js,png,jpeg,jpg,svg,gif,woff,woff2,ttf,eot,otf,ico",
        help="Custom flags for Katana. Enclose in quotes. Script expects JSON output."
    )
    parser.add_argument(
        "--gospider-flags",
        type=str,
        default="-q --json --other-source --include-subs -t 20 -c 50",
        help="Custom flags for Gospider. Enclose in quotes. Script expects JSON output."
    )
    parser.add_argument(
        "--gau-flags",
        type=str,
        default="--subs --providers wayback,otx,commoncrawl,urlscan",
        help="Custom flags for Gau. Enclose in quotes."
    )
    parser.add_argument(
        "--waybackurls-flags",
        type=str,
        default="",
        help="Custom flags for Waybackurls. Enclose in quotes."
    )
    parser.add_argument(
        "--httpx-flags",
        type=str,
        default="-silent -json -mc 200,201,202,203,204,206,300,301,302,303,304,307,308", # Default: 2xx & 3xx status codes
        help="Custom flags for Httpx. Script expects JSON output for parsing (ensure -json is present). Enclose in quotes."
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output."
    )

    return parser.parse_args()

def run_command(command_parts, tool_name, expect_json_output=False):
    """
    Runs a command and returns its stdout.
    Handles FileNotFoundError if the tool isn't installed.
    """
    cprint(f"[*] Running {Colors.HEADER}{tool_name}{Colors.ENDC} with command: {' '.join(command_parts)}", Colors.WARNING)
    try:
        process = subprocess.Popen(
            command_parts,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            if not (tool_name == "Httpx" and stdout and expect_json_output):
                cprint(f"[!] Error running {Colors.HEADER}{tool_name}{Colors.ENDC}:", Colors.FAIL)
                cprint(f"    Return Code: {process.returncode}", Colors.FAIL)
                if stdout:
                    cprint(f"    Stdout: {stdout.strip()[:500]}...", Colors.FAIL)
                if stderr:
                    cprint(f"    Stderr: {stderr.strip()[:500]}...", Colors.FAIL)
                return None

        if stderr and "level=error" in stderr.lower() and tool_name != "Httpx":
            cprint(f"[!] Potential error messages from {Colors.HEADER}{tool_name}{Colors.ENDC}:", Colors.WARNING)
            cprint(stderr.strip()[:500] + "...", Colors.WARNING)
        
        return stdout
    except FileNotFoundError:
        cprint(f"[!] Error: {Colors.HEADER}{tool_name}{Colors.ENDC} not found. Please ensure it's installed and in your PATH.", Colors.FAIL)
        return None
    except Exception as e:
        cprint(f"[!] An unexpected error occurred while running {Colors.HEADER}{tool_name}{Colors.ENDC}: {e}", Colors.FAIL)
        return None

def parse_json_lines(output_str, key_name, tool_name=""):
    items = set()
    if not output_str:
        return items
    for line_num, line in enumerate(output_str.strip().split('\n'), 1):
        try:
            data = json.loads(line)
            item_value = data.get(key_name)
            if item_value:
                items.add(str(item_value))
        except json.JSONDecodeError:
            pass
        except AttributeError:
            pass
    return items

def parse_plain_urls(output_str):
    urls = set()
    if not output_str:
        return urls
    for line in output_str.strip().split('\n'):
        if line.strip() and (line.strip().startswith("http://") or line.strip().startswith("https://")):
            urls.add(line.strip())
    return urls

def get_urls_katana(domain_url, custom_flags_str):
    base_command = ['katana', '-u', domain_url]
    custom_flags = shlex.split(custom_flags_str)
    if "-json" not in custom_flags and "--json" not in custom_flags:
        cprint("[!] Warning: Katana flags do not include -json. Parsing might fail.", Colors.WARNING)
    command = base_command + custom_flags
    output = run_command(command, "Katana", expect_json_output=True)
    if output:
        urls = set()
        for line in output.strip().split('\n'):
            try:
                data = json.loads(line)
                if 'url' in data: urls.add(data['url'])
                elif 'endpoint' in data: urls.add(data['endpoint'])
                elif 'request' in data and isinstance(data['request'], dict) and 'url' in data['request']:
                     urls.add(data['request']['url'])
            except (json.JSONDecodeError, TypeError, AttributeError): pass
        cprint(f"[*] Found {Colors.OKGREEN}{len(urls)}{Colors.ENDC} URLs from {Colors.HEADER}Katana{Colors.ENDC} for {Colors.OKCYAN}{domain_url}{Colors.ENDC}", Colors.OKGREEN)
        return urls
    return set()

def get_urls_gospider(domain_url, custom_flags_str):
    base_command = ['gospider', '-s', domain_url]
    custom_flags = shlex.split(custom_flags_str)
    if "--json" not in custom_flags:
        cprint("[!] Warning: Gospider flags do not include --json. Parsing might fail.", Colors.WARNING)
    command = base_command + custom_flags
    output = run_command(command, "Gospider", expect_json_output=True)
    if output:
        urls = parse_json_lines(output, "output", "Gospider")
        cprint(f"[*] Found {Colors.OKGREEN}{len(urls)}{Colors.ENDC} URLs from {Colors.HEADER}Gospider{Colors.ENDC} for {Colors.OKCYAN}{domain_url}{Colors.ENDC}", Colors.OKGREEN)
        return urls
    return set()

def get_urls_gau(domain, custom_flags_str):
    base_command = ['gau']
    custom_flags = shlex.split(custom_flags_str)
    command = base_command + custom_flags + [domain]
    output = run_command(command, "Gau")
    if output:
        urls = parse_plain_urls(output)
        cprint(f"[*] Found {Colors.OKGREEN}{len(urls)}{Colors.ENDC} URLs from {Colors.HEADER}Gau{Colors.ENDC} for {Colors.OKCYAN}{domain}{Colors.ENDC}", Colors.OKGREEN)
        return urls
    return set()

def get_urls_waybackurls(domain, custom_flags_str):
    base_command = ['waybackurls']
    custom_flags = shlex.split(custom_flags_str)
    command = base_command + custom_flags + [domain]
    output = run_command(command, "Waybackurls")
    if output:
        urls = parse_plain_urls(output)
        cprint(f"[*] Found {Colors.OKGREEN}{len(urls)}{Colors.ENDC} URLs from {Colors.HEADER}Waybackurls{Colors.ENDC} for {Colors.OKCYAN}{domain}{Colors.ENDC}", Colors.OKGREEN)
        return urls
    return set()

def get_live_urls_httpx(urls_to_check, custom_flags_str):
    if not urls_to_check:
        cprint("[*] No URLs to check with Httpx.", Colors.WARNING)
        return set()

    live_urls = set()
    tmpfile_path = ""
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8', suffix=".txt") as tmpfile:
            for url in urls_to_check:
                tmpfile.write(url + '\n')
            tmpfile_path = tmpfile.name
        
        cprint(f"[*] Wrote {len(urls_to_check)} URLs to temporary file {tmpfile_path} for Httpx.", Colors.WARNING)

        base_command = ['httpx', '-l', tmpfile_path]
        custom_flags = shlex.split(custom_flags_str)
        
        if "-json" not in custom_flags and "--json" not in custom_flags:
            cprint("[!] Warning: Httpx flags do not include -json. Adding it for parsing.", Colors.WARNING)
            custom_flags.append('-json')

        command = base_command + custom_flags
        
        httpx_output_str = run_command(command, "Httpx", expect_json_output=True)

        if httpx_output_str:
            cprint(f"[*] Parsing Httpx JSON output...", Colors.WARNING)
            for line in httpx_output_str.strip().split('\n'):
                try:
                    data = json.loads(line)
                    url_found = data.get('url', data.get('input'))
                    if url_found:
                        live_urls.add(str(url_found))
                except json.JSONDecodeError:
                    pass
            cprint(f"[*] Found {Colors.OKGREEN}{len(live_urls)}{Colors.ENDC} live URLs from {Colors.HEADER}Httpx{Colors.ENDC}.", Colors.OKGREEN)
        else:
            cprint("[!] No output received from Httpx.", Colors.FAIL)

    except Exception as e:
        cprint(f"[!] An error occurred during Httpx processing: {e}", Colors.FAIL)
    finally:
        if tmpfile_path and os.path.exists(tmpfile_path):
            try:
                os.remove(tmpfile_path)
            except OSError as e:
                cprint(f"[!] Error deleting temporary file {tmpfile_path}: {e}", Colors.FAIL)
    return live_urls

def main():
    """Main function to orchestrate URL aggregation and liveness checking."""
    start_time = time.monotonic() # Record start time

    args = setup_arg_parser()

    if args.no_color or os.environ.get("NO_COLOR"): # Check arg and env var
        Colors.disable()

    target_domains = list(args.domains)

    if args.targets_file:
        if args.targets_file.exists():
            try:
                with args.targets_file.open('r', encoding='utf-8') as f:
                    domains_from_file = [line.strip() for line in f if line.strip()]
                    target_domains.extend(domains_from_file)
            except Exception as e:
                cprint(f"[!] Error reading targets file {args.targets_file}: {e}", Colors.FAIL)
                if not target_domains: sys.exit(1)
        else:
            cprint(f"[!] Targets file {args.targets_file} not found.", Colors.FAIL)
            if not target_domains: sys.exit(1)
    
    if not target_domains:
        cprint("[!] No target domains provided. Use positional arguments or -tF/--targets-file.", Colors.FAIL)
        sys.exit(1)

    target_domains = sorted(list(set(filter(None, target_domains))))
    
    cprint(f"[*] Target domains: {Colors.OKCYAN}{', '.join(target_domains)}{Colors.ENDC}", Colors.OKBLUE)
    cprint(f"[*] Output file for live URLs: {Colors.OKCYAN}{args.output_file}{Colors.ENDC}", Colors.OKBLUE)

    master_url_set = set()

    for domain in target_domains:
        cprint(f"\n--- Processing domain: {Colors.OKCYAN}{domain}{Colors.ENDC} ---", Colors.OKBLUE + Colors.BOLD)
        
        domain_url_for_http_tools = domain
        if not domain.startswith(('http://', 'https://')):
            domain_url_for_http_tools = f"https://{domain}"

        master_url_set.update(get_urls_katana(domain_url_for_http_tools, args.katana_flags))
        master_url_set.update(get_urls_gospider(domain_url_for_http_tools, args.gospider_flags))
        master_url_set.update(get_urls_gau(domain, args.gau_flags))
        master_url_set.update(get_urls_waybackurls(domain, args.waybackurls_flags))

    cprint(f"\n[*] Total unique URLs collected before Httpx: {Colors.OKGREEN}{len(master_url_set)}{Colors.ENDC}", Colors.OKBLUE)

    if not master_url_set:
        cprint("[*] No URLs were collected from the initial tools. Skipping Httpx.", Colors.WARNING)
        final_urls_to_write = set()
    else:
        cprint(f"\n--- Checking liveness with {Colors.HEADER}Httpx{Colors.ENDC} ---", Colors.OKBLUE + Colors.BOLD)
        final_urls_to_write = get_live_urls_httpx(master_url_set, args.httpx_flags)

    num_live_urls = len(final_urls_to_write)
    cprint(f"\n[*] Total unique LIVE URLs to be saved: {Colors.OKGREEN}{num_live_urls}{Colors.ENDC}", Colors.OKBLUE)

    try:
        with args.output_file.open('w', encoding='utf-8') as f:
            for url in sorted(list(final_urls_to_write)): # Sort for consistent output
                f.write(url + '\n')
        cprint(f"[*] Successfully saved all unique LIVE URLs to {Colors.OKCYAN}{args.output_file}{Colors.ENDC}", Colors.OKGREEN + Colors.BOLD)
    except IOError as e:
        cprint(f"[!] Error writing to output file {args.output_file}: {e}", Colors.FAIL)
        sys.exit(1)
    finally: # Ensure time is printed even if writing fails
        end_time = time.monotonic()
        total_duration_seconds = end_time - start_time
        minutes = int(total_duration_seconds // 60)
        seconds = int(total_duration_seconds % 60)
        
        time_str = ""
        if minutes > 0:
            time_str += f"{minutes} minute{'s' if minutes > 1 else ''} "
        time_str += f"{seconds} second{'s' if seconds > 1 else ''}"
        
        cprint(f"\n[*] Finished! {Colors.OKGREEN}{num_live_urls}{Colors.ENDC} live URLs found in {Colors.OKBLUE}{time_str}{Colors.ENDC}.", Colors.OKGREEN + Colors.BOLD)


if __name__ == "__main__":
    main()
