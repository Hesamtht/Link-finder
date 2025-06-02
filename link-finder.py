#!/usr/bin/env python3
# pylint: disable=invalid-name, too-many-locals, too-many-arguments, too-many-statements

"""
URL Aggregator, Liveness Checker, and Parameter Finder Script (v3.4)
This script:
1. Runs Katana, Gospider, Gau, Waybackurls to collect URLs.
2. Uses Httpx to check for live URLs from the collected set.
3. Saves these live URLs to the file specified by -o.
4. For EACH live URL, calls Fallparams to discover parameterized URLs.
5. Saves combined Fallparams output to 'parameters.txt'.
Output to the terminal is colorized and includes total execution time.
NOTE: Running Fallparams for each URL individually will be much slower.

Prerequisites:
- Python 3
- Katana, Gospider, Gau, Waybackurls, Httpx (ProjectDiscovery tools) installed and in PATH.
- Fallparams (https://github.com/glebarez/fallparams or similar) installed and in PATH.

Example Usage:
   python url_aggregator_v3.4.py example.com -o live_urls.txt
   # Parameterized URLs will be in parameters.txt
"""

import argparse
import subprocess
import json
import sys
from pathlib import Path
import shlex
import tempfile
import os
import time

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @staticmethod
    def disable():
        Colors.HEADER, Colors.OKBLUE, Colors.OKCYAN, Colors.OKGREEN, Colors.WARNING, Colors.FAIL, Colors.ENDC, Colors.BOLD, Colors.UNDERLINE = '', '', '', '', '', '', '', '', ''

if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    Colors.disable()

def cprint(message, color=Colors.ENDC, **kwargs):
    print(f"{color}{message}{Colors.ENDC}", **kwargs)

def setup_arg_parser():
    parser = argparse.ArgumentParser(
        description=f"{Colors.OKBLUE}Aggregate URLs, check liveness, find parameters (one by one), and time execution.{Colors.ENDC}",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("domains", nargs="*", help="One or more domains to scan.")
    parser.add_argument("-tF", "--targets-file", type=Path, help="File containing target domains.")
    parser.add_argument("-o", "--output-file", type=Path, required=True, help="File to save LIVE URLs (from httpx). Parameterized URLs will be in 'parameters.txt'.")
    parser.add_argument("--katana-flags", type=str, default="-silent -j -aff -ef css,js,png,jpeg,jpg,svg,gif,woff,woff2,ttf,eot,otf,ico", help="Custom flags for Katana.")
    parser.add_argument("--gospider-flags", type=str, default="-q --json --other-source --include-subs -t 20 -c 50", help="Custom flags for Gospider.")
    parser.add_argument("--gau-flags", type=str, default="--subs --providers wayback,otx,commoncrawl,urlscan", help="Custom flags for Gau.")
    parser.add_argument("--waybackurls-flags", type=str, default="", help="Custom flags for Waybackurls.")
    parser.add_argument("--httpx-flags", type=str, default="-silent -json -mc 200,201,202,203,204,206,300,301,302,303,304,307,308", help="Custom flags for Httpx.")
    parser.add_argument("--fallparams-flags", type=str, default="-silent", help="Custom flags for Fallparams. Do not include -u or -o here.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    return parser.parse_args()

def run_command(command_parts, tool_name, expect_json_output=False, capture_output=True, stdin_data=None):
    cprint(f"[*] Running {Colors.HEADER}{tool_name}{Colors.ENDC} with command: {' '.join(command_parts)}{' (with stdin)' if stdin_data else ''}", Colors.WARNING)
    try:
        process = subprocess.Popen(
            command_parts,
            stdin=subprocess.PIPE if stdin_data else None,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE,
            text=True, encoding='utf-8', errors='ignore'
        )
        stdout_val, stderr_val = None, None
        if stdin_data:
            stdout_val, stderr_val = process.communicate(input=stdin_data)
        elif capture_output:
            stdout_val, stderr_val = process.communicate()
        else:
            _, stderr_val = process.communicate()

        if process.returncode != 0:
            if not (tool_name == "Httpx" and stdout_val and expect_json_output):
                cprint(f"[!] Error running {Colors.HEADER}{tool_name}{Colors.ENDC}:", Colors.FAIL)
                cprint(f"    Return Code: {process.returncode}", Colors.FAIL)
                if stdout_val: cprint(f"    Stdout: {stdout_val.strip()[:500]}...", Colors.FAIL)
                if stderr_val: cprint(f"    Stderr: {stderr_val.strip()[:500]}...", Colors.FAIL)
                return None if capture_output else False
        if stderr_val and "error" in stderr_val.lower() and tool_name not in ["Httpx", "Fallparams", "Gau"]:
            cprint(f"[!] Potential error messages from {Colors.HEADER}{tool_name}{Colors.ENDC}:", Colors.WARNING)
            cprint(stderr_val.strip()[:500] + "...", Colors.WARNING)
        return stdout_val if capture_output else (process.returncode == 0)
    except FileNotFoundError:
        cprint(f"[!] Error: {Colors.HEADER}{tool_name}{Colors.ENDC} not found. Please ensure it's installed and in your PATH.", Colors.FAIL)
        return None if capture_output else False
    except Exception as e:
        cprint(f"[!] An unexpected error occurred while running {Colors.HEADER}{tool_name}{Colors.ENDC}: {e}", Colors.FAIL)
        return None if capture_output else False

def parse_json_lines(output_str, key_name, tool_name=""):
    items = set()
    if not output_str: return items
    for line in output_str.strip().split('\n'):
        try:
            data = json.loads(line)
            item_value = data.get(key_name)
            if item_value: items.add(str(item_value))
        except (json.JSONDecodeError, AttributeError): pass
    return items

def parse_plain_urls(output_str):
    urls = set()
    if not output_str: return urls
    for line in output_str.strip().split('\n'):
        if line.strip() and (line.strip().startswith("http://") or line.strip().startswith("https://")):
            urls.add(line.strip())
    return urls

def get_urls_tool(tool_name, base_cmd_list, domain_or_url, custom_flags_str, is_json_tool=False, json_key=None, is_plain_tool=False):
    custom_flags = shlex.split(custom_flags_str)
    command = base_cmd_list + custom_flags
    if domain_or_url and tool_name in ["Gau", "Waybackurls"]:
        command.append(domain_or_url)
    if is_json_tool and ((tool_name == "Katana" and "-j" not in command) or \
                        (tool_name == "Gospider" and "--json" not in command)):
        cprint(f"[!] Warning: {tool_name} flags do not include its JSON output flag. Parsing might fail.", Colors.WARNING)
    output = run_command(command, tool_name, expect_json_output=is_json_tool, capture_output=True)
    urls = set()
    if output:
        if is_json_tool:
            if tool_name == "Katana":
                for line in output.strip().split('\n'):
                    try:
                        data = json.loads(line)
                        if 'url' in data: urls.add(data['url'])
                        elif 'endpoint' in data: urls.add(data['endpoint'])
                        elif 'request' in data and isinstance(data['request'], dict) and 'url' in data['request']:
                            urls.add(data['request']['url'])
                    except (json.JSONDecodeError, TypeError, AttributeError): pass
            elif json_key: urls = parse_json_lines(output, json_key, tool_name)
        elif is_plain_tool: urls = parse_plain_urls(output)
    display_target = domain_or_url if domain_or_url else base_cmd_list[-1] 
    cprint(f"[*] Found {Colors.OKGREEN if urls else Colors.WARNING}{len(urls)}{Colors.ENDC} URLs from {Colors.HEADER}{tool_name}{Colors.ENDC} for {Colors.OKCYAN}{display_target}{Colors.ENDC}", Colors.OKGREEN if urls else Colors.WARNING)
    return urls

def get_live_urls_httpx(urls_to_check, custom_flags_str):
    if not urls_to_check:
        cprint("[*] No URLs to check with Httpx.", Colors.WARNING)
        return set()
    live_urls = set()
    tmpfile_path = ""
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8', suffix=".txt") as tmpfile:
            for url in urls_to_check: tmpfile.write(url + '\n')
            tmpfile_path = tmpfile.name
        cprint(f"[*] Wrote {len(urls_to_check)} URLs to temporary file {tmpfile_path} for Httpx.", Colors.WARNING)
        base_command = ['httpx', '-l', tmpfile_path]
        custom_flags = shlex.split(custom_flags_str)
        if "-json" not in custom_flags and "--json" not in custom_flags:
            cprint("[!] Warning: Httpx flags do not include -json. Adding it for parsing.", Colors.WARNING)
            custom_flags.append('-json')
        command = base_command + custom_flags
        httpx_output_str = run_command(command, "Httpx", expect_json_output=True, capture_output=True)
        if httpx_output_str:
            cprint(f"[*] Parsing Httpx JSON output...", Colors.WARNING)
            for line in httpx_output_str.strip().split('\n'):
                try:
                    data = json.loads(line)
                    url_found = data.get('url', data.get('input'))
                    if url_found: live_urls.add(str(url_found))
                except json.JSONDecodeError: pass
            cprint(f"[*] Found {Colors.OKGREEN}{len(live_urls)}{Colors.ENDC} live URLs from {Colors.HEADER}Httpx{Colors.ENDC}.", Colors.OKGREEN)
        else: cprint("[!] No output received from Httpx.", Colors.FAIL)
    except Exception as e: cprint(f"[!] An error occurred during Httpx processing: {e}", Colors.FAIL)
    finally:
        if tmpfile_path and os.path.exists(tmpfile_path):
            try: os.remove(tmpfile_path)
            except OSError as e: cprint(f"[!] Error deleting temporary file {tmpfile_path}: {e}", Colors.FAIL)
    return live_urls

def get_parameterized_urls_fallparams_single(live_url_set, fallparams_custom_flags_str, final_output_param_file_path):
    if not live_url_set:
        cprint(f"[*] No live URLs to process with Fallparams.", Colors.WARNING)
        return

    cprint(f"[*] Processing {len(live_url_set)} live URLs with Fallparams (one by one)... This may take a while.", Colors.WARNING)

    all_parameterized_urls = set()
    processed_count = 0

    for live_url in live_url_set:
        processed_count += 1
        cprint(f"    -> Processing URL ({processed_count}/{len(live_url_set)}): {Colors.OKCYAN}{live_url}{Colors.ENDC}", Colors.WARNING)

        temp_fallparams_output = None
        try:
            # Create a temporary file for this single URL's fallparams output
            with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8', suffix=".txt") as tmp_out_fp_file:
                temp_fallparams_output_path_str = tmp_out_fp_file.name

            # Fallparams uses -u for a single URL, -o for its output file.
            base_command = ['fallparams.exe', '-u', live_url, '-o', temp_fallparams_output_path_str]
            custom_flags = shlex.split(fallparams_custom_flags_str) # User flags like -silent, -d wordlist etc.
            command = base_command + custom_flags

            success = run_command(command, "Fallparams (single)", capture_output=False) 

            if success:
                if os.path.exists(temp_fallparams_output_path_str) and os.path.getsize(temp_fallparams_output_path_str) > 0:
                    with open(temp_fallparams_output_path_str, 'r', encoding='utf-8') as f_temp_out:
                        for line in f_temp_out:
                            all_parameterized_urls.add(line.strip())
                    cprint(f"    ✓ Parameters found for {Colors.OKCYAN}{live_url}{Colors.ENDC}", Colors.OKGREEN)
                else:
                    cprint(f"    - No parameters found by Fallparams for {Colors.OKCYAN}{live_url}{Colors.ENDC} (or output file empty).", Colors.OKBLUE)
            else:
                cprint(f"    ✗ Fallparams failed or was interrupted for {Colors.OKCYAN}{live_url}{Colors.ENDC}", Colors.FAIL)

        except Exception as e:
            cprint(f"    ✗ Error processing {Colors.OKCYAN}{live_url}{Colors.ENDC} with Fallparams: {e}", Colors.FAIL)
        finally:
            if temp_fallparams_output_path_str and os.path.exists(temp_fallparams_output_path_str):
                try: os.remove(temp_fallparams_output_path_str)
                except OSError: pass # Ignore error on temp file deletion

    # Write all collected unique parameterized URLs to the final parameters.txt
    try:
        final_output_param_file_path.parent.mkdir(parents=True, exist_ok=True)
        with final_output_param_file_path.open('w', encoding='utf-8') as f_final:
            for p_url in sorted(list(all_parameterized_urls)):
                f_final.write(p_url + '\n')
        cprint(f"[*] Found {Colors.OKGREEN}{len(all_parameterized_urls)}{Colors.ENDC} unique parameterized URLs in total. Saved to {Colors.OKCYAN}{final_output_param_file_path}{Colors.ENDC}", Colors.OKGREEN)
    except IOError as e:
        cprint(f"[!] Error writing final parameterized URLs to {final_output_param_file_path}: {e}", Colors.FAIL)


def main():
    start_time = time.monotonic()
    args = setup_arg_parser()
    if args.no_color or os.environ.get("NO_COLOR"): Colors.disable()

    target_domains = list(args.domains)
    if args.targets_file:
        if args.targets_file.exists():
            try:
                with args.targets_file.open('r', encoding='utf-8') as f:
                    target_domains.extend([line.strip() for line in f if line.strip()])
            except Exception as e:
                cprint(f"[!] Error reading targets file {args.targets_file}: {e}", Colors.FAIL)
                if not target_domains: sys.exit(1)
        else:
            cprint(f"[!] Targets file {args.targets_file} not found.", Colors.FAIL)
            if not target_domains: sys.exit(1)

    if not target_domains:
        cprint("[!] No target domains provided.", Colors.FAIL)
        sys.exit(1)

    target_domains = sorted(list(set(filter(None, target_domains))))
    cprint(f"[*] Target domains: {Colors.OKCYAN}{', '.join(target_domains)}{Colors.ENDC}", Colors.OKBLUE)
    cprint(f"[*] Live URLs output file: {Colors.OKCYAN}{args.output_file}{Colors.ENDC}", Colors.OKBLUE)
    param_output_file = Path("parameters.txt")
    cprint(f"[*] Parameterized URLs output file: {Colors.OKCYAN}{param_output_file}{Colors.ENDC}", Colors.OKBLUE)

    master_url_set = set()
    for domain in target_domains:
        cprint(f"\n--- Processing domain: {Colors.OKCYAN}{domain}{Colors.ENDC} ---", Colors.OKBLUE + Colors.BOLD)
        domain_url_for_http_tools = domain if domain.startswith(('http://', 'https://')) else f"https://{domain}"

        master_url_set.update(get_urls_tool("Katana", ['katana', '-u', domain_url_for_http_tools], None, args.katana_flags, is_json_tool=True))
        master_url_set.update(get_urls_tool("Gospider", ['gospider', '-s', domain_url_for_http_tools], None, args.gospider_flags, is_json_tool=True, json_key="output"))
        master_url_set.update(get_urls_tool("Gau", ['gau'], domain, args.gau_flags, is_plain_tool=True))
        master_url_set.update(get_urls_tool("Waybackurls", ['waybackurls'], domain, args.waybackurls_flags, is_plain_tool=True))

    cprint(f"\n[*] Total unique URLs collected before Httpx: {Colors.OKGREEN}{len(master_url_set)}{Colors.ENDC}", Colors.OKBLUE)

    live_urls_to_write = set()
    if not master_url_set:
        cprint("[*] No URLs collected from initial tools. Skipping Httpx and Fallparams.", Colors.WARNING)
    else:
        cprint(f"\n--- Checking liveness with {Colors.HEADER}Httpx{Colors.ENDC} ---", Colors.OKBLUE + Colors.BOLD)
        live_urls_to_write = get_live_urls_httpx(master_url_set, args.httpx_flags)

    num_live_urls = len(live_urls_to_write)
    cprint(f"\n[*] Total unique LIVE URLs (from Httpx): {Colors.OKGREEN}{num_live_urls}{Colors.ENDC}", Colors.OKBLUE)

    if num_live_urls > 0 or not master_url_set :
        try:
            args.output_file.parent.mkdir(parents=True, exist_ok=True)
            with args.output_file.open('w', encoding='utf-8') as f:
                for url in sorted(list(live_urls_to_write)): f.write(url + '\n')
            cprint(f"[*] Successfully saved {num_live_urls} live URLs to {Colors.OKCYAN}{args.output_file}{Colors.ENDC}", Colors.OKGREEN + Colors.BOLD)
        except IOError as e:
            cprint(f"[!] Error writing live URLs to {args.output_file}: {e}", Colors.FAIL)

    if num_live_urls > 0:
        cprint(f"\n--- Discovering parameters with {Colors.HEADER}Fallparams (single URL mode){Colors.ENDC} ---", Colors.OKBLUE + Colors.BOLD)
        get_parameterized_urls_fallparams_single(live_urls_to_write, args.fallparams_flags, param_output_file)
    elif master_url_set :
        cprint(f"\n[*] No live URLs found by Httpx. Skipping {Colors.HEADER}Fallparams{Colors.ENDC}.", Colors.WARNING)

    end_time = time.monotonic()
    total_duration_seconds = end_time - start_time
    minutes = int(total_duration_seconds // 60)
    seconds = int(total_duration_seconds % 60)
    time_str = f"{minutes} minute{'s' if minutes != 1 else ''} {seconds} second{'s' if seconds != 1 else ''}" if minutes > 0 else f"{seconds} second{'s' if seconds != 1 else ''}"

    cprint(f"\n[*] Finished! Process completed in {Colors.OKBLUE}{time_str}{Colors.ENDC}.", Colors.OKGREEN + Colors.BOLD)

if __name__ == "__main__":
    main()
