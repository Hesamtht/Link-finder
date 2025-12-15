import argparse
import subprocess
import json
import sys
from pathlib import Path
import shlex
import tempfile
import os
import time
from urllib.parse import urlparse

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
        description=f"{Colors.OKBLUE}Aggregate URLs, check liveness (optional), find parameters.{Colors.ENDC}",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("domains", nargs="*", help="One or more domains to scan.")
    parser.add_argument("-tF", "--targets-file", type=Path, help="File containing target domains.")
    parser.add_argument("-o", "--output-file", type=Path, required=True, help="File to save COLLECTED (or LIVE) URLs.")
    
    parser.add_argument("-httpx", "--run-httpx", action="store_true", help="Run Httpx to check for live URLs.")
    parser.add_argument("-is", "--include-subdomains", action="store_true", help="Include subdomains in results.")

    parser.add_argument("--katana-flags", type=str, default="-silent -j -aff -ef css,js,png,jpeg,jpg,svg,gif,woff,woff2,ttf,eot,otf,ico", help="Custom flags for Katana.")
    parser.add_argument("--gospider-flags", type=str, default="-q --json --other-source --include-subs -t 20 -c 50", help="Custom flags for Gospider.")
    parser.add_argument("--gau-flags", type=str, default="--subs --providers wayback,otx,commoncrawl,urlscan", help="Custom flags for Gau.")
    parser.add_argument("--waybackurls-flags", type=str, default="", help="Custom flags for Waybackurls.")
    parser.add_argument("--httpx-flags", type=str, default="-silent -json -mc 200,201,202,203,204,206,300,301,302,303,304,307,308", help="Custom flags for Httpx.")
    parser.add_argument("--fallparams-flags", type=str, default="-silent", help="Custom flags for Fallparams.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    
    return parser.parse_args()

def run_command(command_parts, tool_name, expect_json_output=False, capture_output=True, stdin_data=None, quiet=False):
    # Minimal Output: Just "Running Tool..."
    if not quiet:
        cprint(f"[*] Running {Colors.HEADER}{tool_name}{Colors.ENDC}...", Colors.WARNING)
        
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
                if not quiet:
                    # We still show errors if a tool completely fails
                    cprint(f"[!] Error running {tool_name} (RC: {process.returncode})", Colors.FAIL)
                return None if capture_output else False

        return stdout_val if capture_output else (process.returncode == 0)

    except FileNotFoundError:
        cprint(f"[!] Error: {tool_name} not found in PATH.", Colors.FAIL)
        return None if capture_output else False
    except Exception as e:
        cprint(f"[!] Exception running {tool_name}: {e}", Colors.FAIL)
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

    # Simplified Result Output
    count_str = f"{len(urls)}"
    color = Colors.OKGREEN if urls else Colors.WARNING
    cprint(f"    -> Found {color}{count_str}{Colors.ENDC} URLs.", color)
    return urls

def get_live_urls_httpx(urls_to_check, custom_flags_str):
    if not urls_to_check: return set()

    live_urls = set()
    tmpfile_path = ""
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8', suffix=".txt") as tmpfile:
            for url in urls_to_check: tmpfile.write(url + '\n')
            tmpfile_path = tmpfile.name
        
        base_command = ['httpx', '-l', tmpfile_path]
        custom_flags = shlex.split(custom_flags_str)
        if "-json" not in custom_flags and "--json" not in custom_flags:
            custom_flags.append('-json')
        
        command = base_command + custom_flags
        httpx_output_str = run_command(command, "Httpx", expect_json_output=True, capture_output=True)

        if httpx_output_str:
            for line in httpx_output_str.strip().split('\n'):
                try:
                    data = json.loads(line)
                    url_found = data.get('url', data.get('input'))
                    if url_found: live_urls.add(str(url_found))
                except json.JSONDecodeError: pass
            cprint(f"    -> Found {Colors.OKGREEN}{len(live_urls)}{Colors.ENDC} LIVE URLs.", Colors.OKGREEN)
        else:
            cprint("    -> No response from Httpx.", Colors.FAIL)

    except Exception: pass
    finally:
        if tmpfile_path and os.path.exists(tmpfile_path):
            try: os.remove(tmpfile_path)
            except OSError: pass
            
    return live_urls

def get_parameterized_urls_fallparams_single(live_url_set, fallparams_custom_flags_str, final_output_param_file_path):
    if not live_url_set: return

    cprint(f"[*] Starting Fallparams on {len(live_url_set)} URLs...", Colors.WARNING)
    all_parameterized_urls = set()
    total_urls = len(live_url_set)
    
    for i, live_url in enumerate(live_url_set):
        # Progress Bar
        print(f"\r{Colors.WARNING}    Processing: {i+1}/{total_urls} URLs...{Colors.ENDC}", end="", flush=True)
        
        temp_fallparams_output_path_str = ""
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8', suffix=".txt") as tmp_out_fp_file:
                temp_fallparams_output_path_str = tmp_out_fp_file.name
            
            base_command = ['fallparams', '-u', live_url, '-o', temp_fallparams_output_path_str]
            custom_flags = shlex.split(fallparams_custom_flags_str)
            command = base_command + custom_flags

            success = run_command(command, "Fallparams", capture_output=True, quiet=True) 
            
            if success:
                if os.path.exists(temp_fallparams_output_path_str) and os.path.getsize(temp_fallparams_output_path_str) > 0:
                    with open(temp_fallparams_output_path_str, 'r', encoding='utf-8') as f_temp_out:
                        for line in f_temp_out:
                            all_parameterized_urls.add(line.strip())
        except Exception: pass
        finally:
            if temp_fallparams_output_path_str and os.path.exists(temp_fallparams_output_path_str):
                try: os.remove(temp_fallparams_output_path_str)
                except OSError: pass
    
    print() # Newline after progress bar

    try:
        final_output_param_file_path.parent.mkdir(parents=True, exist_ok=True)
        with final_output_param_file_path.open('w', encoding='utf-8') as f_final:
            for p_url in sorted(list(all_parameterized_urls)):
                f_final.write(p_url + '\n')
        cprint(f"[*] Found {Colors.OKGREEN}{len(all_parameterized_urls)}{Colors.ENDC} params. Saved to {Colors.OKCYAN}{final_output_param_file_path}{Colors.ENDC}", Colors.OKGREEN)
    except IOError as e:
        cprint(f"[!] Error writing file: {e}", Colors.FAIL)

def filter_subdomains(urls, targets, include_subdomains):
    if include_subdomains:
        return urls
    
    # cprint(f"\n[*] Filtering for Strict Hostname Matching...", Colors.OKBLUE)
    
    target_hosts = set()
    for t in targets:
        if "://" not in t: t = "http://" + t
        try:
            parsed = urlparse(t)
            target_hosts.add(parsed.netloc)
        except: pass
        
    filtered = set()
    for u in urls:
        try:
            u_parsed = urlparse(u)
            if u_parsed.netloc in target_hosts:
                filtered.add(u)
        except: pass
        
    cprint(f"[*] Filtered to {Colors.OKGREEN}{len(filtered)}{Colors.ENDC} URLs (Host match).", Colors.OKBLUE)
    return filtered

def extract_primary_hostname(target_domains):
    if not target_domains: return "parameters"
    first = target_domains[0]
    if "://" not in first: first = "http://" + first
    try:
        return urlparse(first).netloc
    except:
        return "parameters"

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
            except Exception: pass

    if not target_domains:
        cprint("[!] No targets.", Colors.FAIL)
        sys.exit(1)

    target_domains = sorted(list(set(filter(None, target_domains))))
    primary_hostname = extract_primary_hostname(target_domains)
    param_output_file = Path(f"{primary_hostname}_params.txt")

    cprint(f"[*] Targets: {Colors.OKCYAN}{', '.join(target_domains)}{Colors.ENDC}", Colors.OKBLUE)

    master_url_set = set()

    for domain in target_domains:
        # Removed the "--- Processing domain ---" header block as requested
        
        domain_url_for_http_tools = domain if domain.startswith(('http://', 'https://')) else f"https://{domain}"
        
        master_url_set.update(get_urls_tool("Katana", ['katana', '-u', domain_url_for_http_tools], None, args.katana_flags, is_json_tool=True))
        master_url_set.update(get_urls_tool("Gospider", ['gospider', '-s', domain_url_for_http_tools], None, args.gospider_flags, is_json_tool=True, json_key="output"))
        master_url_set.update(get_urls_tool("Gau", ['gau'], domain, args.gau_flags, is_plain_tool=True))
        master_url_set.update(get_urls_tool("Waybackurls", ['waybackurls'], domain, args.waybackurls_flags, is_plain_tool=True))

    cprint(f"\n[*] Total Collected: {Colors.OKGREEN}{len(master_url_set)}{Colors.ENDC}", Colors.OKBLUE)

    master_url_set = filter_subdomains(master_url_set, target_domains, args.include_subdomains)

    final_urls_to_process = set()

    if not master_url_set:
        cprint("[*] No URLs.", Colors.WARNING)
    else:
        if args.run_httpx:
            final_urls_to_process = get_live_urls_httpx(master_url_set, args.httpx_flags)
            cprint(f"[*] Total LIVE: {Colors.OKGREEN}{len(final_urls_to_process)}{Colors.ENDC}", Colors.OKBLUE)
        else:
            final_urls_to_process = master_url_set

    if final_urls_to_process:
        try:
            args.output_file.parent.mkdir(parents=True, exist_ok=True)
            with args.output_file.open('w', encoding='utf-8') as f:
                for url in sorted(list(final_urls_to_process)): f.write(url + '\n')
            cprint(f"[*] URLs saved to {Colors.OKCYAN}{args.output_file}{Colors.ENDC}", Colors.OKGREEN)
        except IOError: pass

        get_parameterized_urls_fallparams_single(final_urls_to_process, args.fallparams_flags, param_output_file)
        
    end_time = time.monotonic()
    total = int(end_time - start_time)
    cprint(f"\n[*] Finished in {Colors.OKBLUE}{total}s{Colors.ENDC}.", Colors.OKGREEN + Colors.BOLD)

if __name__ == "__main__":
    main()
