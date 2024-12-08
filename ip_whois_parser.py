import ipwhois
import sys
import pycountry
import ipaddress
import logging
import argparse
import json
import csv
import time
import os
import threading
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format="%(message)s")

# Global cache for network blocks
block_cache = {}
cache_lock = threading.Lock()  # Lock for thread-safe cache access
rate_limit_lock = threading.Semaphore(5)  # Allow up to 5 threads concurrently

def validate_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)

        # Check if the IP is private (RFC 1918 subnets)
        if ip_obj.is_private:
            logging.warning(f"Warning: Private-use IP {ip_obj} detected. Skipping...")
            return False

        # Special-use networks (e.g., loopback, multicast, etc.)
        special_use_networks = [
            ipaddress.ip_network("0.0.0.0/8"),  # This host on this network
            ipaddress.ip_network("127.0.0.0/8"),  # Loopback
            ipaddress.ip_network("169.254.0.0/16"),  # APIPA
            ipaddress.ip_network("192.0.0.0/24"),  # IETF Protocol Assignments
            ipaddress.ip_network("192.0.2.0/24"),  # Documentation (TEST-NET-1)
            ipaddress.ip_network("192.88.99.0/24"),  # 6to4 Relay Anycast
            ipaddress.ip_network("198.18.0.0/15"),  # Benchmarking
            ipaddress.ip_network("198.51.100.0/24"),  # Documentation (TEST-NET-2)
            ipaddress.ip_network("203.0.113.0/24"),  # Documentation (TEST-NET-3)
            ipaddress.ip_network("224.0.0.0/4"),  # Multicast
            ipaddress.ip_network("240.0.0.0/4"),  # Reserved for Future Use
            ipaddress.ip_network("100.64.0.0/10"),  # GCNAT, Shared Address Space
            ipaddress.ip_network("255.255.255.255/32"),  # Limited Broadcast
        ]

        # Check if IP belongs to special-use networks
        if any(ip_obj in net for net in special_use_networks):
            logging.warning(f"Warning: Special-use IP {ip_obj} detected. Skipping...")
            return False

        # IPv6-specific checks (multicast, reserved, unspecified)
        if ip_obj.version == 6 and (ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
            logging.warning(f"Warning: Internal IPv6 address {ip_obj} detected. Skipping...")
            return False

        return True

    except ValueError:
        logging.error(f"Error: Invalid IP address '{ip}'. Skipping...")
        return False

def get_or_default(value, default="Not Listed"):
    # Return value if valid; otherwise, return the default
    return value if value not in [None, "", "Unknown"] else default

def identify_network_block(whois_data: dict) -> str:
    # Attempt to retrieve ASN CIDR 
    asn_cidr = whois_data.get("asn_cidr")
    if asn_cidr:
        try:
            ipaddress.ip_network(asn_cidr)  # Validate CIDR format
            return asn_cidr
        except ValueError:
            pass

    # Fall back to "handle" field if ASN CIDR is unavailable or invalid
    network_info = whois_data.get("network", {})
    handle = network_info.get("handle")
    if handle:
        parts = handle.split("-")  # Parse handle field
        if len(parts) == 2:
            start_str = parts[0].strip()
            end_str = parts[1].strip()
            try:
                # Convert to IP addresses and summarize as a CIDR range
                start_ip = ipaddress.ip_address(start_str)
                end_ip = ipaddress.ip_address(end_str)
                nets = list(ipaddress.summarize_address_range(start_ip, end_ip))
                if nets:
                    return str(nets[0])
            except ValueError:
                pass
    return None  # No valid block found

def find_cached_block(ip: str) -> str:
    ip_obj = ipaddress.ip_address(ip)
    # Iterate through cached network blocks to find a match
    for block in block_cache.keys():
        net = ipaddress.ip_network(block)
        if ip_obj in net:
            return block
    return None

def parse_whois(ip_address: str, verbose: bool, raw: bool, debug: bool, max_retries=3, delay=.25) -> dict:
    # Check if the IP block is already cached
    with cache_lock:
        cached_block = find_cached_block(ip_address)
        if cached_block is not None:
            cached_result = block_cache[cached_block].copy()

    if cached_block is not None:
        # Return cached data for the IP
        link = f"https://www.whois.com/whois/{ip_address}"
        result = {
            "ip_address": ip_address,
            "country_name": cached_result.get("country_name", "Not Listed"),
            "network_name": cached_result.get("network_name", "Not Listed"),
            "link": link,
            "registration_date": cached_result.get("registration_date", "Not Listed")
        }

        if verbose:
            # Include additional WHOIS details if verbose mode is enabled
            result.update({
                "abuse_contacts": cached_result.get("abuse_contacts", "Not Listed"),
                "registrar": cached_result.get("registrar", "Not Listed"),
                "registrant_info": cached_result.get("registrant_info", "Not Listed"),
                "updated_date": cached_result.get("updated_date", "Not Listed")
            })

        return result

    # Retry mechanism for failed lookups due to rate limits
    for attempt in range(max_retries):
        time.sleep(delay)
        try:
            with rate_limit_lock:  
                time.sleep(0.10)  
                whois_obj = ipwhois.IPWhois(ip_address)
                whois_data = whois_obj.lookup_rdap()

            if raw:
                return {"ip_address": ip_address, "raw_data": whois_data}

            # Extract country information (prioritize "network.country" if two conflicting values are found)
            country_code = whois_data.get('network', {}).get('country', None) or whois_data.get('asn_country_code', None)

            if debug and whois_data.get('network', {}).get('country') != whois_data.get('asn_country_code'):
                logging.warning(f"Discrepancy detected for IP {ip_address}: network.country={whois_data.get('network', {}).get('country')} asn_country_code={whois_data.get('asn_country_code')}.")

            # Structure results from WHOIS data
            network_info = whois_data.get('network', {}) or {}
            network_name = get_or_default(whois_data.get('asn_description'))
            country = pycountry.countries.get(alpha_2=country_code)
            country_name = get_or_default(country.name if country else None)
            link = f"https://www.whois.com/whois/{ip_address}"

            result = {
                "ip_address": ip_address,
                "country_name": country_name,
                "network_name": network_name,
                "link": link,
                "registration_date": next((
                    get_or_default(event.get('timestamp')) for event in (network_info.get('events') or [])
                    if isinstance(event, dict) and event.get('action') == 'registration'
                ), "Not Listed")
            }

            if verbose:
                # Add extra info for verbose output
                abuse_contacts = "; ".join(
                    get_or_default(e.get('contact', {}).get('email', [{}])[0].get('value'))
                    for e in (whois_data.get('objects') or {}).values()
                    if isinstance(e, dict) and 'roles' in e and 'abuse' in e['roles']
                ) if whois_data.get('objects') else "Not Listed"

                registrar = get_or_default(whois_data.get('asn_description'))

                registrant_info = "; ".join(
                    get_or_default(e.get('contact', {}).get('name'))
                    for e in (whois_data.get('objects') or {}).values()
                    if isinstance(e, dict) and 'roles' in e and 'registrant' in e['roles']
                ) if whois_data.get('objects') else "Not Listed"

                updated_date = next((
                    get_or_default(event.get('timestamp')) for event in (network_info.get('events') or [])
                    if isinstance(event, dict) and event.get('action') == 'last changed'
                ), "Not Listed")

                result.update({
                    "abuse_contacts": abuse_contacts,
                    "registrar": registrar,
                    "registrant_info": registrant_info,
                    "updated_date": updated_date
                })

            # Identify and cache the network block
            block = identify_network_block(whois_data)
            if block:
                cached_data = {
                    "country_name": result.get("country_name", "Not Listed"),
                    "network_name": result.get("network_name", "Not Listed"),
                    "registration_date": result.get("registration_date", "Not Listed")
                }
                if verbose:
                    cached_data.update({
                        "abuse_contacts": result.get("abuse_contacts", "Not Listed"),
                        "registrar": result.get("registrar", "Not Listed"),
                        "registrant_info": result.get("registrant_info", "Not Listed"),
                        "updated_date": result.get("updated_date", "Not Listed")
                    })

                # Update cache with lock to ensure thread safety
                with cache_lock:
                    block_cache[block] = cached_data

            return result

        except Exception as error:
            if debug and attempt < max_retries - 1:
                logging.warning(f"Warning: Error processing IP {ip_address}: {error}. Retrying...")
            elif attempt >= max_retries - 1:
                logging.error(f"Error: Error processing IP {ip_address}: {error}. Retry limit reached. Skipping...")

# Load the IPs from a txt file 
def load_ips(file_path: str) -> list[str]:
    try:
        if not file_path.endswith(".txt"):
            raise ValueError(f"Error: Input file '{file_path}' must be a valid .txt file.")
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        logging.error(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as error:
        logging.error(f"Error: Error reading file '{file_path}': {error}.")
        sys.exit(1)

# Helper function to validate and correct output file extensions
def validate_output_extension(output_file: str, format: str) -> str:
    expected_extension = f".{format}"
    if not output_file.endswith(expected_extension):
        logging.warning(
            f"Warning: Output file extension does not match the format '{format}'. "
            f"Overriding to '{expected_extension}'. The -f argument must specify the same format as the output file's extension."
        )
        return output_file.rsplit('.', 1)[0] + expected_extension
    return output_file

# Write results to JSON
def write_to_json(results: list[dict], output_file: str):
    output_file = validate_output_extension(output_file, "json")
    try:
        with open(output_file, 'w') as file:
            json.dump(results, file, indent=4)
        logging.info(f"Info: Results saved to {os.path.join(os.getcwd(), output_file)}")
    except Exception as e:
        logging.error(f"Error: Failed to write JSON output: {e}.")

# Write results to CSV
def write_to_csv(results: list[dict], output_file: str):
    output_file = validate_output_extension(output_file, "csv")

    fieldnames = ["ip_address", "country_name", "network_name", "link", "registration_date"]

    if any("abuse_contacts" in result for result in results):
        fieldnames.extend(["abuse_contacts", "registrar", "registrant_info", "updated_date"])

    try:
        with open(output_file, 'w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                writer.writerow({key: get_or_default(result.get(key)) for key in fieldnames})
        logging.info(f"Info: Results saved to {os.path.join(os.getcwd(), output_file)}")
    except Exception as e:
        logging.error(f"Error: Failed to write CSV output: {e}.")

# Write results to plain text
def write_to_text(results: list[dict], output_file: str, verbose: bool):
    output_file = validate_output_extension(output_file, "txt")
    try:
        with open(output_file, 'w') as file:
            for result in results:
                if "error" in result:
                    file.write(f"IP Address: {result['ip_address']}\nError: {result['error']}\n===============================\n")
                elif "raw_data" in result:
                    file.write(f"IP Address: {result['ip_address']}\nRaw Data: {json.dumps(result['raw_data'], indent=4)}\n===============================\n")
                else:
                    file.write(f"IP Address: {result['ip_address']}\nCountry: {get_or_default(result.get('country_name'))}\nNetwork Name: {get_or_default(result.get('network_name'))}\nLink: {get_or_default(result.get('link'))}\nRegistration Date: {get_or_default(result.get('registration_date'))}\n")
                    if verbose:
                        file.write(f"Abuse Contacts: {get_or_default(result.get('abuse_contacts'))}\n")
                        file.write(f"Registrar: {get_or_default(result.get('registrar'))}\n")
                        file.write(f"Registrant Info: {get_or_default(result.get('registrant_info'))}\n")
                        file.write(f"Updated Date: {get_or_default(result.get('updated_date'))}\n")
                    file.write("===============================\n")
        logging.info(f"Info: Results saved to {os.path.join(os.getcwd(), output_file)}")
    except Exception as e:
        logging.error(f"Error: Failed to write text output: {e}.")

# Error handling
class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, f"Error: {message}. Use -h or --help for more info.\n")

if __name__ == "__main__":
    parser = CustomArgumentParser(description="A script for bulk WHOIS lookups for IP addresses with block caching.")
    parser.add_argument("input_file", nargs="?", help="Path to the input file containing IP addresses (one per line, must be .txt).")
    parser.add_argument("-o", "--output", default=None, help="Output file to save the results (default: auto-generated based on format).")
    parser.add_argument("-f", "--format", choices=["txt", "json", "csv"], default="txt", help="Output format: txt, json, or csv (default: txt).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode to include additional WHOIS data.")
    parser.add_argument("--raw", action="store_true", help="Output raw WHOIS data without parsing.")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode to display additional warnings and errors.")

    try:
        args = parser.parse_args()

        if args.raw and (args.verbose or args.format != "txt"):
            sys.exit("Error: The '--raw' flag cannot be combined with '-v' (verbose) or '-f' (format) options.")

        if not args.input_file:
            sys.exit("Error: Input file must be a valid .txt file. Use -h or --help for more info.")

        if not args.input_file.endswith(".txt"):
            sys.exit(f"Error: Input file '{args.input_file}' must be a valid .txt file. Use -h or --help for more info.")

        if not args.output:
            args.output = f"whois_results.{args.format}"
        else:
            args.output = validate_output_extension(args.output, args.format)

        # Load and validate IPs
        ip_list = load_ips(args.input_file)
        valid_ips = [ip for ip in ip_list if validate_ip(ip)]

        results = []

        # Track processing time and display progress bar
        last_update_time = time.time()
        start_time = time.time()

        with tqdm(total=len(valid_ips), desc="Processing IPs", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} | {postfix}") as progress_bar:
            with ThreadPoolExecutor() as executor:
                future_to_ip = {executor.submit(parse_whois, ip, args.verbose, args.raw, args.debug): ip for ip in valid_ips}
                for future in as_completed(future_to_ip):
                    result = future.result()
                    results.append(result)
                    progress_bar.update(1)

                    
                    current_time = time.time()
                    elapsed_time = current_time - start_time
                    processed = progress_bar.n
                    if processed > 0:
                        estimated_total_time = (elapsed_time / processed) * len(valid_ips)
                        remaining_time = int(estimated_total_time - elapsed_time)
                    else:
                        remaining_time = 0

                    if current_time - last_update_time >= 1: # Update "Estimated Time Remaining" every 1 second
                        hours, remainder = divmod(remaining_time, 3600)
                        minutes, seconds = divmod(remainder, 60)
                        eta_formatted = f"{hours}h {minutes}m {seconds}s" if hours > 0 else f"{minutes}m {seconds}s"
                        progress_bar.set_postfix_str(f"Estimated Time Remaining: {eta_formatted}")
                        last_update_time = current_time

        # Write results to the selected format
        if args.raw:
            write_to_text(results, args.output, verbose=False)
        else:
            if args.format == "json":
                write_to_json(results, args.output)
            elif args.format == "csv":
                write_to_csv(results, args.output)
            else:
                write_to_text(results, args.output, args.verbose)

    except Exception as e:
        logging.error(f"Error: Unexpected error occurred: {e}. Use -h or --help for more info.")
        sys.exit(1)
