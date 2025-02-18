#!/usr/bin/env python3

import argparse
import requests
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored terminal output
init()


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="A tool for web application fuzzing with multiple FUZZ support"
    )
    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="URL for fuzzing (use FUZZ keyword where payloads should be injected)",
    )
    parser.add_argument(
        "-z",
        "--payload",
        action="append",
        required=True,
        help='Payload specification in format "type,source". Type can be range or file. '
        "For range: range,1-100 or range,0x00-0xFF. For file: file,wordlist.txt. "
        "Multiple -z flags can be used for multiple FUZZ occurrences.",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=1,
        help="Number of concurrent threads (default: 1)",
    )
    parser.add_argument(
        "-m",
        "--method",
        default="GET",
        choices=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
        help="HTTP method (default: GET)",
    )
    parser.add_argument(
        "-d", "--data", help="Data to be sent in the body (can contain FUZZ keywords)"
    )
    parser.add_argument(
        "-H",
        "--headers",
        default=[
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome"
        ],
        action="append",
        help='Custom headers in format "name: value" (can be used multiple times)',
    )
    parser.add_argument(
        "-mc",
        "--codes",
        help="Filter responses by comma-separated status codes (e.g., 200,302,404) or ranges (e.g., 2xx, 4xx)",
    )
    parser.add_argument(
        "-ms", "--size", help="Filter responses by size (e.g., >100, <1000, =512)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0,
        help="Delay between requests in seconds (default: 0)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-c", "--color", action="store_true", help="Colorized output")

    return parser.parse_args()


def parse_range(range_str):
    try:
        if "0x" in range_str:
            start, end = range_str.split("-")
            start = int(start, 16)
            end = int(end, 16)
            return [format(i, "x") for i in range(start, end + 1)]
        else:
            start, end = map(int, range_str.split("-"))
            return [str(i) for i in range(start, end + 1)]
    except ValueError:
        print(
            f"{Fore.RED}Error: Invalid range format. Use 'start-end' (e.g., 1-100 or 0x00-0xFF).{Style.RESET_ALL}"
        )
        sys.exit(1)


def read_wordlist(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(
            f"{Fore.RED}Error: Wordlist file '{file_path}' not found.{Style.RESET_ALL}"
        )
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error reading wordlist: {e}{Style.RESET_ALL}")
        sys.exit(1)


def parse_headers(headers_list):
    if not headers_list:
        return {}

    headers = {}
    for header in headers_list:
        try:
            name, value = header.split(":", 1)
            headers[name.strip()] = value.strip()
        except ValueError:
            print(
                f"{Fore.YELLOW}Warning: Ignoring invalid header format: {header}{Style.RESET_ALL}"
            )

    return headers


def parse_payload_spec(payload_specs):
    payloads_list = []

    for spec in payload_specs:
        try:
            payload_type, payload_source = spec.split(",", 1)

            if payload_type.lower() == "range":
                payloads_list.append(parse_range(payload_source))
            elif payload_type.lower() == "file":
                payloads_list.append(read_wordlist(payload_source))
            else:
                print(
                    f"{Fore.RED}Error: Unknown payload type '{payload_type}'. Use 'range' or 'file'.{Style.RESET_ALL}"
                )
                sys.exit(1)
        except ValueError:
            print(
                f"{Fore.RED}Error: Invalid payload specification format. Use 'type,source' (e.g., range,1-100 or file,wordlist.txt).{Style.RESET_ALL}"
            )
            sys.exit(1)

    return payloads_list


def parse_status_codes(codes_str):
    if not codes_str:
        return None

    result = set()
    patterns = codes_str.split(",")

    for pattern in patterns:
        pattern = pattern.strip().lower()

        if pattern == "2xx":
            result.update(range(200, 300))
        elif pattern == "3xx":
            result.update(range(300, 400))
        elif pattern == "4xx":
            result.update(range(400, 500))
        elif pattern == "5xx":
            result.update(range(500, 600))
        else:
            try:
                result.add(int(pattern))
            except ValueError:
                print(
                    f"{Fore.YELLOW}Warning: Invalid status code pattern '{pattern}'. Ignoring.{Style.RESET_ALL}"
                )

    return result if result else None


def match_size_filter(size, filter_exp):
    if not filter_exp:
        return True

    operator = filter_exp[0]
    if operator not in [">", "<", "="]:
        try:
            value = int(filter_exp)
            return size == value
        except ValueError:
            return False

    try:
        value = int(filter_exp[1:])
        if operator == ">":
            return size > value
        elif operator == "<":
            return size < value
        elif operator == "=":
            return size == value
    except ValueError:
        return False


def replace_fuzz_keywords(text, combo):
    if not text:
        return text

    result = text
    for item in combo:
        result = result.replace("FUZZ", str(item), 1)

    return result


def process_request(
    combo, args, url_template, data_template, codes_filter, results, counter
):
    # Replace FUZZ occurrences in URL and data
    url = replace_fuzz_keywords(url_template, combo)
    data = replace_fuzz_keywords(data_template, combo) if data_template else None
    headers = parse_headers(args.headers)

    start_time = time.time()
    try:
        response = requests.request(
            method=args.method,
            url=url,
            headers=headers,
            data=data,
            timeout=args.timeout,
            allow_redirects=False,
        )

        elapsed = time.time() - start_time
        content_length = len(response.content)

        # Check if response matches the filters
        if (not codes_filter or response.status_code in codes_filter) and (
            not args.size or match_size_filter(content_length, args.size)
        ):
            result = {
                "combo": combo,
                "url": url,
                "status": response.status_code,
                "length": content_length,
                "time": elapsed,
            }
            results.append(result)

            # Print result immediately
            color = Fore.RESET
            if args.color:
                color = (
                    Fore.GREEN
                    if 200 <= response.status_code < 300
                    else Fore.YELLOW
                    if 300 <= response.status_code < 400
                    else Fore.RED
                    if 400 <= response.status_code < 600
                    else Fore.WHITE
                )

            combo_str = ",".join(str(x) for x in combo)
            if args.verbose:
                print(
                    f"{color}[+] {combo_str:<20} | {response.status_code:<3} | {content_length:<8} | {elapsed:.4f}s | {url}{Style.RESET_ALL}"
                )
            else:
                print(
                    f"{color}[+] {combo_str:<20} | {response.status_code:<3} | {content_length:<8}{Style.RESET_ALL}"
                )

    except requests.exceptions.Timeout:
        if args.verbose:
            print(
                f"{Fore.YELLOW if args.color else ''}[-] {','.join(str(x) for x in combo):<30} | Timeout | {url}{Style.RESET_ALL}"
            )
    except requests.exceptions.RequestException as e:
        if args.verbose:
            print(
                f"{Fore.RED if args.color else ''}[!] {','.join(str(x) for x in combo):<30} | Error: {str(e)} | {url}{Style.RESET_ALL}"
            )

    # Update counter and show progress
    counter["processed"] += 1
    if counter["processed"] % 100 == 0 or counter["processed"] == counter["total"]:
        progress = counter["processed"] / counter["total"] * 100
        print(
            f"\r{Fore.CYAN if args.color else ''}Progress: {counter['processed']}/{counter['total']} ({progress:.1f}%){Style.RESET_ALL}",
            end="",
        )
        sys.stdout.flush()

    # Add delay if specified
    if args.delay > 0:
        time.sleep(args.delay)


def main():
    args = parse_arguments()

    # Validate inputs
    fuzz_count_url = args.url.count("FUZZ")
    fuzz_count_data = args.data.count("FUZZ") if args.data else 0
    fuzz_count = fuzz_count_url + fuzz_count_data

    if fuzz_count == 0:
        print(
            f"{Fore.RED if args.color else ''}Error: FUZZ keyword must be present in URL or data.{Style.RESET_ALL}"
        )
        sys.exit(1)

    # Parse payloads
    payloads_list = parse_payload_spec(args.payload)

    if len(payloads_list) != fuzz_count:
        print(
            f"{Fore.RED if args.color else ''}Error: Number of payload specifications ({len(payloads_list)}) "
            f"doesn't match the number of FUZZ occurrences ({fuzz_count}).{Style.RESET_ALL}"
        )
        sys.exit(1)

    # Parse status codes filter
    codes_filter = parse_status_codes(args.codes)

    # Generate combinations
    combinations = []

    def generate_combinations(current_combo, lists, index=0):
        if index == len(lists):
            combinations.append(tuple(current_combo))
            return
        for item in lists[index]:
            generate_combinations(current_combo + [item], lists, index + 1)

    generate_combinations([], payloads_list)
    total_combinations = len(combinations)

    if total_combinations == 0:
        print(
            f"{Fore.RED if args.color else ''}Error: No valid combinations to process.{Style.RESET_ALL}"
        )
        sys.exit(1)

    # Print banner and settings
    print(f"{Fore.CYAN if args.color else ''}{'=' * 80}")
    print("Fuzzinator - Web Fuzzing Tool")
    print(f"{'=' * 80}")
    print(f"Target URL: {args.url}")
    print(f"Method: {args.method}")
    print(f"FUZZ occurrences: {fuzz_count}")
    print(f"Threads: {args.threads}")
    print(f"Total combinations: {total_combinations}")
    if codes_filter:
        print(f"Filter by status codes: {args.codes}")
    if args.size:
        print(f"Filter by size: {args.size}")
    print(f"{'=' * 80}{Style.RESET_ALL}")

    # Print table header
    if args.verbose:
        print(
            f"{Fore.CYAN if args.color else ''}{'PAYLOAD':<20} | {'CODE':<4} | {'LENGTH':<8} | {'TIME':<8}{Style.RESET_ALL}"
        )
        print(
            f"{Fore.CYAN if args.color else ''}{'-' * 20}-+-{'-' * 4}-+-{'-' * 8}-+-{'-' * 8}{Style.RESET_ALL}"
        )
    else:
        print(
            f"{Fore.CYAN if args.color else ''}{'PAYLOAD':<20} | {'CODE':<4} | {'LENGTH':<8}{Style.RESET_ALL}"
        )
        print(
            f"{Fore.CYAN if args.color else ''}{'-' * 20}-+-{'-' * 4}-+-{'-' * 8}{Style.RESET_ALL}"
        )

    # Run fuzzing with threads
    results = []
    counter = {"processed": 0, "total": total_combinations}

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for combo in combinations:
            executor.submit(
                process_request,
                combo,
                args,
                args.url,
                args.data,
                codes_filter,
                results,
                counter,
            )

    # Print summary
    print(f"\n\n{Fore.CYAN if args.color else ''}{'=' * 80}")
    print(
        f"Fuzzing complete - {len(results)} matching results found out of {total_combinations} combinations"
    )
    print(f"{'=' * 80}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(
            f"\n{Fore.YELLOW if '-c' in sys.argv or '--color' in sys.argv else ''}Fuzzing interrupted by user.{Style.RESET_ALL}"
        )
        sys.exit(0)
