#!/usr/bin/env python3

import argparse
import csv
import json
import os
import random
import signal
import sys
import threading
import time

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from http.client import responses as HTTP_RESPONSES
from urllib.parse import quote, urlparse

import chardet
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text



VERSION = "3.2.0"

STOP_EVENT = threading.Event()

COUNTER_LOCK = threading.Lock()
RESULT_LOCK = threading.Lock()
PRINT_LOCK = threading.Lock()

PROCESSED = 0
FOUND = 0

console = Console()



# BANNER


RIKA_BANNER = r"""
██████╗ ██╗██╗  ██╗ █████╗
██╔══██╗██║██║ ██╔╝██╔══██╗
██████╔╝██║█████╔╝ ███████║
██╔══██╗██║██╔═██╗ ██╔══██║
██║  ██║██║██║  ██╗██║  ██║
╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝

        WEB PATH DISCOVERY ENGINE
                 RIKA V3.2
"""


def show_banner():
    banner = Text()

    banner.append(
        RIKA_BANNER,
        style="bold cyan",
    )

    banner.append(
        "\nAUTHORIZED SECURITY TESTING ONLY\n",
        style="bold white",
    )

    console.print(
        Panel(
            Align.center(banner),
            border_style="cyan",
            box=box.DOUBLE,
            padding=(1, 3),
        )
    )



# USER AGENTS


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0 Safari/537.36",

    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0 Safari/537.36",

    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",

    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) "
    "Gecko/20100101 Firefox/129.0",
]

DEFAULT_USER_AGENT = USER_AGENTS[0]




@dataclass
class Result:
    url: str
    status: int
    size: int
    words: int
    lines: int
    response_time_ms: float
    content_type: str
    server: str
    redirect: str




def load_wordlist(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"Wordlist not found: {path}"
        )

    with open(path, "rb") as f:
        raw = f.read()

    detected = chardet.detect(raw)
    encoding = detected.get("encoding") or "utf-8"

    try:
        content = raw.decode(
            encoding,
            errors="replace",
        )
    except Exception:
        content = raw.decode(
            "utf-8",
            errors="replace",
        )

    words = []
    seen = set()

    for line in content.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if line in seen:
            continue

        seen.add(line)
        words.append(line)

    return words



def normalize_url(url):
    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.netloc:
        raise ValueError(
            f"Invalid URL: {url}"
        )

    url = url.rstrip("/") + "/"

    return url


def build_url(base_url, word):
    word = word.strip()

    if not word:
        return base_url

    encoded = quote(
        word,
        safe="/:@-._~!$&'()*+,;=",
    )

    return base_url.rstrip("/") + "/" + encoded.lstrip("/")


def create_session(args):
    session = requests.Session()

    retry_strategy = Retry(
        total=args.retries,
        connect=args.retries,
        read=args.retries,
        redirect=0,
        status=0,
        backoff_factor=0.3,
        allowed_methods=frozenset(
            ["GET", "HEAD"]
        ),
        raise_on_status=False,
    )

    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=max(args.threads, 10),
        pool_maxsize=max(args.threads, 10),
        pool_block=False,
    )

    session.mount(
        "http://",
        adapter,
    )

    session.mount(
        "https://",
        adapter,
    )

    session.verify = not args.no_ssl_verify

    return session




def analyze_response(response):
    try:
        size = len(response.content)
    except Exception:
        size = 0

    try:
        text = response.text
    except Exception:
        text = ""

    words = len(
        text.split()
    )

    lines = len(
        text.splitlines()
    )

    content_type = response.headers.get(
        "Content-Type",
        "",
    )

    server = response.headers.get(
        "Server",
        "",
    )

    redirect = response.headers.get(
        "Location",
        "",
    )

    return (
        size,
        words,
        lines,
        content_type,
        server,
        redirect,
    )




class FilterEngine:

    def __init__(self, args):
        self.status_include = args.status_codes
        self.status_exclude = args.exclude_status_codes

        self.min_size = args.min_size
        self.max_size = args.max_size

        self.min_words = args.min_words
        self.max_words = args.max_words

        self.min_lines = args.min_lines
        self.max_lines = args.max_lines

    def match(self, result):
        if (
            self.status_include
            and result.status not in self.status_include
        ):
            return False

        if (
            self.status_exclude
            and result.status in self.status_exclude
        ):
            return False

        if (
            self.min_size is not None
            and result.size < self.min_size
        ):
            return False

        if (
            self.max_size is not None
            and result.size > self.max_size
        ):
            return False

        if (
            self.min_words is not None
            and result.words < self.min_words
        ):
            return False

        if (
            self.max_words is not None
            and result.words > self.max_words
        ):
            return False

        if (
            self.min_lines is not None
            and result.lines < self.min_lines
        ):
            return False

        if (
            self.max_lines is not None
            and result.lines > self.max_lines
        ):
            return False

        return True



class RikaFuzzer:

    def __init__(
        self,
        args,
        base_url,
        paths,
    ):
        self.args = args
        self.base_url = base_url
        self.paths = paths

        self.filters = FilterEngine(args)

        self.results = []

        self.start_time = time.time()

        self.total = len(paths)

        self.processed = 0
        self.errors = 0
        self.retry_count = 0

        self.local = threading.local()

        self.rate_lock = threading.Lock()
        self.last_request_time = 0.0


    def get_session(self):
        if not hasattr(
            self.local,
            "session",
        ):
            self.local.session = create_session(
                self.args
            )

        return self.local.session


    def rate_limit(self):
        delay = self.args.delay

        if delay <= 0:
            return

        with self.rate_lock:
            now = time.time()

            elapsed = now - self.last_request_time

            if elapsed < delay:
                time.sleep(
                    delay - elapsed
                )

            self.last_request_time = time.time()

  

    def request(self, path):
        url = build_url(
            self.base_url,
            path,
        )

        self.rate_limit()

        session = self.get_session()

        headers = dict(
            self.args.headers
        )

        if self.args.random_agent:
            headers["User-Agent"] = random.choice(
                USER_AGENTS
            )
        else:
            headers.setdefault(
                "User-Agent",
                DEFAULT_USER_AGENT,
            )

        started = time.perf_counter()

        try:
            response = session.request(
                method=self.args.method,
                url=url,
                headers=headers,
                timeout=self.args.timeout,
                allow_redirects=not self.args.no_redirects,
            )

            elapsed = (
                time.perf_counter()
                - started
            ) * 1000

            (
                size,
                words,
                lines,
                content_type,
                server,
                redirect,
            ) = analyze_response(
                response
            )

            result = Result(
                url=url,
                status=response.status_code,
                size=size,
                words=words,
                lines=lines,
                response_time_ms=elapsed,
                content_type=content_type,
                server=server,
                redirect=redirect,
            )

            return result

        except requests.RequestException as exc:

            self.errors += 1

            if self.args.verbose:
                self.safe_print(
                    f"[bold red]ERROR[/bold red] "
                    f"{url} -> {exc}"
                )

            return None

        except Exception as exc:

            self.errors += 1

            if self.args.verbose:
                self.safe_print(
                    f"[bold red]ERROR[/bold red] "
                    f"{url} -> {exc}"
                )

            return None



    def safe_print(self, message):
        with PRINT_LOCK:
            console.print(message)


    @staticmethod
    def status_style(status):

        if 200 <= status < 300:
            return "bold green"

        if 300 <= status < 400:
            return "bold yellow"

        if 400 <= status < 500:
            return "bold red"

        if 500 <= status < 600:
            return "bold magenta"

        return "white"


    def display(self, result):

        if self.args.quiet:
            console.print(
                result.url
            )
            return

        status = str(
            result.status
        )

        line = Text()

        line.append(
            "[",
            style="dim",
        )

        line.append(
            status,
            style=self.status_style(
                result.status
            ),
        )

        line.append(
            "] ",
            style="dim",
        )

        line.append(
            result.url,
            style="bold white",
        )

        line.append(
            f"  {result.size:,}B",
            style="cyan",
        )

        line.append(
            f"  {result.words:,}w",
            style="yellow",
        )

        line.append(
            f"  {result.lines:,}l",
            style="blue",
        )

        line.append(
            f"  {result.response_time_ms:.0f}ms",
            style="magenta",
        )

        console.print(line)


    def worker(self, path):

        if STOP_EVENT.is_set():
            return None

        result = self.request(
            path
        )

        with COUNTER_LOCK:
            self.processed += 1

        if result is None:
            return None

        if not self.filters.match(
            result
        ):
            return None

        with RESULT_LOCK:
            self.results.append(
                result
            )

        self.display(
            result
        )

        return result



    def generate_paths(self):

        targets = []

        extensions = (
            self.args.extensions
            or []
        )

        for word in self.paths:

            targets.append(
                word
            )

            if extensions:

                clean = word.rstrip(
                    "/"
                )

                for extension in extensions:

                    extension = extension.lstrip(
                        "."
                    )

                    targets.append(
                        f"{clean}.{extension}"
                    )

        return targets



    def run(self):

        global PROCESSED
        global FOUND

        targets = self.generate_paths()

        self.total = len(
            targets
        )

        if self.total == 0:

            console.print(
                Panel(
                    "No targets generated.",
                    border_style="red",
                )
            )

            return

        progress = Progress(
            SpinnerColumn(
                style="cyan"
            ),

            TextColumn(
                "[bold cyan]RIKA[/bold cyan] "
                "[white]{task.description}[/white]"
            ),

            BarColumn(
                bar_width=40
            ),

            TaskProgressColumn(),

            TextColumn(
                "[bold white]{task.completed:,}[/bold white]"
                "/[cyan]{task.total:,}[/cyan]"
            ),

            TimeRemainingColumn(),

            console=console,
        )

        task_id = progress.add_task(
            "Scanning",
            total=self.total,
        )

        console.print()

        with ThreadPoolExecutor(
            max_workers=self.args.threads
        ) as executor:

            futures = {
                executor.submit(
                    self.worker,
                    path,
                ): path
                for path in targets
            }

            completed = 0

            with progress:

                for future in as_completed(
                    futures
                ):

                    if STOP_EVENT.is_set():
                        break

                    try:
                        future.result()

                    except Exception as exc:

                        self.errors += 1

                        if self.args.verbose:
                            self.safe_print(
                                f"[bold red]ERROR[/bold red] "
                                f"{exc}"
                            )

                    completed += 1

                    progress.update(
                        task_id,
                        completed=completed,
                    )

        with COUNTER_LOCK:
            PROCESSED += self.processed
            FOUND += len(
                self.results
            )

        console.print()

        self.show_summary()

        if self.args.output:
            save_results(
                self.results,
                self.args.output,
                self.args.format,
            )



    def show_summary(self):

        duration = (
            time.time()
            - self.start_time
        )

        if duration <= 0:
            duration = 0.001

        speed = (
            self.processed
            / duration
        )

        status_2xx = 0
        status_3xx = 0
        status_4xx = 0
        status_5xx = 0

        for result in self.results:

            if 200 <= result.status < 300:
                status_2xx += 1

            elif 300 <= result.status < 400:
                status_3xx += 1

            elif 400 <= result.status < 500:
                status_4xx += 1

            elif 500 <= result.status < 600:
                status_5xx += 1

        table = Table(
            show_header=False,
            box=box.SIMPLE_HEAVY,
            expand=True,
            padding=(0, 2),
        )

        table.add_column(
            "Metric",
            style="bold cyan",
        )

        table.add_column(
            "Value",
            justify="right",
            style="bold white",
        )

        table.add_row(
            "Requests",
            f"{self.total:,}",
        )

        table.add_row(
            "Processed",
            f"{self.processed:,}",
        )

        table.add_row(
            "Found",
            f"{len(self.results):,}",
        )

        table.add_row(
            "2xx",
            f"{status_2xx:,}",
        )

        table.add_row(
            "3xx",
            f"{status_3xx:,}",
        )

        table.add_row(
            "4xx",
            f"{status_4xx:,}",
        )

        table.add_row(
            "5xx",
            f"{status_5xx:,}",
        )

        table.add_row(
            "Errors",
            f"{self.errors:,}",
        )

        table.add_row(
            "Retries",
            f"{self.retry_count:,}",
        )

        table.add_row(
            "Speed",
            f"{speed:.2f} req/s",
        )

        table.add_row(
            "Duration",
            format_duration(
                duration
            ),
        )

        console.print(
            Panel(
                table,
                title=(
                    "[bold cyan] RIKA SUMMARY [/bold cyan]"
                ),
                subtitle=(
                    "[bold white] Scan completed [/bold white]"
                ),
                border_style="cyan",
                box=box.DOUBLE,
                padding=(1, 2),
            )
        )

        console.print(
            Panel(
                Align.center(
                    Text(
                        "✓ RIKA SCAN COMPLETE",
                        style="bold cyan",
                    )
                ),
                border_style="cyan",
                box=box.ROUNDED,
            )
        )




def show_config(
    args,
    target,
    total,
):

    table = Table(
        show_header=False,
        box=box.SIMPLE,
        expand=True,
        padding=(0, 1),
    )

    table.add_column(
        "Key",
        style="bold cyan",
        width=18,
    )

    table.add_column(
        "Value",
        style="white",
    )

    table.add_row(
        "TARGET",
        target,
    )

    table.add_row(
        "WORDLIST",
        str(args.wordlist),
    )

    table.add_row(
        "REQUESTS",
        f"{total:,}",
    )

    table.add_row(
        "THREADS",
        str(args.threads),
    )

    table.add_row(
        "METHOD",
        args.method,
    )

    table.add_row(
        "TIMEOUT",
        f"{args.timeout}s",
    )

    table.add_row(
        "RETRIES",
        str(args.retries),
    )

    table.add_row(
        "DELAY",
        f"{args.delay}s",
    )

    if args.extensions:

        table.add_row(
            "EXTENSIONS",
            ", ".join(
                args.extensions
            ),
        )

    if args.random_agent:

        table.add_row(
            "USER-AGENT",
            "Randomized",
        )

    if args.no_redirects:

        table.add_row(
            "REDIRECTS",
            "Disabled",
        )

    if args.no_ssl_verify:

        table.add_row(
            "SSL VERIFY",
            "Disabled",
        )

    console.print(
        Panel(
            table,
            title="[bold cyan] RIKA CONFIG [/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def show_scan_header(
    args,
    target,
):

    table = Table(
        show_header=False,
        box=None,
        expand=True,
        padding=(0, 1),
    )

    table.add_column(
        "A",
        style="bold cyan",
        width=15,
    )

    table.add_column(
        "B",
        style="white",
    )

    table.add_row(
        "TARGET",
        target,
    )

    table.add_row(
        "METHOD",
        args.method,
    )

    table.add_row(
        "THREADS",
        str(args.threads),
    )

    console.print(
        Panel(
            table,
            title="[bold cyan] SCAN [/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def show_progress_header():

    console.print(
        Panel(
            Align.center(
                Text(
                    "SCANNING TARGET...",
                    style="bold cyan",
                )
            ),
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def show_reload(
    scan_number,
    total,
):

    console.print(
        Panel(
            Align.center(
                Text(
                    f"RELOAD #{scan_number}\n\n"
                    f"Starting new scan...\n"
                    f"Total targets: {total:,}",
                    style="bold cyan",
                )
            ),
            title=(
                "[bold cyan] RIKA RELOAD [/bold cyan]"
            ),
            border_style="cyan",
            box=box.DOUBLE,
            padding=(1, 3),
        )
    )



def parse_headers(
    header_values
):

    headers = {}

    for value in (
        header_values
        or []
    ):

        if ":" not in value:
            raise ValueError(
                f"Invalid header: {value}"
            )

        key, val = value.split(
            ":",
            1,
        )

        key = key.strip()
        val = val.strip()

        if not key:
            raise ValueError(
                f"Invalid header: {value}"
            )

        headers[key] = val

    return headers




def parse_status_codes(
    value
):

    if not value:
        return None

    codes = set()

    for part in value.split(","):

        part = part.strip()

        if not part:
            continue

        if "-" in part:

            start, end = part.split(
                "-",
                1,
            )

            start = int(
                start
            )

            end = int(
                end
            )

            if start > end:
                start, end = end, start

            for code in range(
                start,
                end + 1,
            ):
                codes.add(code)

        else:

            codes.add(
                int(part)
            )

    return codes




def build_parser():

    parser = argparse.ArgumentParser(
        prog="rika",
        description=(
            "RIKA V3.2 - Web Path Discovery Engine"
        ),
        formatter_class=(
            argparse.ArgumentDefaultsHelpFormatter
        ),
    )

 

    target = parser.add_argument_group(
        "Target"
    )

    target.add_argument(
        "-u",
        "--url",
        required=True,
        help="Target URL",
    )

    target.add_argument(
        "-w",
        "--wordlist",
        required=True,
        help="Wordlist file",
    )


    performance = parser.add_argument_group(
        "Performance"
    )

    performance.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        help="Number of worker threads",
    )

    performance.add_argument(
        "--delay",
        type=float,
        default=0,
        help="Delay between requests",
    )

    performance.add_argument(
        "--timeout",
        type=float,
        default=10,
        help="HTTP timeout",
    )

    performance.add_argument(
        "--retries",
        type=int,
        default=2,
        help="HTTP retry attempts",
    )

    performance.add_argument(
        "--reload",
        type=int,
        default=0,
        metavar="COUNT",
        help=(
            "Repeat the complete scan COUNT times"
        ),
    )

    performance.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress display",
    )

    performance.add_argument(
        "--progress-every",
        type=int,
        default=1,
        metavar="N",
        help="Update progress every N requests",
    )


    http = parser.add_argument_group(
        "HTTP"
    )

    http.add_argument(
        "-X",
        "--method",
        choices=[
            "GET",
            "HEAD",
        ],
        default="GET",
        help="HTTP method",
    )

    http.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        help=(
            "Custom HTTP header "
            "(repeatable)"
        ),
    )

    http.add_argument(
        "--no-redirects",
        action="store_true",
        help="Do not follow redirects",
    )

    http.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL verification",
    )

    http.add_argument(
        "--random-agent",
        action="store_true",
        help="Randomize User-Agent",
    )


    parser.add_argument(
        "-e",
        "--extensions",
        nargs="+",
        default=None,
        metavar="EXTENSIONS",
        help=(
            "Extensions to append, "
            "e.g. php html txt"
        ),
    )



    filters = parser.add_argument_group(
        "Filters"
    )

    filters.add_argument(
        "--status",
        dest="status_codes",
        help=(
            "Include status codes, "
            "e.g. 200,204,301-304"
        ),
    )

    filters.add_argument(
        "--exclude-status",
        dest="exclude_status",
        help="Exclude status codes",
    )

    filters.add_argument(
        "--min-size",
        type=int,
        default=None,
        help="Minimum response size",
    )

    filters.add_argument(
        "--max-size",
        type=int,
        default=None,
        help="Maximum response size",
    )

    filters.add_argument(
        "--min-words",
        type=int,
        default=None,
        help="Minimum word count",
    )

    filters.add_argument(
        "--max-words",
        type=int,
        default=None,
        help="Maximum word count",
    )

    filters.add_argument(
        "--min-lines",
        type=int,
        default=None,
        help="Minimum line count",
    )

    filters.add_argument(
        "--max-lines",
        type=int,
        default=None,
        help="Maximum line count",
    )



    output = parser.add_argument_group(
        "Output"
    )

    output.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file",
    )

    output.add_argument(
        "--format",
        choices=[
            "txt",
            "json",
            "jsonl",
            "csv",
        ],
        default="txt",
        help="Output format",
    )

    output.add_argument(
        "--quiet",
        action="store_true",
        help="Only print discovered URLs",
    )

    output.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Show errors and debug information"
        ),
    )

    return parser




def save_results(
    results,
    path,
    fmt,
):

    if not results:
        console.print(
            "[yellow]No results to save.[/yellow]"
        )
        return

    if fmt == "txt":

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as f:

            for result in results:

                f.write(
                    f"[{result.status}] "
                    f"{result.url} "
                    f"{result.size}B "
                    f"{result.words}w "
                    f"{result.lines}l "
                    f"{result.response_time_ms:.0f}ms\n"
                )

    elif fmt == "json":

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as f:

            json.dump(
                [
                    asdict(result)
                    for result in results
                ],
                f,
                indent=2,
                ensure_ascii=False,
            )

    elif fmt == "jsonl":

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as f:

            for result in results:

                f.write(
                    json.dumps(
                        asdict(result),
                        ensure_ascii=False,
                    )
                    + "\n"
                )

    elif fmt == "csv":

        fields = [
            "url",
            "status",
            "size",
            "words",
            "lines",
            "response_time_ms",
            "content_type",
            "server",
            "redirect",
        ]

        with open(
            path,
            "w",
            encoding="utf-8",
            newline="",
        ) as f:

            writer = csv.DictWriter(
                f,
                fieldnames=fields,
            )

            writer.writeheader()

            for result in results:

                writer.writerow(
                    asdict(result)
                )

    console.print(
        Panel(
            f"[bold green]Saved:[/bold green] "
            f"{path}\n"
            f"[cyan]Results:[/cyan] "
            f"{len(results):,}",
            title=(
                "[bold cyan] OUTPUT [/bold cyan]"
            ),
            border_style="green",
            box=box.ROUNDED,
        )
    )




def format_duration(
    seconds
):

    seconds = int(
        seconds
    )

    hours, remainder = divmod(
        seconds,
        3600,
    )

    minutes, seconds = divmod(
        remainder,
        60,
    )

    if hours:
        return (
            f"{hours}h "
            f"{minutes}m "
            f"{seconds}s"
        )

    if minutes:
        return (
            f"{minutes}m "
            f"{seconds}s"
        )

    return f"{seconds}s"



def handle_signal(
    signum,
    frame,
):

    STOP_EVENT.set()

    console.print()

    console.print(
        Panel(
            Align.center(
                Text(
                    "STOP SIGNAL RECEIVED\n"
                    "Stopping RIKA safely...",
                    style="bold yellow",
                )
            ),
            border_style="yellow",
            box=box.ROUNDED,
        )
    )


def show_startup():

    console.print(
        Panel(
            Align.center(
                Text(
                    "RIKA ENGINE INITIALIZED",
                    style="bold cyan",
                )
            ),
            border_style="cyan",
            box=box.ROUNDED,
        )
    )




def main():

    signal.signal(
        signal.SIGINT,
        handle_signal,
    )

    signal.signal(
        signal.SIGTERM,
        handle_signal,
    )

    show_banner()

    parser = build_parser()

    args = parser.parse_args()


    if args.threads < 1:
        parser.error(
            "--threads must be >= 1"
        )

    if args.delay < 0:
        parser.error(
            "--delay must be >= 0"
        )

    if args.timeout <= 0:
        parser.error(
            "--timeout must be > 0"
        )

    if args.retries < 0:
        parser.error(
            "--retries must be >= 0"
        )

    if args.reload < 0:
        parser.error(
            "--reload must be >= 0"
        )

    if args.progress_every < 1:
        parser.error(
            "--progress-every must be >= 1"
        )



    try:
        target = normalize_url(
            args.url
        )

    except ValueError as exc:

        console.print(
            Panel(
                str(exc),
                title="[bold red] ERROR [/bold red]",
                border_style="red",
            )
        )

        return 1


    try:
        words = load_wordlist(
            args.wordlist
        )

    except Exception as exc:

        console.print(
            Panel(
                str(exc),
                title="[bold red] ERROR [/bold red]",
                border_style="red",
            )
        )

        return 1

    if not words:

        console.print(
            Panel(
                "Wordlist is empty.",
                title="[bold red] ERROR [/bold red]",
                border_style="red",
            )
        )

        return 1



    try:
        args.headers = parse_headers(
            args.header
        )

    except ValueError as exc:

        console.print(
            Panel(
                str(exc),
                title="[bold red] ERROR [/bold red]",
                border_style="red",
            )
        )

        return 1

  

    try:
        args.status_codes = parse_status_codes(
            args.status_codes
        )

        args.exclude_status_codes = parse_status_codes(
            args.exclude_status
        )

    except ValueError:

        console.print(
            Panel(
                "Invalid status code filter.",
                title="[bold red] ERROR [/bold red]",
                border_style="red",
            )
        )

        return 1


    show_startup()

    console.print()

    show_config(
        args,
        target,
        len(words),
    )

    console.print()

    scan_number = 1


    while True:

        if STOP_EVENT.is_set():
            break

        console.print()

        show_scan_header(
            args,
            target,
        )

        console.print()

        show_progress_header()

        fuzzer = RikaFuzzer(
            args=args,
            base_url=target,
            paths=words,
        )

        try:
            fuzzer.run()

        except KeyboardInterrupt:

            STOP_EVENT.set()

            console.print(
                "\n[yellow]Stopping...[/yellow]"
            )

            break

        except Exception as exc:

            console.print(
                Panel(
                    str(exc),
                    title=(
                        "[bold red] RIKA ERROR [/bold red]"
                    ),
                    border_style="red",
                )
            )

            if args.verbose:
                raise

            return 1

     
        if args.reload <= 0:
            break

     

        if scan_number >= args.reload:
            break

        if STOP_EVENT.is_set():
            break

        scan_number += 1

        console.print()

        show_reload(
            scan_number,
            len(words),
        )

        time.sleep(1)



    console.print()

    console.print(
        Panel(
            Align.center(
                Text(
                    "RIKA V3.2\n"
                    "WEB PATH DISCOVERY ENGINE\n\n"
                    "Session finished.",
                    style="bold cyan",
                )
            ),
            border_style="cyan",
            box=box.DOUBLE,
            padding=(1, 3),
        )
    )

    return 0




if __name__ == "__main__":
    sys.exit(
        main()
    )
