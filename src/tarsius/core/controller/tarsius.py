import asyncio
import os
import sys
from collections import deque
from dataclasses import replace
from hashlib import sha256
from time import gmtime, strftime
from typing import List, Deque
from urllib.parse import urlparse

import browser_cookie3
from playwright.async_api import async_playwright, Error as PlaywrightError

from tarsius import TARSIUS_VERSION
from tarsius.attacks.active_scanner import ActiveScanner
from tarsius.attacks.passive_scanner import PassiveScanner
from tarsius.core.controller.exceptions import InvalidOptionValue
from tarsius.definitions import vulnerabilities, flatten_references, anomalies, additionals
from tarsius.network import Request, jsoncookie
from tarsius.network.classes import CrawlerConfiguration, HttpCredential
from tarsius.network.explorer import Explorer
from tarsius.network.intercepting_explorer import InterceptingExplorer
from tarsius.network.scope import Scope
from tarsius.network.sql_persister import SqlPersister
from tarsius.reports import get_report_generator_instance
from tarsius.utils.log import logging, configure, log_green, log_red, log_blue

SCAN_FORCE_VALUES = {
    "paranoid": 1,
    "sneaky": 0.7,
    "polite": 0.5,
    "normal": 0.2,
    "aggressive": 0.06,
    "insane": 0  # Special value that won't be really used
}


class Tarsius:
    # parse options and set up modules

    REPORT_DIR = "report"
    HOME_DIR = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    COPY_REPORT_DIR = os.path.join(HOME_DIR, ".tarsius", "generated_report")

    def __init__(self, scope_request: Request, scope="folder", session_dir=None, config_dir=None):
        self.base_request: Request = scope_request
        self.server: str = scope_request.netloc

        self.crawler_configuration = CrawlerConfiguration(self.base_request)
        # self.crawler = None

        self.target_scope = Scope(self.base_request, scope)

        self.report_gen = None
        self.report_generator_type = "html"
        self.output_file = ""

        self.urls = []
        self.forms = []

        self.color_enabled = False
        self.verbose = 0
        self._start_urls: Deque[Request] = deque([self.base_request])
        self._excluded_urls = []
        self._bad_params = set()
        self._max_depth = 40
        self._max_links_per_page = 0
        self._max_files_per_dir = 0
        self._scan_force = "normal"
        self._max_scan_time = None
        self._logfile = ""
        self._auth_state = None
        self._mitm_proxy_port = 0
        self._proxy = None
        self.detailed_report_level = 0
        self._headless_mode = "no"
        self._wait_time = 2.
        self._buffer = []

        if session_dir:
            SqlPersister.CRAWLER_DATA_DIR = session_dir

        if config_dir:
            SqlPersister.CONFIG_DIR = config_dir

        server_url = self.server.replace(':', '_')
        hashed_root_url = sha256(scope_request.url.encode(errors='replace')).hexdigest()[:8]

        self._history_file = os.path.join(
            SqlPersister.CRAWLER_DATA_DIR,
            f"{server_url}_{self.target_scope.name}_{hashed_root_url}.db"
        )

        if not os.path.isdir(SqlPersister.CRAWLER_DATA_DIR):
            os.makedirs(SqlPersister.CRAWLER_DATA_DIR)

        self.persister = SqlPersister(self._history_file)
        self._active_scanner = ActiveScanner(
            persister=self.persister,
            crawler_configuration=self.crawler_configuration,
            verbosity=self.verbose
        )
        self._passive_scanner = PassiveScanner(persister=self.persister)

    def refresh_logging(self):
        verbosity_levels = {
            0: "INFO",
            1: "INFO",
            2: "VERBOSE"
        }

        handlers = [
            {
                "sink": sys.stdout,
                "colorize": self.color_enabled,
                "level": verbosity_levels[self.verbose]
            }
        ]
        if self._logfile:
            handlers.append({"sink": self._logfile, "level": "DEBUG"})
        configure(handlers=handlers)

    def set_logfile(self, filename: str):
        self._logfile = filename
        self.refresh_logging()

    async def init_persister(self):
        await self.persister.create()

    @property
    def history_file(self):
        return self._history_file

    async def init_report(self):
        self.report_gen = get_report_generator_instance(self.report_generator_type.lower())

        self.report_gen.set_report_info(
            target=self.base_request.url,
            scope=self.target_scope.name,
            date=gmtime(),
            version=f"Tarsius {TARSIUS_VERSION}",
            auth=self._auth_state,
            crawled_pages=await self.persister.get_crawled_paths() if self.detailed_report_level == 2 else [],
            crawled_pages_nbr=await self.count_resources(),
            detailed_report_level=self.detailed_report_level
        )

        for vul in vulnerabilities:
            self.report_gen.add_vulnerability_type(
                vul.name(),
                vul.description(),
                vul.solution(),
                flatten_references(vul.references()),
                vul.wstg_code()
            )

        for anomaly in anomalies:
            self.report_gen.add_anomaly_type(
                anomaly.name(),
                anomaly.description(),
                anomaly.solution(),
                flatten_references(anomaly.references()),
                anomaly.wstg_code()
            )

        for additional in additionals:
            self.report_gen.add_additional_type(
                additional.name(),
                additional.description(),
                additional.solution(),
                flatten_references(additional.references()),
                additional.wstg_code()
            )

    async def load_scan_state(self):
        async for request in self.persister.get_to_browse():
            self._start_urls.append(request)
        async for request, __ in self.persister.get_links():
            self._excluded_urls.append(request)
        async for request, __ in self.persister.get_forms():
            self._excluded_urls.append(request)

        await self.persister.set_root_url(self.base_request.url)

    async def save_scan_state(self):
        # save urls that arent scanned yet in bulk
        await self.persister.set_to_browse(self._start_urls)

        log_green("This scan has been saved in the file {0}", self.persister.output_file)
        # if stopped and self._start_urls:
        #     print(_("The scan will be resumed next time unless you pass the --skip-crawl option."))

    async def explore_and_save_requests(self, explorer):
        self._buffer = []
        # brows urls and save when buffer gets big
        async for request, response in explorer.async_explore(self._start_urls, self._excluded_urls):
            self._buffer.append((request, response))

            await self._passive_scanner.scan(request, response)

            if len(self._buffer) > 100:
                await self.persister.save_requests(self._buffer)
                self._buffer = []
                log_blue(f"Discovery progress: {await self.count_resources()} URLs found...")

    async def browse(self, stop_event: asyncio.Event, parallelism: int = 8):
        """get links and forms from pages"""
        stop_event.clear()

        if self._mitm_proxy_port or self._headless_mode != "no":
            modified_configuration = replace(self.crawler_configuration)
            modified_configuration.proxy = f"http://127.0.0.1:{self._mitm_proxy_port or 8080}/"

            explorer = InterceptingExplorer(
                modified_configuration,
                self.target_scope,
                stop_event,
                parallelism=parallelism,
                mitm_port=self._mitm_proxy_port or 8080,
                proxy=self._proxy,
                drop_cookies=self.crawler_configuration.drop_cookies,
                headless=self._headless_mode,
                cookies=self.crawler_configuration.cookies,
                wait_time=self._wait_time,
            )
        else:
            explorer = Explorer(self.crawler_configuration, self.target_scope, stop_event, parallelism=parallelism)

        explorer.max_depth = self._max_depth
        explorer.max_files_per_dir = self._max_files_per_dir
        explorer.max_requests_per_depth = self._max_links_per_page
        explorer.forbidden_parameters = self._bad_params
        explorer.qs_limit = SCAN_FORCE_VALUES[self._scan_force]
        explorer.load_saved_state(self.persister.output_file[:-2] + "pkl")

        self._buffer = []

        try:
            await asyncio.wait_for(
               self.explore_and_save_requests(explorer),
               self._max_scan_time
            )
        except asyncio.TimeoutError:
            logging.info("Max scan time was reached, stopping.")
            if not stop_event.is_set():
                stop_event.set()
        finally:
            await explorer.clean()

        await self.persister.save_requests(self._buffer)

        # save explorer state
        explorer.save_state(self.persister.output_file[:-2] + "pkl")
        # swap cookis for next step
        self.crawler_configuration.cookies = explorer.cookie_jar

    async def write_report(self):
        if not self.output_file:
            if self.report_generator_type == "html":
                self.output_file = self.COPY_REPORT_DIR
            else:
                filename = f"{self.server.replace(':', '_')}_{strftime('%m%d%Y_%H%M', self.report_gen.scan_date)}"
                self.output_file = filename + "." + self.report_generator_type

        async for payload in self.persister.get_payloads():
            if payload.type == "vulnerability":
                self.report_gen.add_vulnerability(
                    category=payload.category,
                    level=payload.level,
                    request=payload.evil_request,
                    parameter=payload.parameter,
                    info=payload.info,
                    module=payload.module,
                    wstg=payload.wstg,
                    response=payload.response
                )
            elif payload.type == "anomaly":
                self.report_gen.add_anomaly(
                    category=payload.category,
                    level=payload.level,
                    request=payload.evil_request,
                    parameter=payload.parameter,
                    info=payload.info,
                    module=payload.module,
                    wstg=payload.wstg,
                    response=payload.response
                )
            elif payload.type == "additional":
                self.report_gen.add_additional(
                    category=payload.category,
                    level=payload.level,
                    request=payload.evil_request,
                    parameter=payload.parameter,
                    info=payload.info,
                    module=payload.module,
                    wstg=payload.wstg,
                    response=payload.response
                )

        print('')
        log_blue("[*] Generating report...")
        self.report_gen.generate_report(self.output_file)
        log_green(f"A report has been generated in the file {self.output_file}")
        if self.report_generator_type == "html":
            log_blue(f"Open {self.report_gen.final_path} with a browser to see this report.")

        await self.persister.close()

    def set_timeout(self, timeout: float = 10.0):
        """set how long to wait for http"""
        self.crawler_configuration.timeout = timeout

    def set_verify_ssl(self, verify: bool = False):
        """check ssl or not"""
        self.crawler_configuration.secure = verify

    def set_proxy(self, proxy: str):
        """use a proxy"""
        self._proxy = proxy
        self.crawler_configuration.proxy = proxy
        # Update mitm proxy settings
        self.set_intercepting_proxy_port(self._mitm_proxy_port)

    def set_intercepting_proxy_port(self, port: int):
        """set port for mitm stuff"""
        if not port:
            return

        self._mitm_proxy_port = port
        # self.crawler_configuration.proxy = f"http://127.0.0.1:{self._mitm_proxy_port}/"
        if self._proxy:
            parts = urlparse(self._proxy)
            if parts.scheme not in ("http", "https"):
                raise InvalidOptionValue(
                    "--proxy", f"The proxy protocol '{parts.scheme}' is not supported by mitmproxy"
                )

    async def set_headless(self, headless_mode: str):
        """set headless browser mode"""
        if headless_mode != "no":
            async with async_playwright() as p:
                try:
                    if not os.path.exists(p.firefox.executable_path):
                        log_red(
                            "Firefox is not installed. "
                            "Please run `tarsius-install-headless-browser`"
                        )
                        self._headless_mode = "no"
                    else:
                        self._headless_mode = headless_mode
                except PlaywrightError:
                    log_red(
                        "Could not find browser installation. "
                        "Please run `tarsius-install-headless-browser`"
                    )
                    self._headless_mode = "no"

    @property
    def headless_mode(self) -> str:
        return self._headless_mode

    def set_wait_time(self, wait_time: float):
        """how long to wait for page content"""
        self._wait_time = wait_time

    def add_start_url(self, request: Request):
        """add url to start the scan"""
        self._start_urls.append(request)

    def add_excluded_url(self, url_or_pattern: str):
        """add url to skip"""
        self._excluded_urls.append(url_or_pattern)

    @property
    def excluded_urls(self) -> List[str]:
        return self._excluded_urls

    def set_cookie_file(self, cookie: str):
        """get cookis from a file"""
        if os.path.isfile(cookie):
            json_cookie = jsoncookie.JsonCookie()
            json_cookie.load(cookie)
            cookiejar = json_cookie.cookiejar(self.server)
            self.crawler_configuration.cookies = cookiejar

    def load_browser_cookies(self, browser_name: str):
        """get cookis from browser"""
        browser_name = browser_name.lower()
        if browser_name == "firefox":
            cookiejar = browser_cookie3.firefox()
            self.crawler_configuration.cookies = cookiejar
        elif browser_name == "chrome":
            cookiejar = browser_cookie3.chrome()
            # workaround for chrome cooky bug
            for cookie in cookiejar:
                cookie.expires = None
            self.crawler_configuration.cookies = cookiejar
        else:
            raise InvalidOptionValue('--cookie', browser_name)

    def set_drop_cookies(self):
        self.crawler_configuration.drop_cookies = True

    def set_http_credentials(self, credentials: HttpCredential):
        """set login creds"""
        self.crawler_configuration.http_credential = credentials

    def add_bad_param(self, param_name: str):
        """skip a param in urls"""
        self._bad_params.add(param_name)

    def set_max_depth(self, limit: int):
        """set scan depth"""
        self._max_depth = limit

    def set_max_links_per_page(self, limit: int):
        self._max_links_per_page = limit

    def set_max_files_per_dir(self, limit: int):
        self._max_files_per_dir = limit

    def set_scan_force(self, force: str):
        self._scan_force = force

    def set_max_scan_time(self, seconds: float):
        self._max_scan_time = seconds

    def set_color(self):
        """use colors in console"""
        self.color_enabled = True
        self.refresh_logging()

    def set_detail_report(self, detailed_report_level: int):
        self.detailed_report_level = detailed_report_level
        # 1 => normal / level="INFO"
        # 2 => verbose / level="VERBOSE"

    def verbosity(self, verbose: int):
        """set verbosity level"""
        self.verbose = verbose
        self._active_scanner.set_verbosity(verbose)
        self.refresh_logging()
        # 0 => quiet / level="SUCCESS"
        # 1 => normal / level="INFO"
        # 2 => verbose / level="VERBOSE"

    def set_report_generator_type(self, report_type: str = "xml"):
        """set report format (html, json, etc)"""
        self.report_generator_type = report_type

    def set_output_file(self, output_file: str):
        """set where to save report"""
        self.output_file = output_file

    def add_custom_header(self, key: str, value: str):
        if self.crawler_configuration.headers is None:
            self.crawler_configuration.headers = {}

        self.crawler_configuration.headers[key] = value

    async def flush_attacks(self):
        await self.persister.flush_attacks()

    async def flush_session(self):
        await self.persister.close()
        try:
            os.unlink(self._history_file)
        except FileNotFoundError:
            pass

        try:
            os.unlink(self.persister.output_file[:-2] + "pkl")
        except FileNotFoundError:
            pass
        self.persister = SqlPersister(self._history_file)
        await self.persister.create()

    async def count_resources(self) -> int:
        return await self.persister.count_paths()

    async def has_scan_started(self) -> bool:
        return await self.persister.has_scan_started()

    async def have_attacks_started(self) -> bool:
        return await self.persister.have_attacks_started()

    def set_auth_state(self, is_logged_in: bool, form: dict, url: str):
        self._auth_state = {
            "url": url,
            "logged_in": is_logged_in,
            "form": form,
        }

    @property
    def active_scanner(self):
        return self._active_scanner

    @property
    def passive_scaner(self):
        return self._passive_scanner
