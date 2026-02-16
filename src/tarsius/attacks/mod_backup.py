from difflib import SequenceMatcher
from os.path import splitext, join as path_join
from urllib.parse import urljoin
from typing import Optional, Iterator

from httpx import RequestError

from tarsius.utils.log import log_verbose, log_red, log_orange
from tarsius.attacks.attack import Attack, random_string, Parameter
from tarsius.definitions.backup import BackupFinding
from tarsius.core.model import PayloadInfo
from tarsius.network import Request, Response
from tarsius.parsers.txt_payload_parser import TxtPayloadReader


def compare_responses(response1: str, response2: str) -> bool:
    """
    Compare two responses to determine if they are too similar.
    return True if the responses are too similar (false positive), False otherwise.
    """
    similarity_threshold: float = 0.9
    # Compute similarity ratio directly on raw responses
    similarity = SequenceMatcher(None, response1, response2).quick_ratio()
    return similarity > similarity_threshold


class ModuleBackup(Attack):
    """
    Uncover backup files on the web server.
    """
    name = "backup"

    do_get = True
    do_post = False

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        super().__init__(crawler, persister, attack_options, crawler_configuration)
        self.false_positive_directories = {}

    def get_payloads(self, _: Optional[Request] = None, __: Optional[Parameter] = None) -> Iterator[PayloadInfo]:
        """Load the payloads from the specified file"""
        payload_reader = TxtPayloadReader(path_join(self.DATA_DIR, "backupPayloads.txt"))
        yield from payload_reader

    async def is_false_positive(self, request: Request):
        # Check for false positives by asking an improbable file inside the same folder
        # Use a dict to cache state for each directory
        if request.dir_name not in self.false_positive_directories:
            request = Request(urljoin(request.dir_name, random_string() + ".zip"))
            try:
                response = await self.crawler.async_send(request)
            except RequestError:
                self.network_errors += 1
                # Do not put anything in false_positive_directories, another luck for next time
                return False

            self.false_positive_directories[request.dir_name] = (response and response.is_success)

        return self.false_positive_directories[request.dir_name]

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        page = request.path
        headers = response.headers

        if response.is_directory_redirection:
            return False

        if page in self.attacked_get:
            return False

        # Do not attack application-type files
        if "content-type" not in headers:
            # Sometimes there's no content-type... so we rely on the document extension
            if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
                return False
        elif "text" not in headers["content-type"]:
            return False

        return not await self.is_false_positive(request)

    async def attack(self, request: Request, response: Optional[Response] = None):
        page = request.path

        for payload_info in self.get_payloads():
            raw_payload = payload_info.payload

            if request.file_name:
                if "[FILE_" not in raw_payload:
                    continue

                raw_payload = raw_payload.replace("[FILE_NAME]", request.file_name)
                raw_payload = raw_payload.replace("[FILE_NOEXT]", splitext(request.file_name)[0])
                url = page.replace(request.file_name, raw_payload)
            else:
                if "[FILE_" in raw_payload:
                    continue
                url = urljoin(request.path, raw_payload)

            log_verbose(f"[¨] {url}")

            self.attacked_get.append(page)
            evil_req = Request(url)

            try:
                original_response = await self.crawler.async_send(request)
                response = await self.crawler.async_send(evil_req)
            except RequestError:
                self.network_errors += 1
                continue
            if response and response.is_success:
                if compare_responses(response.content or "", original_response.content or ""):
                    log_orange(f"Skipping {evil_req.url} because it's too similar to the response from {request.url}")
                    continue
                log_red(f"Found backup file {evil_req.url}")

                await self.add_low(
                    finding_class=BackupFinding,
                    request=evil_req,
                    info=f"Backup file {url} found for {page}",
                    response=response
                )
