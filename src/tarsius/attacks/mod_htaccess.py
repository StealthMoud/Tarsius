from typing import Optional

from httpx import RequestError

from tarsius.attacks.attack import Attack
from tarsius.definitions.htaccess import HtaccessBypassFinding
from tarsius.network import Request, Response
from tarsius.utils.log import log_red, log_verbose


class ModuleHtaccess(Attack):
    """
    Attempt to bypass access controls to a resource by using a custom HTTP method.
    """

    name = "htaccess"

    do_get = True
    do_post = True

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if request.path in self.attacked_get:
            return False

        if response.is_directory_redirection:
            return False

        return response.status in (401, 402, 403, 407)

    async def attack(self, request: Request, response: Optional[Response] = None):
        url = request.path
        referer = request.referer
        original_status = response.status
        headers = {}
        if referer:
            headers["referer"] = referer

        evil_req = Request(url, method="ABC")
        try:
            response = await self.crawler.async_send(evil_req, headers=headers)
        except RequestError:
            self.network_errors += 1
            return

        if response.status == 404 or response.status < 400 or response.status >= 500:
            # Every 4xx status should be uninteresting (specially bad request in our case)

            unblocked_content = response.content

            log_red("---")
            await self.add_medium(
                finding_class=HtaccessBypassFinding,
                request=evil_req,
                info=f"{evil_req.url} bypassable weak restriction",
                response=response
            )
            log_red(f"Weak restriction bypass vulnerability: {evil_req.url}")
            log_red(f"HTTP status code changed from {original_status} to {response.status}")

            log_verbose("Source code:")
            log_verbose(unblocked_content)
            log_red("---")

        self.attacked_get.append(url)
