import uuid

from typing import Optional
from httpx import RequestError
from tarsius.attacks.attack import Attack
from tarsius.definitions.spring4shell import Spring4ShellFinding
from tarsius.utils.log import log_red, log_verbose
from tarsius.network import Request, Response
from tarsius.network.web import http_repr


class ModuleSpring4Shell(Attack):
    """
    Detect the Spring4Shell vulnerability
    """
    name = "spring4shell"

    async def _default_request(self, request_url: str, method: str) -> int:
        request = Request(
            path=request_url,
            method=method,
        )
        response = await self.crawler.async_send(request, follow_redirects=False)
        return response.status

    async def _attack_spring4shell_url(self, request: Request):
        payload_unique_id = uuid.uuid4()
        payload = self._generate_payload(payload_unique_id)

        try:
            if not await self._check_spring4shell("GET", request, payload):
                await self._check_spring4shell("POST", request, payload)

        except RequestError:
            self.network_errors += 1
            return

    async def attack(self, request: Request, response: Optional[Response] = None):
        await self._attack_spring4shell_url(request)

    async def _check_spring4shell(self, method: str, request: Request, payload: str) -> bool:
        key_payload, value_payload = payload.split("=")

        params = request.get_params
        params.append([key_payload, value_payload])

        malicious_request = Request(
            path=request.url,
            method=method,
            get_params=params if method == "GET" else request.get_params,
            post_params=params if method == "POST" else None,
        )

        log_verbose(malicious_request)
        try:
            default_response = await self._default_request(request.url, method)
            response = await self.crawler.async_send(malicious_request, follow_redirects=False)
        except RequestError:
            self.network_errors += 1
            return False
        if response.is_redirect:
            return False
        if not response.is_success and default_response != response.status:
            await self._vulnerable(malicious_request)
            return True
        return False

    async def _vulnerable(self, request: Request):
        await self.add_critical(
            finding_class=Spring4ShellFinding,
            request=request,
            info=f"URL {request.url} seems vulnerable to Spring4Shell attack",
            parameter=None,
        )

        log_red("---")
        log_red("URL {0} seems vulnerable to Spring4Shell attack", request.url)
        log_red(http_repr(request))
        log_red("---")

    @staticmethod
    def _generate_payload(unique_id: uuid.UUID) -> str:
        return f"class.module.classLoader[{unique_id}]={unique_id}"
