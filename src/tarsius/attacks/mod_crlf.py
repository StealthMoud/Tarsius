from typing import Optional

from httpx import ReadTimeout, HTTPStatusError, RequestError

from tarsius.attacks.attack import Attack
from tarsius.language.vulnerability import Messages
from tarsius.definitions.crlf import CrlfFinding
from tarsius.definitions.resource_consumption import ResourceConsumptionFinding
from tarsius.core.model import PayloadInfo, str_to_payloadinfo
from tarsius.network import Request, Response
from tarsius.utils.log import logging, log_verbose, log_orange, log_red
from tarsius.network.web import http_repr


class ModuleCrlf(Attack):
    """Detect Carriage Return Line Feed (CRLF) injection vulnerabilities."""
    # Won't work with PHP >= 4.4.2

    name = "crlf"
    MSG_VULN = "CRLF Injection"
    do_get = True
    do_post = True
    payloads = [PayloadInfo(payload="http://www.google.fr\r\ntarsius: 3.2.10 version")]
    parallelize_attacks = True

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        super().__init__(crawler, persister, attack_options, crawler_configuration)
        self.mutator = self.get_mutator()

    async def attack(self, request: Request, response: Optional[Response] = None):
        page = request.path

        for mutated_request, parameter, _payload in self.mutator.mutate(
                request,
                str_to_payloadinfo(["http://www.google.fr\r\ntarsius: 3.2.10 version"]),
        ):
            log_verbose(f"[¨] {mutated_request.url}")

            try:
                response = await self.crawler.async_send(mutated_request)
            except ReadTimeout:
                self.network_errors += 1
                await self.add_medium(
                    finding_class=ResourceConsumptionFinding,
                    request=mutated_request,
                    parameter=parameter.display_name,
                    info="Timeout (" + parameter.display_name + ")",
                )

                log_orange("---")
                log_orange(Messages.MSG_TIMEOUT, page)
                log_orange(Messages.MSG_EVIL_REQUEST)
                log_orange(http_repr(mutated_request))
                log_orange("---")
            except HTTPStatusError:
                self.network_errors += 1
                logging.error("Error: The server did not understand this request")
            except RequestError:
                self.network_errors += 1
            else:
                if "tarsius" in response.headers:
                    await self.add_low(
                        finding_class=CrlfFinding,
                        request=mutated_request,
                        parameter=parameter.display_name,
                        info=f"{self.MSG_VULN} via injection in the parameter {parameter.display_name}",
                        response=response,
                    )

                    if parameter.is_qs_injection:
                        injection_msg = Messages.MSG_QS_INJECT
                    else:
                        injection_msg = Messages.MSG_PARAM_INJECT

                    log_red("---")
                    log_red(
                        injection_msg,
                        self.MSG_VULN,
                        page,
                        parameter.display_name
                    )
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(http_repr(mutated_request))
                    log_red("---")
