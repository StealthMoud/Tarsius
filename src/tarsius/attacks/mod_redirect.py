from typing import Optional
from urllib.parse import urlparse

from httpx import RequestError

from tarsius.utils.log import log_red, log_verbose
from tarsius.attacks.attack import Attack
from tarsius.language.vulnerability import Messages
from tarsius.definitions.redirect import RedirectFinding
from tarsius.core.model import str_to_payloadinfo
from tarsius.network import Request, Response
from tarsius.network.web import http_repr
from tarsius.parsers.html_parser import Html


class ModuleRedirect(Attack):
    """Detect Open Redirect vulnerabilities."""
    # Won't work with PHP >= 4.4.2

    name = "redirect"
    MSG_VULN = "Open Redirect"
    do_get = True
    do_post = False
    parallelize_attacks = True

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        super().__init__(crawler, persister, attack_options, crawler_configuration)
        self.mutator = self.get_mutator()

    async def attack(self, request: Request, response: Optional[Response] = None):
        page = request.path

        for mutated_request, parameter, __ in self.mutator.mutate(
                request,
                str_to_payloadinfo(["https://openbugbounty.org/", "//openbugbounty.org/"]),
        ):
            log_verbose(f"[¨] {mutated_request.url}")

            try:
                response = await self.crawler.async_send(mutated_request)
            except RequestError:
                self.network_errors += 1
                continue

            html = Html(response.content, mutated_request.url)
            all_redirections = {response.redirection_url} | html.all_redirections
            if any(urlparse(url).netloc.endswith("openbugbounty.org") for url in all_redirections):
                await self.add_low(
                    finding_class=RedirectFinding,
                    request=mutated_request,
                    parameter=parameter.display_name,
                    info=f"{self.MSG_VULN} via injection in the parameter {parameter.display_name}",
                    response=response
                )

                if not parameter.is_qs_injection:
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
