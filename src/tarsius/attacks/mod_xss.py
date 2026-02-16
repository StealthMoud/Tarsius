from os.path import join as path_join
from typing import Optional, Iterator, List, Tuple, Dict

from httpx import ReadTimeout, RequestError

from tarsius.utils.log import log_orange, log_red, log_verbose
from tarsius.attacks.attack import Attack, Mutator, ParameterSituation, random_string, Parameter
from tarsius.language.vulnerability import Messages
from tarsius.definitions.reflected_xss import XssFinding
from tarsius.definitions.html_injection import HtmlInjectionFinding
from tarsius.definitions.resource_consumption import ResourceConsumptionFinding
from tarsius.definitions.internal_error import InternalErrorFinding
from tarsius.core.model import PayloadInfo
from tarsius.network.web import http_repr
from tarsius.network.xss_utils import generate_payloads, valid_xss_content_type, check_payload
from tarsius.network.csp_utils import has_strong_csp
from tarsius.network import Request, Response
from tarsius.parsers.html_parser import Html


def get_random_string_payload(_: Request, __: Parameter) -> Iterator[PayloadInfo]:
    yield PayloadInfo(payload=random_string())


class ModuleXss(Attack):
    """find permanant xss vulns on the server."""

    name = "xss"
    parallelize_attacks = True

    # dicts for permanent xss scaning
    # get_xss structure : {uniq_code : http://url/?param1=value1...}
    # post_xss structure : {uniq_code: [target_url, params, referer]}
    tried_xss: Dict[str, Tuple[Request, Parameter]] = {}
    PHP_SELF = []

    # key = taint code, value = (evil request, payload info)
    successful_xss: Dict[str, Tuple[Request, PayloadInfo]] = {}

    PAYLOADS_FILE = path_join(Attack.DATA_DIR, "xssPayloads.ini")

    RANDOM_WEBSITE = f"https://{random_string(length=6)}.com/"

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        Attack.__init__(self, crawler, persister, attack_options, crawler_configuration)
        methods = ""
        if self.do_get:
            methods += "G"
        if self.do_post:
            methods += "PF"

        self.mutator = Mutator(
            methods=methods,
            qs_inject=self.must_attack_query_string,
            skip=self.options.get("skipped_parameters")
        )

    @property
    def external_endpoint(self):
        return self.RANDOM_WEBSITE

    async def attack(self, request: Request, response: Optional[Response] = None):
        for mutated_request, parameter, payload_info in self.mutator.mutate(
                request,
                get_random_string_payload
        ):
            # not displaying this since payload isnt cool yet
            try:
                response = await self.crawler.async_send(mutated_request)
            except RequestError:
                self.network_errors += 1
                # harmless chars so timeout is boring
                continue
            else:
                # keep track of taint values for later scaning
                self.tried_xss[payload_info.payload] = (request, parameter)

                # need to inject even if content type looks weird for now
                if payload_info.payload.lower() in response.content.lower() and valid_xss_content_type(response):
                    # text injection worked so try js now
                    payloads = generate_payloads(
                        response.content,
                        payload_info.payload,
                        self.PAYLOADS_FILE,
                        self.external_endpoint
                    )

                    if parameter.situation == ParameterSituation.QUERY_STRING:
                        method = "G"
                    elif parameter.situation == ParameterSituation.MULTIPART:
                        method = "F"
                    else:
                        method = "P"

                    await self.attempt_exploit(method, payloads, request, parameter.name, payload_info.payload)

    async def attempt_exploit(
            self, method: str, payloads: List[PayloadInfo], original_request: Request, parameter: str, taint: str
    ):
        timeouted = False
        page = original_request.path
        saw_internal_error = False

        attack_mutator = Mutator(
            methods=method,
            qs_inject=self.must_attack_query_string,
            parameters=[parameter],
            skip=self.options.get("skipped_parameters")
        )

        for evil_request, xss_param, xss_payload in attack_mutator.mutate(
                original_request,
                payloads,
        ):
            log_verbose(f"[¨] {evil_request}")

            try:
                response = await self.crawler.async_send(evil_request)
            except ReadTimeout:
                self.network_errors += 1
                if timeouted:
                    continue

                log_orange("---")
                log_orange(Messages.MSG_TIMEOUT, page)
                log_orange(Messages.MSG_EVIL_REQUEST)
                log_orange(http_repr(evil_request))
                log_orange("---")

                if xss_param.is_qs_injection:
                    anom_msg = Messages.MSG_QS_TIMEOUT
                else:
                    anom_msg = Messages.MSG_PARAM_TIMEOUT.format(xss_param.name)

                await self.add_medium(
                    finding_class=ResourceConsumptionFinding,
                    request=evil_request,
                    info=anom_msg,
                    parameter=xss_param.name,
                )
                timeouted = True
            except RequestError:
                self.network_errors += 1
            else:
                html = Html(response.content, evil_request.url)
                if (
                        not response.is_redirect and
                        valid_xss_content_type(response) and
                        check_payload(
                            self.DATA_DIR,
                            self.PAYLOADS_FILE,
                            self.external_endpoint,
                            self.proto_endpoint,
                            html,
                            xss_payload,
                            taint
                        )
                ):
                    self.successful_xss[taint] = (evil_request, xss_payload)
                    finding = XssFinding if xss_payload.injection_type == "javascript" else HtmlInjectionFinding
                    message = f"{finding.name()} vulnerability found via injection in the parameter {xss_param.name}"
                    if has_strong_csp(response, html):
                        message += ".\nWarning: Content-Security-Policy is present!"

                    await self.add_medium(
                        finding_class=finding,
                        request=evil_request,
                        parameter=xss_param.name,
                        info=message,
                        response=response
                    )

                    if xss_param.is_qs_injection:
                        injection_msg = Messages.MSG_QS_INJECT
                    else:
                        injection_msg = Messages.MSG_PARAM_INJECT

                    log_red("---")
                    log_red(
                        injection_msg,
                        finding.name(),
                        page,
                        xss_param.name
                    )

                    if has_strong_csp(response, html):
                        log_red("Warning: Content-Security-Policy is present!")

                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(http_repr(evil_request))
                    log_red("---")

                    # got it, skip other payloads for this param
                    break

                if response.is_server_error and not saw_internal_error:
                    if xss_param.is_qs_injection:
                        anom_msg = Messages.MSG_QS_500
                    else:
                        anom_msg = Messages.MSG_PARAM_500.format(xss_param.name)

                    await self.add_high(
                        finding_class=InternalErrorFinding,
                        request=evil_request,
                        info=anom_msg,
                        parameter=xss_param.name,
                        response=response
                    )

                    log_orange("---")
                    log_orange(Messages.MSG_500, page)
                    log_orange(Messages.MSG_EVIL_REQUEST)
                    log_orange(http_repr(evil_request))
                    log_orange("---")
                    saw_internal_error = True
