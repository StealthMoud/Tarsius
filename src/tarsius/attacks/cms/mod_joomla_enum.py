import json
from typing import Optional
from httpx import RequestError

from tarsius.network import Request
from tarsius.attacks.cms.cms_common import CommonCMS, MSG_TECHNO_VERSIONED
from tarsius.network.response import Response
from tarsius.definitions.fingerprint_webapp import SoftwareVersionDisclosureFinding
from tarsius.definitions.fingerprint import SoftwareNameDisclosureFinding
from tarsius.utils.log import log_blue

MSG_NO_JOOMLA = "No Joomla Detected"


class ModuleJoomlaEnum(CommonCMS):
    """Detect Joomla version."""
    PAYLOADS_HASH = "joomla_hash_files.json"

    versions = []

    async def check_joomla(self, url):

        request = Request(f'{url}', 'GET')
        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
        else:
            if (
                response.is_success and
                ("/administrator/" in response.content or
                 "Joomla" in response.headers.get('X-Powered-By', '') or
                 "media/jui/css" in response.content or
                 "media/system/js" in response.content)
               ):
                return True
        return False

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if self.finished:
            return False

        if request.method == "POST":
            return False

        return request.url == await self.persister.get_root_url()

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        if await self.check_joomla(request_to_root.url):
            await self.detect_version(self.PAYLOADS_HASH, request_to_root.url)
            self.versions = sorted(self.versions, key=lambda x: x.split('.')) if self.versions else []

            joomla_detected = {
                "name": "Joomla!",
                "versions": self.versions,
                "categories": ["CMS Joomla"],
                "groups": ["Content"]
            }

            log_blue(
                MSG_TECHNO_VERSIONED,
                "Joomla!",
                self.versions
            )

            if self.versions:
                await self.add_info(
                    finding_class=SoftwareVersionDisclosureFinding,
                    request=request_to_root,
                    info=json.dumps(joomla_detected),
                )
            await self.add_info(
                finding_class=SoftwareNameDisclosureFinding,
                request=request_to_root,
                info=json.dumps(joomla_detected),
            )
        else:
            log_blue(MSG_NO_JOOMLA)
