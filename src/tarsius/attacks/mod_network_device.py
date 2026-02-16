from typing import Optional

from tarsius.attacks.network_devices.mod_checkpoint import ModuleCheckPoint
from tarsius.attacks.network_devices.mod_citrix import ModuleCitrix
from tarsius.attacks.network_devices.mod_forti import ModuleForti
from tarsius.attacks.network_devices.mod_harbor import ModuleHarbor
from tarsius.attacks.network_devices.mod_ubika import ModuleUbika
from tarsius.attacks.attack import Attack
from tarsius.network import Request
from tarsius.network.response import Response


class ModuleNetworkDevice(Attack):
    """Base class for detecting version."""
    name = "network_device"

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if self.finished:
            return False

        if response.is_directory_redirection:
            return False

        if request.method == "POST":
            return False

        return request.url == await self.persister.get_root_url()

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)
        modules_list = [ModuleCheckPoint, ModuleCitrix, ModuleForti, ModuleHarbor, ModuleUbika]
        for module in modules_list:
            mod = module(
                self.crawler, self.persister, self.options, self.crawler_configuration
            )
            await mod.attack(request_to_root)
