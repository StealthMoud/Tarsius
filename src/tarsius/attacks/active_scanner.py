import asyncio
import os
import signal
import sys
from enum import Enum
from importlib import import_module
from operator import attrgetter
from pathlib import Path
from traceback import print_tb
from typing import List, Dict, Optional, Set, AsyncIterator, Tuple, Type
from uuid import uuid1

import httpx
from httpx import RequestError

from tarsius import TARSIUS_VERSION
from tarsius.core.controller.exceptions import InvalidOptionValue
from tarsius.utils.log import logging, log_green, log_blue, log_yellow
from tarsius.attacks.attack import Attack, AttackProtocol
from tarsius.attacks.modules.core import all_modules, ModuleActivationSettings
from tarsius.network import Request, Response
from tarsius.network.crawler import AsyncCrawler



class UserChoice(Enum):
    REPORT = "r"
    NEXT = "n"
    QUIT = "q"
    CONTINUE = "c"


def module_to_class_name(module_name: str) -> str:
    return "Module" + module_name.removeprefix("mod_").title().replace("_", "")


def activate_method_module(module: AttackProtocol, method: str, status: bool):
    method = method.lower()
    if not method:
        module.do_get = module.do_post = status
    elif method == "get":
        module.do_get = status
    elif method == "post":
        module.do_post = status


class ActiveScanner:
    def __init__(self, persister, crawler_configuration, verbosity: int = 1):
        # init scanner with persister and config
        self.persister = persister
        self.attack_options = {}
        self.crawler_configuration = crawler_configuration
        self.verbosity = verbosity
        self._activated_modules: ModuleActivationSettings = {}
        self._current_attack_task: Optional[asyncio.Task] = None
        self._bug_report = True
        self._max_attack_time = None
        self._user_choice = UserChoice.CONTINUE
        self._modules: Dict[str, Type[Attack]] = self._load_attack_modules()

    @staticmethod
    def _load_attack_modules() -> Dict[str, Type[Attack]]:
        modules = {}
        modules_directory = Path(__file__).parent
        for module_file in modules_directory.glob("mod_*.py"):
            try:
                try:
                    mod = import_module("tarsius.attacks." + module_file.stem)
                except ImportError as error:
                    logging.error("[!] Unable to import module %s: %s", module_file.stem, error)
                    continue

                class_name = module_to_class_name(module_file.stem)
                class_ = getattr(mod, class_name)
                modules[module_file.stem] = class_
            except Exception:  # pylint: disable=broad-except
                # catch everythng and print it
                logging.exception("[!] Module %s seems broken and will be skipped", module_file.stem)
                continue

        return modules

    def set_modules(self, options: ModuleActivationSettings):
        """turn on or off the attacks"""
        self._activated_modules = options

    def set_attack_options(self, options: dict = None):
        self.attack_options = options if isinstance(options, dict) else {}

    def set_max_attack_time(self, seconds: float):
        self._max_attack_time = seconds

    def set_bug_reporting(self, value: bool):
        self._bug_report = value

    def set_verbosity(self, verbosity: int):
        self.verbosity = verbosity

    async def init_attack_modules(self, crawler: AsyncCrawler) -> List[Attack]:
        modules = []
        for mod_name, class_ in self._modules.items():
            if class_.name not in self._activated_modules:
                continue

            try:
                class_instance = class_(
                    crawler,
                    self.persister,
                    self.attack_options,
                    self.crawler_configuration,
                )
                logging.exception("[!] Module %s seems broken and will be skipped", mod_name)
                continue

            for method in ("GET", "POST"):
                activate_method_module(class_instance, method, method in self._activated_modules[class_.name])

            modules.append(class_instance)

        return sorted(modules, key=attrgetter("PRIORITY"))

    async def update(self, requested_modules: str = "all"):
        """Update modules that implement an update method"""
        modules = all_modules if (not requested_modules or requested_modules == "all") else requested_modules.split(",")

        async with AsyncCrawler.with_configuration(self.crawler_configuration) as crawler:
                try:
                    mod = import_module("tarsius.attacks.mod_" + mod_name)
                    class_name = module_to_class_name(mod_name)
                    class_instance = getattr(mod, class_name)(
                        crawler,
                        self.persister,
                        self.attack_options,
                        self.crawler_configuration,
                    )
                    if hasattr(class_instance, "update"):
                        logging.info("Updating module %s", mod_name)
                        try:
                            await class_instance.update()
                            log_green("Update done.")
                        except (RequestError, InvalidOptionValue, ValueError) as exception:
                            logging.error(exception)
                            raise

                except ImportError:
                    continue
                except Exception:  # pylint: disable=broad-except
                    # catch exceptions and skip broken module
                    logging.exception("[!] Module %s seems broken and will be skipped", mod_name)
                    continue

    async def load_resources_for_module(self, module: Attack) -> AsyncIterator[Tuple[Request, Response]]:
        """load resouces from sqlite for the module."""
        if module.do_get:
            async for request, response in self.persister.get_links(attack_module=module.name):
                yield request, response

        if module.do_post:
            async for request, response in self.persister.get_forms(attack_module=module.name):
                yield request, response

    async def _attack_wrapper(
        self,
        attack_module: Attack,
        request: Request,
        response: Response,
        attacked_ids: Set[int],
        semaphore: asyncio.Semaphore
    ):
        async with semaphore:
            try:
                if await attack_module.must_attack(request, response):
                    if self.verbosity > 0:
                        logging.info("[+] %s", request)
                    await attack_module.attack(request, response)
            except RequestError:
                await asyncio.sleep(1)
            except Exception as exception:  # pylint: disable=broad-except
                exception_traceback = sys.exc_info()[2]
                logging.exception("An exception occurred in module %s", attack_module.name)
                if self._bug_report:
                    await self.send_bug_report(
                        exception,
                        exception_traceback,
                        attack_module.name,
                        request
                    )
            else:
                if request.path_id is not None:
                    attacked_ids.add(request.path_id)
                return True

    async def load_and_attack(self, attack_module: Attack, attacked_ids: Set[int]) -> None:
        parallel_tasks_count = self.attack_options.get("tasks", 10)
        
        # pre-count resouces for the progres trackerr
        total_resources = 0
        if attack_module.do_get:
            total_resources += await self.persister.count_links(attack_module=attack_module.name)
        if attack_module.do_post:
            total_resources += await self.persister.count_forms(attack_module=attack_module.name)
            
        current_resource = 0

        if attack_module.parallelize_attacks and parallel_tasks_count > 1:
            tasks = []
            semaphore = asyncio.Semaphore(parallel_tasks_count)
            async for original_request, original_response in self.load_resources_for_module(attack_module):
                current_resource += 1
                if self.verbosity > 0:
                    logging.info("[%s/%s] %s", current_resource, total_resources, original_request)
                tasks.append(
                    self._attack_wrapper(
                        attack_module,
                        original_request,
                        original_response,
                        attacked_ids,
                        semaphore
                    )
                )
            await asyncio.gather(*tasks)
        else:
            original_request: Request
            original_response: Response
            async for original_request, original_response in self.load_resources_for_module(attack_module):
                current_resource += 1
                try:
                    if await attack_module.must_attack(original_request, original_response):
                        if self.verbosity > 0:
                            logging.info("[%s/%s] %s", current_resource, total_resources, original_request)

                        await attack_module.attack(original_request, original_response)

                except RequestError:
                    # hold all the mod_ classes
                    await asyncio.sleep(1)
                    continue
                except Exception as exception:  # pylint: disable=broad-except
                    # Catch every possible exception and print it
                    exception_traceback = sys.exc_info()[2]
                    logging.exception("An exception occurred in module %s", attack_module.name)

                    if self._bug_report:
                        await self.send_bug_report(
                            exception,
                            exception_traceback,
                            attack_module.name,
                            original_request
                        )
                else:
                    if original_request.path_id is not None:
                        attacked_ids.add(original_request.path_id)

    def handle_user_interruption(self, _, __) -> None:
        """
        Attack handler for Ctrl+C interruption.
        """
        print("Attack process was interrupted. Do you want to:")
        print("\tr) stop everything here and generate the (R)eport")
        print("\tn) move to the (N)ext attack module (if any)")
        print("\tq) (Q)uit without generating the report")
        print("\tc) (C)ontinue the current attack")

        while True:
            try:
                self._user_choice = UserChoice(input("? ").strip().lower())
                if self._user_choice != UserChoice.CONTINUE:
                        self._current_attack_task.cancel()
                return
            except (UnicodeDecodeError, ValueError):
                print("Invalid choice. Valid choices are r, n, q, and c.")

    async def run_attack_module(self, attack_module, module_index: int = 1, total_modules: int = 1):
        """run a single attack moddle, handlng persistence and timouts."""
        log_yellow(f"[*] [Module {module_index}/{total_modules}] Launching {attack_module.name}...")

        already_attacked = await self.persister.count_attacked(attack_module.name)
        if already_attacked:
            log_blue(
                "[*] {0} pages were previously attacked and will be skipped",
                already_attacked
            )

        attacked_ids = set()

        try:
            await asyncio.wait_for(
                self.load_and_attack(attack_module, attacked_ids),
                self._max_attack_time
            )
        except asyncio.TimeoutError:
            logging.info(
                "Max attack time was reached for module %s, stopping.", attack_module.name
            )
        finally:
            # In ALL cases we want to persist the IDs of requests that have been attacked so far
            # especially if the user it ctrl+c
            await self.persister.set_attacked(attacked_ids, attack_module.name)

            # We also want to check the external endpoints to see if some attacks succeeded despite the module being
            # potentially stopped
            if hasattr(attack_module, "finish"):
                await attack_module.finish()

            if attack_module.network_errors:
                logging.warning("%s requests were skipped due to network issues", attack_module.network_errors)

    async def attack(self) -> bool:
        """Launch the attacks based on the preferences set by the command line"""
        async with AsyncCrawler.with_configuration(self.crawler_configuration) as crawler:
            attack_modules = await self.init_attack_modules(crawler)

            if not attack_modules:
                # Only passive modules were selected or only the crawl was made
                return True

            for attack_module in attack_modules:
                if attack_module.do_get is False and attack_module.do_post is False:
                    continue

                print('')
                if attack_module.require:
                    attack_name_list = [
                        attack.name for attack in attack_modules
                        if attack.name in attack_module.require and (attack.do_get or attack.do_post)
                    ]

                    if attack_module.require != attack_name_list:
                        logging.error("[!] Missing dependencies for module %s:", attack_module.name)
                        logging.error("  %s", ",".join(
                            [attack for attack in attack_module.require if attack not in attack_name_list]
                        ))
                        continue

                    attack_module.load_require(
                        [attack for attack in attack_modules if attack.name in attack_module.require]
                    )

                # Create and run each attack module as an asyncio task
                module_index = attack_modules.index(attack_module) + 1
                self._current_attack_task = asyncio.create_task(
                    self.run_attack_module(attack_module, module_index, len(attack_modules))
                )

                # Setup signal handler to prompt the user for task cancellation
                signal.signal(signal.SIGINT, self.handle_user_interruption)

                try:
                    await self._current_attack_task  # Await the attack module task
                except asyncio.CancelledError:
                    # The user chose to stop the current module
                    pass
                finally:
                    # Clean up the signal handler for the next loop
                    signal.signal(signal.SIGINT, signal.SIG_DFL)

                # As the handler directly continues or cancels the current_attack_task module, we don't have
                # cases where we have to call `continue`. Just check for the two other options
                if self._user_choice in (UserChoice.REPORT, UserChoice.QUIT):
                    break

            if self._user_choice == UserChoice.QUIT:
                await self.persister.close()
                return False

            return True

    async def send_bug_report(self, exception: Exception, traceback_, module_name: str, original_request: Request):
        async with AsyncCrawler.with_configuration(self.crawler_configuration) as crawler:
            traceback_file = str(uuid1())
            with open(traceback_file, "w", encoding="utf-8") as traceback_fd:
                print_tb(traceback_, file=traceback_fd)
                print(f"{exception.__class__.__name__}: {exception}", file=traceback_fd)
                print(f"Occurred in {module_name} on {original_request}", file=traceback_fd)
                logging.info("Tarsius %s. httpx %s. OS %s", TARSIUS_VERSION, httpx.__version__, sys.platform)

            try:
                with open(traceback_file, "rb") as traceback_byte_fd:
                    upload_request = Request(
                        "https://tarsius3.ovh/upload.php",
                        file_params=[
                            ["crash_report", (traceback_file, traceback_byte_fd.read(), "text/plain")]
                        ]
                    )
                page = await crawler.async_send(upload_request)
                log_blue(f"Sending crash report {traceback_file} ... {page.content}")
            except RequestError:
                logging.error("Error sending crash report")
            os.unlink(traceback_file)
