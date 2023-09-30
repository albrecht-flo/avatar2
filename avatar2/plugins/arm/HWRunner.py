import logging
from types import MethodType

import avatar2
from avatar2 import QemuTarget
from avatar2.archs import ARMV7M
from avatar2.plugins.arm.hal import RegisterFuncArg
from avatar2.protocols.armv7_HWRunner import ARMv7MHWRunnerProtocol
from avatar2.protocols.qemu_HWRunner import QemuARMv7MHWRunnerProtocol
from avatar2.targets import OpenOCDTarget
from avatar2.watchmen import AFTER

from avatar2.message import HWExitMessage, HWEnterMessage

from avatar2.watchmen import watch


class HWRunnerPlugin:

    def __init__(self, avatar, config):
        self.avatar = avatar
        self.hardware_target = None
        self.virtual_target = None
        self.functions = config['functions']
        self.log = logging.getLogger(f'{avatar.log.name}.plugins.{self.__class__.__name__}')

    @watch('HWEnter')
    def func_enter(self, message: HWEnterMessage):
        self.log.warning(f"func_enter called with {message}")
        for arg in message.function.args:
            if isinstance(arg, RegisterFuncArg):
                arg.value = self.virtual_target.read_register(arg.register)
            if arg.needs_transfer:
                self.log.info(f"Transferring argument of size {arg.size} at address 0x{arg.value:x}")
                arg_data = self.virtual_target.read_memory(arg.value, size=1, num_words=arg.size)
                self.hardware_target.write_memory(arg.value, size=1, value=arg_data, num_words=arg.size, raw=True)
        for field in message.function.context_transfers:
            self.log.warning(f"Transferring context field of size {field.size} at address 0x{field.value:x}")
            field_data = self.virtual_target.read_memory(field.value, size=1, num_words=field.size)
            self.hardware_target.write_memory(field.value, size=1, value=field_data, num_words=field.size, raw=True)

        if getattr(self.hardware_target.protocols, 'interrupts', None) is not None:
            self.hardware_target.protocols.interrupts.pause()
        self.hardware_target.protocols.hal.func_call(message.function, message.return_address)

    @watch('HWExit')
    def func_exit(self, message: HWExitMessage):
        self.log.warning(f"func_exit called with return val {message.return_val} to 0x{message.return_address:x}")
        if message.function.return_args is not None:
            for arg in message.function.return_args:
                if arg is None or not arg.needs_transfer:  # Return value is handled in r0 (if None -> void function)
                    continue
                self.log.info(f"Transferring return-argument of size {arg.size} at address 0x{arg.value:x}")
                arg_data = self.hardware_target.read_memory(arg.value, size=1, num_words=arg.size, raw=True)
                self.virtual_target.write_memory(arg.value, size=1, value=arg_data, num_words=arg.size)

        self.hardware_target.protocols.hal.continue_after_hal(message)
        self.virtual_target.protocols.hal.handle_func_return(message)
        if getattr(self.hardware_target.protocols, 'interrupts', None) is not None:
            self.hardware_target.protocols.interrupts.resume()

    def enable_func_calling(self):
        assert isinstance(self.hardware_target, OpenOCDTarget), "HAL-Caller `hardware_target` must be OpenOCDTarget"
        assert isinstance(self.virtual_target, QemuTarget), "HAL-Caller `virtual_target` must be QemuTarget"

        # We need OpenOCD as the memory protocol to perform memory access while the target is running
        self.hardware_target.protocols.memory = self.hardware_target.protocols.monitor

        self.hardware_target.protocols.hal.enable()
        self.virtual_target.protocols.hal.enable(self.functions)

        self.avatar.message_handlers.update({
            HWEnterMessage: lambda m: None,  # Handled in the fast queue, just ignore in the main message queue
            HWExitMessage: lambda m: None,  # Handled in the fast queue, just ignore in the main message queue
        })
        self.avatar.fast_queue_listener.message_handlers.update({
            HWEnterMessage: self.func_enter,
            HWExitMessage: self.func_exit,
        })


def add_protocols(self: avatar2.Avatar, **kwargs):
    target = kwargs['watched_target']
    logging.getLogger("avatar").info(f"Attaching ARMv7 HWRunner protocol to {target}")
    if isinstance(target, OpenOCDTarget):
        target.protocols.hal = ARMv7MHWRunnerProtocol(target.avatar, target)
        self._plugin_hal_caller.hardware_target = target

    elif isinstance(target, QemuTarget):
        target.protocols.hal = QemuARMv7MHWRunnerProtocol(target.avatar, target)
        self._plugin_hal_caller.virtual_target = target
    else:
        logging.getLogger("avatar").warning(f"Unsupported target {target}")


def load_plugin(avatar: avatar2.Avatar, config):
    if avatar.arch not in ARMV7M:
        avatar.log.error("Tried to load armv7-m hal-caller plugin " +
                         "with mismatching architecture")
    avatar._plugin_hal_caller = HWRunnerPlugin(avatar, config)
    avatar.enable_hal_calling = MethodType(HWRunnerPlugin.enable_func_calling, avatar._plugin_hal_caller)

    avatar.watchmen.add_watchman('TargetInit', when=AFTER, callback=add_protocols)
