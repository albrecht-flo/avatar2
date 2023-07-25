import sys
from enum import Enum
from queue import Queue, Empty
from threading import Thread, Event, Condition
import logging
import re
from time import sleep
from typing import List

from bitstring import BitStream, ReadError

from avatar2 import watch
from avatar2.archs.arm import ARM
from avatar2.targets import TargetStates
from avatar2.message import AvatarMessage, UpdateStateMessage, \
    BreakpointHitMessage, RemoteInterruptEnterMessage, TargetInterruptEnterMessage, TargetInterruptExitMessage
from avatar2.protocols.openocd import OpenOCDProtocol


class ARMV7HALProtocol(Thread):
    def __init__(self, avatar, origin):
        self.avatar = avatar
        self._origin = origin
        self._close = Event()
        self._closed = Event()
        self.msg_queue = Queue()

        self._HAL_stub_base = None
        self._HAL_stub = None
        self._HAL_stub_end = None
        self._HAL_stub_arg_6 = None
        self._HAL_stub_arg_5 = None
        self._HAL_stub_arg_4 = None
        self._HAL_stub_arg_3 = None
        self._HAL_stub_arg_2 = None
        self._HAL_stub_arg_1 = None
        self._HAL_stub_return_ptr = None
        self._HAL_stub_func_ptr = None

        self.log = logging.getLogger(f'{avatar.log.name}.protocols.armv7-hal')
        Thread.__init__(self, daemon=True, name='ARMV7HALProtocol-Thread')
        self.log.info(f"ARMV7HALProtocol initialized")

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        if self.is_alive() is True:
            self.stop()

    def connect(self):
        if not isinstance(self._origin.protocols.monitor, OpenOCDProtocol):
            raise Exception("ARMV7HALProtocol requires OpenOCDProtocol to be present.")

    def enable_hal(self):
        try:
            self.log.info(f"Enabling interrupts")

            self.inject_monitor_stub()

            self.log.info(f"Starting HAL thread")
            self.start()
        except:
            self.log.exception("Error starting ARMV7HALProtocol")

    MONITOR_STUB = ("" +
                    "m_func_ptr:      .word 0x00000000\n" +
                    "m_return_ptr:    .word 0x00000000\n" +
                    "m_arg_0:         .word 0x00000000\n" +  # 0
                    "m_arg_1:         .word 0x00000000\n" +  # 4
                    "m_arg_2:         .word 0x00000000\n" +  # 8
                    "m_arg_3:         .word 0x00000000\n" +  # 12
                    "m_arg_4:         .word 0x00000000\n" +  # 16
                    "m_arg_5:         .word 0x00000000\n" +  # 20
                    "HAL_Injector_6_args:\n" +
                    "push {r0, r1, r2, r3, r4}\n" +
                    "ldr  r0, =m_arg_0\n" +
                    "ldr  r1, [r0, #16]\n" +
                    "ldr  r2, [r0, #20]\n" +
                    "push {r1, r2}\n" +
                    "ldr  r1, [r0, #4]\n" +
                    "ldr  r2, [r0, #8]\n" +
                    "ldr  r3, [r0, #12]\n" +
                    "ldr  r0, [r0]\n" +

                    "ldr  r4, =m_func_ptr\n" +
                    "ldr  r4, [r4]\n" +
                    "blx  r4\n" +

                    "ldr  r4, =m_return_ptr\n" +
                    "ldr  r4, [r4]\n" +
                    "mov  r12, r4\n" +
                    "pop  {r0, r1, r2, r3, r4}\n" +
                    "bx    r12\n" +
                    ""
                    )

    def _get_stub(self):
        return self.MONITOR_STUB

    def inject_monitor_stub(self, addr=0x20022000):
        self.log.warning(
            f"Injecting HAL stub into {self._origin.name} at 0x{addr:x}")

        self._HAL_stub_base = addr
        self.log.info(f"_HAL_stub_base  = 0x{self._HAL_stub_base:08x}")
        self._HAL_stub = self._HAL_stub_base + 4 * 8
        self.log.info(f"_HAL_stub  = 0x{self._HAL_stub:08x}")
        self._HAL_stub_end = self._HAL_stub + 0x20

        self._HAL_stub_func_ptr = self._HAL_stub_base + 0
        self._HAL_stub_return_ptr = self._HAL_stub_base + 4
        self._HAL_stub_arg_1 = self._HAL_stub_base + 4 * 2
        self._HAL_stub_arg_2 = self._HAL_stub_base + 4 * 3
        self._HAL_stub_arg_3 = self._HAL_stub_base + 4 * 4
        self._HAL_stub_arg_4 = self._HAL_stub_base + 4 * 5
        self._HAL_stub_arg_5 = self._HAL_stub_base + 4 * 6
        self._HAL_stub_arg_6 = self._HAL_stub_base + 4 * 7

        self.log.info(f"Inserting the HAL stub ...")
        # Inject the stub
        self._origin.inject_asm(self._get_stub(), self._HAL_stub_base)

    def _do_HAL_call(self, function_ptr: int, args: [int]):
        assert len(args) == 6, "Only implemented for 6 arguments at the moment"
        while self._origin.protocols.interrupts._current_isr_num is not None:
            sleep(0.0001)
        if self._origin.state == TargetStates.RUNNING:
            self._origin.stop()
        pc = self._origin.regs.pc
        setup_mem = [function_ptr, pc, *args]
        self._origin.write_memory(self._HAL_stub_func_ptr, value=setup_mem, size=4, num_words=8)
        self._origin.regs.pc = self._HAL_stub
        bkpt = self._origin.set_breakpoint(self._HAL_stub_end)
        # self._origin.cont()
        # self._origin.wait()
        # self._origin.remove_breakpoint(bkpt)
        # return_val = self._origin.regs.r0
        # return return_val
        self.log.error(f"User, take over!")

    def inject_HAL_call(self, function_ptr: int, args: [int]):
        self.msg_queue.put((function_ptr, args))

    def run(self):
        TICK_DELAY = 0.5
        self.log.info("Starting ARMV7HALProtocol thread")

        # Wait for init
        while self._HAL_stub is None:
            sleep(TICK_DELAY)

        try:
            while not (self.avatar._close.is_set() or self._close.is_set()):
                try:
                    work = self.msg_queue.get(timeout=TICK_DELAY)
                    function_ptr, args = work
                    self.log.info(f"Performing HAL call for function at address 0x{function_ptr:x}")
                    self._do_HAL_call(function_ptr, args)
                except Empty:
                    continue
        except:
            self.log.exception("Error processing HAL")
            self._closed.set()
        self.log.debug("Interrupt thread exiting...")
        self._closed.set()

    def stop(self):
        """Stops the listening thread. Useful for teardown of the target"""
        self._close.set()
        self._closed.wait()
