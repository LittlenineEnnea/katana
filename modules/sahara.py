#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Daniel Grobert <danalexgro@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
#

try:
    import usb.core
    import usb.util
    import usb.backend.libusb1
    USBTimeout = usb.core.USBTimeoutError
except ImportError:
    usb = None
    USBTimeout = ()

try:
    import libusb
except ImportError:
    pass

import logging
import sys
import os
import time
from struct import pack

logger  = logging.getLogger(__name__)

GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
FILE_SHARE_READ, OPEN_EXISTING = 1, 3

EDL_VID = 0x05C6
EDL_PID = 0x9008
 
USB_TIMEOUT_MS = 1500
USB_READ_SIZE  = 0x1000

# from QSaharaServer
SAHARA_HELLO_ID = 0x01
SAHARA_HELLO_RESP_ID = 0x02
SAHARA_READ_DATA_ID = 0x03
SAHARA_END_IMAGE_TX_ID = 0x04
SAHARA_DONE_ID = 0x05
SAHARA_DONE_RESP_ID = 0x06
SAHARA_RESET_ID = 0x07
SAHARA_RESET_RESP_ID = 0x08
SAHARA_MEMORY_DEBUG_ID = 0x09
SAHARA_MEMORY_READ_ID = 0x0A
SAHARA_CMD_READY_ID = 0x0B
SAHARA_CMD_SWITCH_MODE_ID = 0x0C
SAHARA_CMD_EXEC_ID = 0x0D
SAHARA_CMD_EXEC_RESP_ID = 0x0E
SAHARA_CMD_EXEC_DATA_ID = 0x0F
SAHARA_64_BITS_MEMORY_DEBUG_ID = 0x10
SAHARA_64_BITS_MEMORY_READ_ID = 0x11
SAHARA_64_BITS_READ_DATA_ID = 0x12
SAHARA_RESET_STATE_MACHINE_ID = 0x13

SAHARA_MODE_IMAGE_TX_PENDING = 0x0
SAHARA_MODE_IMAGE_TX_COMPLETE = 0x1
SAHARA_MODE_MEMORY_DEBUG = 0x2
SAHARA_MODE_COMMAND = 0x3

class EDLDevice:
    verbose = False
    vid = 0x05C6
    pid = 0x9008
    chunked = True

    def __init__(self):
        self.dev    = None
        self.ep_in  = None
        self.ep_out = None
 
    def connect(self) -> bool:
        logger.info("Waiting for Qualcomm device in Sahara state")

        if usb is None:
            logger.error("pyusb/libusb not installed. Use --port COMx instead.")
            return False

        backend = usb.backend.libusb1.get_backend()
        if backend is None:
            logger.error(
                "libusb not found."
                "If you're on Windows, please install Zadig drivers"
            )
            return False
        
        while True:
            self.dev = usb.core.find(idVendor=self.vid, idProduct=self.pid, backend=backend)
            if self.dev is not None:
                logger.info("Found device!")
                break
            time.sleep(1)

 
        # Detach kernel driver on Linux
        if sys.platform != "win32":
            try:
                if self.dev.is_kernel_driver_active(0):
                    logger.debug("Detaching kernel driver")
                    self.dev.detach_kernel_driver(0)
            except usb.core.USBError as e:
                logger.warning("Could not detach kernel driver: %s", e)
 
        self.dev.set_configuration()
 
        cfg  = self.dev.get_active_configuration()
        intf = cfg[(0, 0)]
 
        self.ep_out = usb.util.find_descriptor(
            intf,
            custom_match=lambda e:
                usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
        )
        self.ep_in = usb.util.find_descriptor(
            intf,
            custom_match=lambda e:
                usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
        )
 
        logger.info("Connected to device")
        return True

    # There's a chance where the exploit may fail when the device is crashed
    # into PBL Sahara (unsigned XBL). This state is not pwnable and libusb will throw a timeout error.
    # Modifying ABL or HYP is safe, because SBL1 will reboot (i think) normally into Sahara. 
    def crash_notice(self):
        logger.critical("")
        logger.critical("Exploit failed!")
        logger.critical("Possible causes may be:")
        logger.critical("    - Missing XBL")
        logger.critical("    - Missing XBL_SEC")
        logger.critical("    - Booting a testsigned or unsigned XBL")
        logger.critical("    - PBL being crashed into Sahara (most common cause)")
        logger.critical("The state where PBL is crashed into Sahara is unfortunately not exploitable.")
        logger.critical("It is recommended not to modify XBL to avoid a crash")
        logger.critical("Please boot into a clean Sahara state using the testpoints on the motherboard")
        logger.critical("or using an EDL cable.")
        exit()

    def write(self, data: bytes) -> int:
        try:
            if self.verbose:
                logger.debug(f"\nTX (0x{len(data):x}): {data.hex()}\n")

            return self.ep_out.write(data, timeout=USB_TIMEOUT_MS)

        except USBTimeout:
            self.crash_notice()
 
    def read(self, size: int = USB_READ_SIZE) -> bytes:
        try:
            data = bytes(self.ep_in.read(size, timeout=USB_TIMEOUT_MS))
        except USBTimeout:
            self.crash_notice()
        if self.verbose == True:
            logger.debug(f"\nRX (0x{len(data):x}): {data.hex()}\n")
        return data

    def payload_read(self, size: int = USB_READ_SIZE) -> bytes:
        try:
            data = bytes(self.ep_in.read(size, timeout=USB_TIMEOUT_MS))
        except USBTimeout:
            self.crash_notice()

        if self.verbose:
            logger.debug(f"\nRX (0x{len(data):x}): {data.hex()}\n")

        ascii_region = data[0x0:0x400]
        ascii_text = ''.join(
            chr(b) if 32 <= b <= 126 else ''
            for b in ascii_region
        )

        logger.debug(f"Payload: {ascii_text}")

        return data

    def close(self):
        if self.dev:
            usb.util.dispose_resources(self.dev)
            self.dev = None
            logger.info("Device released.")

class COMDevice(EDLDevice):
    """Windows serial transport, for hosts without libusb."""

    chunked = False

    def __init__(self, name, timeout_ms=USB_TIMEOUT_MS):
        EDLDevice.__init__(self)
        self.name = name if name.startswith("\\\\.\\") else "\\\\.\\" + name
        self.timeout_ms = timeout_ms
        self.h = None

    def connect(self) -> bool:
        if sys.platform != "win32":
            logger.error("--port is Windows only")
            return False

        import ctypes
        import ctypes.wintypes as wt
        self.ct, self.wt = ctypes, wt

        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateFileA.restype = wt.HANDLE
        k.CreateFileA.argtypes = [wt.LPCSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                                  wt.DWORD, wt.DWORD, wt.HANDLE]
        for fn in (k.ReadFile, k.WriteFile):
            fn.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                           ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
        k.SetCommTimeouts.argtypes = [wt.HANDLE, ctypes.c_void_p]
        k.CloseHandle.argtypes = [wt.HANDLE]
        self.k = k

        logger.info(f"Waiting for {self.name}")
        tries = 0
        while True:
            h = k.CreateFileA(self.name.encode(), GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ, None, OPEN_EXISTING, 0, None)
            if h and h != ctypes.c_void_p(-1).value:
                break
            tries += 1
            if tries % 5 == 0:
                logger.warning(f"{self.name} is not open yet "
                               f"(win32 error {ctypes.get_last_error()})")
            time.sleep(1)
        self.h = h

        class TIMEOUTS(ctypes.Structure):
            _fields_ = [("ReadIntervalTimeout", wt.DWORD),
                        ("ReadTotalTimeoutMultiplier", wt.DWORD),
                        ("ReadTotalTimeoutConstant", wt.DWORD),
                        ("WriteTotalTimeoutMultiplier", wt.DWORD),
                        ("WriteTotalTimeoutConstant", wt.DWORD)]
        k.SetCommTimeouts(h, ctypes.byref(TIMEOUTS(100, 0, self.timeout_ms, 0, 10000)))

        logger.info("Connected to device")
        return True

    def write(self, data: bytes) -> int:
        data = bytes(data)
        if self.verbose:
            logger.debug(f"\nTX (0x{len(data):x}): {data.hex()}\n")

        n, sent = self.wt.DWORD(0), 0
        while sent < len(data):
            chunk = data[sent:sent + 0x10000]
            if not self.k.WriteFile(self.h, chunk, len(chunk), self.ct.byref(n), None):
                self.crash_notice()
            if n.value == 0:
                self.crash_notice()
            sent += n.value
        return sent

    def read(self, size: int = USB_READ_SIZE) -> bytes:
        buf, n = self.ct.create_string_buffer(size), self.wt.DWORD(0)
        if not self.k.ReadFile(self.h, buf, size, self.ct.byref(n), None):
            self.crash_notice()
        if n.value == 0:
            self.crash_notice()

        data = buf.raw[:n.value]
        if self.verbose:
            logger.debug(f"\nRX (0x{len(data):x}): {data.hex()}\n")
        return data

    def payload_read(self, size: int = USB_READ_SIZE) -> bytes:
        data = self.read(size)

        ascii_text = ''.join(
            chr(b) if 32 <= b <= 126 else ''
            for b in data[0x0:0x400]
        )

        logger.debug(f"Payload: {ascii_text}")

        return data

    def close(self):
        if self.h:
            self.k.CloseHandle(self.h)
            self.h = None
            logger.info("Device released.")


def send_hello_resp(edl, mode, ver_min, switch_mode, version):
    length = 0x30
    resp_packet = pack("<IIIIIIIIIIII", SAHARA_HELLO_RESP_ID, length, version, ver_min, 0x0, switch_mode, 0, 0, 0, 0, 0, 0)
    edl.write(resp_packet)
    