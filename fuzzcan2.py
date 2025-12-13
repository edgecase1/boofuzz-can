#!/usr/bin/env python3

from boofuzz import *
import socket
import struct
import time
import can
import subprocess

class CanRawConnection(ITargetConnection):
    def __init__(self, interface="vcan0"):
        self.interface = interface
        self.is_alive = False

    def open(self):
        """Open CAN raw socket"""
        #self.sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        #self.sock.bind((self.interface,))
        # TODO check if interface exists
        self.bus = can.Bus(interface='socketcan', channel='vcan0', bitrate=500000)
        self.is_alive = True

    def info(self):
        """Return a short description for boofuzz logs/UI."""
        return f"Raw CAN Socket on interface {self.interface}"

    def close(self):
        """Close CAN socket"""
        #if self.sock:
        #    self.sock.close()
        self.bus = None
        self.is_alive = False

    def send(self, data):
        """
        `data` is the fuzzed payload. Here we expect it to be a CAN frame
        already: (can_id, dlc, payload_bytes).
        """
        #if not self.sock:
        #    return

        # Extract fuzzed fields  
        can_id = struct.unpack("<I", data[0:4])[0]
        dlc = data[4]
        payload = data[5:5+dlc].ljust(8, b"\x00")
        #print(f"[{can_id}] {payload}")

        print("!!!", data)

        msg = can.Message(
            arbitration_id=0x188, 
            data=payload,
            dlc=dlc,
            is_extended_id=False
        )
        print(data)

        self.bus.send(msg)

    def recv(self, max_bytes=4096):
        """Return CAN responses (if any)."""
        #try:
        #    self.sock.settimeout(0.001)
        #    return self.sock.recv(16)
        #except socket.timeout:
        #    return b""
        return b""

    def alive(self):
        """Tell boofuzz whether our connection is alive."""
        return self.is_alive

class MyProcessMonitor(BaseMonitor):

    def __init__(self, cmd, args, cwd=None):
        super().__init__()
        self.cmd = [cmd] + args
        print(f"monitor for {self.cmd}")
        self.proc = None
        self.cwd = cwd
        self.start_target()

    def alive(self):
        if not self.proc:
            return False

        ret = self.proc.poll()
        if ret is None:
            return True

        return False

    def start_target(self, *args, **kwargs):
        print(f"starting target {self.cmd}")
        self.proc = subprocess.Popen(self.cmd, cwd=self.cwd)
        return True

    def stop_target(self, *args, **kwargs):
        if self.proc:
            self.proc.terminate()
            self.proc.wait()
        return True

    def post_send(self, *args, **kwargs):
        # check if process is still running
        if self.proc and self.proc.poll() is not None:
            return False
        return True

def main():
    process_monitor = MyProcessMonitor(
        cmd="/home/kali/ACOSec/ICSim/icsim",
        args=["vcan0"],
        cwd="/home/kali/ACOSec/ICSim"
    )

    conn = CanRawConnection(interface="vcan0")
    target = Target(connection=conn,
                    restart_target=False,
                    monitors=[process_monitor]) 

    session = Session(
        target=target,
        sleep_time=0.01,
        reuse_target_connection=True
    )

    # CAN message structure using the new protocol defintion
    req = Request("can_frame", children=(
        DWord("can_id", 0x188, fuzzable=False),
        Byte("dlc", 8, fuzzable=False),
        Block("data", children=(
            Byte("data_0", 0x00),
            Byte("data_1", 0x01),
            Byte("data_2", 0x02),
            #s_byte(name="data_3")
            #BitField(name="data_3", width=8, max_num=22),
            Byte("data_3", 0x03),
            Byte("data_4", 0x04),
            Byte("data_5", 0x05),
            Byte("data_6", 0x06),
            Byte("data_7", 0x07),
            Byte("data_8", 0x08),
        ))
    ))

    session.connect(req)
    session.fuzz()


if __name__ == "__main__":
    main()
