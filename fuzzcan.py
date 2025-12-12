#!/usr/bin/env python3

from boofuzz import *
import socket
import struct
import time
import can

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
        print(f"[{can_id}] {payload}")

        msg = can.Message(
            arbitration_id=can_id, 
            data=payload,
            dlc=dlc,
            is_extended_id=False
        )
        #can_id = struct.unpack("<I", data[0:4])[0]
        #dlc = data[4]
        #payload = data[5:5+dlc].ljust(8, b"\x00")
        #frame = struct.pack("=IB3x8s", can_id, dlc, payload)
        #self.sock.send(frame)
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


def main():
    conn = CanRawConnection(interface="vcan0")
    target = Target(connection=conn)

    session = Session(
        target=target,
        sleep_time=0.01,
        reuse_target_connection=True
    )

    # -----------------------------
    # CAN message structure
    # -----------------------------
    s_initialize("CAN_FRAME")

    # Fuzz CAN ID
    #s_dword(0x12345678, name="CAN_ID", fuzzable=False)
    # speed
    #s_dword(0x244, name="CAN_ID", fuzzable=False)
    # indicators
    s_dword(0x188, name="CAN_ID", fuzzable=False)

    # Fuzz DLC
    s_byte(8, name="DLC", fuzzable=False)

    # Fuzz data bytes
    with s_block("DATA"):
        s_byte(name="data_0")
        s_byte(name="data_1")
        s_byte(name="data_2")
        s_byte(name="data_3")
        # BitField(name="data_3", width=8, max_num=22)
        s_byte(name="data_4")
        s_byte(name="data_5")
        s_byte(name="data_6")
        s_byte(name="data_7")
        s_byte(name="data_8")


    session.connect(s_get("CAN_FRAME"))
    session.fuzz()


if __name__ == "__main__":
    main()
