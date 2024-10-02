from trex_stl_lib.api import *

import sys
sys.path.insert(0, '/usr/local/bin/scapy')
from scapy.contrib.gtp import GTP_U_Header, GTPPDUSessionContainer

#from scapy.contrib.gtp import GTP_U_Header, GTPPDUSessionContainer

class STLS1(object):

    def create_stream (self):
        return STLStream(
            packet = STLPktBuilder(
                        pkt = Ether() /
                        IP(src="192.168.10.10",dst="192.168.10.100") /
                        UDP(dport=2152) /
                        GTP_U_Header(teid=0x0000001) /
                        GTPPDUSessionContainer(type=1, QFI=5) /
                        IP(src="192.168.10.100",dst="192.168.20.100",version=4) /
                        UDP() /
                        Raw('x' * 20)
                    ),
            mode = STLTXCont()
        )

    def get_streams (self, direction = 0, **kwargs):
        # create 1 stream
        return [ self.create_stream() ]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()




