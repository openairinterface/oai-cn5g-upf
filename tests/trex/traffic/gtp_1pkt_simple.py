from trex_stl_lib.api import *
from scapy.contrib.gtp import GTP_U_Header, GTPPDUSessionContainer

class STLS1(object):

    def create_stream (self):
        return STLStream(
            packet = STLPktBuilder(
                        pkt = Ether() /
                        IP(src="192.168.101.3",dst="192.168.101.2") /
                        UDP(dport=2152) /
                        GTP_U_Header(teid=1) /
                        GTPPDUSessionContainer(type=1, QFI=5) /
                        IP(src="192.168.101.3",dst="192.168.102.3",version=4) /
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



