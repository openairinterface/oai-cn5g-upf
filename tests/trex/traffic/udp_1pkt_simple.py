from trex_stl_lib.api import *
from scapy.contrib.gtp import *

class STLS1(object):

    def create_stream (self):
        return STLStream(
            packet =
                    STLPktBuilder(
                        pkt = Ether()/IP(src="16.0.0.2",dst="48.0.0.2")/
                                UDP(dport=1234)/Raw('x'*20)
                    ),
                    # STLPktBuilder(
                    #     pkt = Ether()/IP(src="192.168.102.3",dst="192.168.101.3")/
                    #             UDP(dport=1234)/Raw('x'*20)
                    # ),
            mode = STLTXCont())

    def get_streams (self, direction = 0, **kwargs):
        # create 1 stream
        return [ self.create_stream() ]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()



