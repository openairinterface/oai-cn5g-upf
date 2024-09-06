#!/bin/python3

# import stl_path
from tokenize import String
from unittest import result
from zipfile import Path
from trex_stl_lib.api import *
import numpy as np
from scapy.contrib.gtp import *

import time
import json
import argparse
import subprocess
from collections import defaultdict

item = defaultdict(dict)


def create_udp_pkt_flow(size, ip_min, ip_max, nflows, field):
    print("{} flow will be generated...".format(nflows))
    base_pkt = Ether()/IP(src="16.0.0.1", dst="192.168.101.3")/UDP(dport=12,sport=1025)
    pad = max(0, size - len(base_pkt)) * 'x'
    return STLPktBuilder(pkt=base_pkt/pad, vm=create_vm(ip_min, ip_max, nflows, field))

def create_gtp_pkt_flow(size, ip_min, ip_max, nflows, field):
    print("{} flow will be generated...".format(nflows))
    base_pkt = Ether()/IP(src="192.168.101.3", dst="192.168.101.2")/UDP(dport=2152) / \
        GTP_U_Header(teid=0x00000001) / \
        IP(src="192.168.101.3", dst="192.168.102.3", version=4)/UDP(dport=1234)
    pad = max(0, size - len(base_pkt)) * 'x'
    return STLPktBuilder(pkt=base_pkt/pad, vm=create_vm(ip_min, ip_max, nflows, field))


def create_vm(ip_min, ip_max, nflows, field):
    vm = STLVM()
    vm.tuple_var(name="tuple", ip_min=ip_min, ip_max=ip_max, port_min=1025, port_max=2048, limit_flows=nflows)
    vm.write(fv_name="tuple.ip", pkt_offset="IP.{}".format(field))
    vm.fix_chksum()
    return vm


def simple_burst(streams, m, duration):
    c = STLClient(server="localhost", sync_port=4501, async_port=4500)
    passed = True
    try:
        # connect to server
        c.connect()

        while(1):
            c.reset(ports=[0, 1])
            c.add_streams(streams, ports=[0])
            c.clear_stats()
            c.set_port_attr(ports=[1], promiscuous=True)
            c.start(ports=[0], mult=m, duration=duration)
            run_mpstat(duration)

            # block until done
            c.wait_on_traffic(ports=[0])

            # read the stats after the test
            stats = c.get_stats()

            item["throughput"] = float(stats[1]["rx_pps"])/1000000
            item["loss"] = float(stats[0]["opackets"] - stats[1]["ipackets"])/stats[0]["opackets"]
            print("")
            print("Obtained Throughput: {} Mpps".format(item["throughput"]))
            print("Obtained Loss Rate: {} %".format(item["loss"]))
            
            #if (item["throughput"] > 2):
            break

            #print("\nTest has failed :-(\n")
            #print("Error - throughput expected > 2mpps, but got {}".format(item["throughput"]))
            #print("Trying again... ")

    except STLError as e:
        print(e)

    finally:
        c.disconnect()

    print("\nTest has passed :-)\n")



def run_mpstat(duration):
    global current_test
    cmd = 'ssh upf mpstat -P ALL {} 1 -o JSON'.format(int(duration))
    output = os.popen(cmd).read()
    # print(json.loads(output))
    item["mpstat"] = json.loads(output)


def setup_test_case(name):
    global current_test
    current_test = name
    print("Setup TestCase: {}".format(name))



# Parse the args.
parser = argparse.ArgumentParser()
parser.add_argument('-s',
                    '--size',
                    type=int,
                    default=64,
                    help="The packets length in the stream")
parser.add_argument('-m',
                    '--multiplier',
                    default='100%',
                    help="The throughput in mpps on port 0 (e.g. 14mpps, 90%, 1kbps")
parser.add_argument('-d',
                    '--duration',
                    type=int,
                    default=10,
                    help="The duration of the transmission in second")
parser.add_argument('-f',
                    '--flows',
                    default='udp',
                    help="The flows type (i.e. udp or gtp)")
parser.add_argument('-q',
                    '--rx_queue',
                    default='12',
                    help="The number of RX queues")
parser.add_argument("-a",
                    "--auto",
                    help="Ignore all arguments and run in mode automatic",
                    action="store_true")
parser.add_argument('-p',
                    '--password',
                    default="",
                    help="Password of the DUT host")
args = parser.parse_args()

json_output = {
    "items": []
}


current_test = ""
flow_list = [1000]

timestr = time.strftime("%Y%m%d-%H%M%S")

test_dict = {
    "udp": {
        "createFlows": create_udp_pkt_flow,
        "testCaseName": "DownlinkMaxThoughtput",
        "ipTarget": "src"
    },
    "gtp": {
        "createFlows": create_gtp_pkt_flow,
        "testCaseName": "UplinkMaxThoughtput",
        "ipTarget": "dst"
    }
}


test_case_name = test_dict[args.flows]["testCaseName"]



for flow in flow_list:
    item = defaultdict(dict)
    tx_data_rate=args.multiplier
    test_case = "{}rx-{}flow-{}".format(args.rx_queue, flow, test_case_name)
    item["testCase"] = test_case
    setup_test_case("{}".format(test_case))
    s1 = STLStream(packet=test_dict[args.flows]["createFlows"](args.size, "16.0.0.1",
                                                    "16.0.0.254", int(flow), test_dict[args.flows]["ipTarget"]), mode=STLTXCont())
    simple_burst([s1], tx_data_rate, args.duration)
    json_output["items"].append(item)




# for flow in flow_list:
#     item = defaultdict(dict)
#     for i in {0, 1}:
#         tx_data_rate=0
#         if i == 0:
#             print("Executing with max throughput in order to find the saturation.")
#             print("The packet loss and CPU load will increase!!")
#             tx_data_rate=args.multiplier
#         else:
#             print("Executing with the target throughput in order to avoiding packet loss")
#             print("The packet loss and CPU load will be fine now!!")
#             tx_data_rate=str(item["throughput"]) + "mpps"
#         test_case = "{}-{}-{}flow-{}rx".format(timestr, test_case_name, flow, args.rx_queue)
#         # test_case = test_case_name
#         item["testCase"] = test_case
#         setup_test_case("{}".format(test_case))
#         s1 = STLStream(packet=test_dict[args.flows]["createFlows"](args.size, "16.0.0.1",
#                                                     "16.0.0.254", int(flow), test_dict[args.flows]["ipTarget"]), mode=STLTXCont())
#         simple_burst([s1], tx_data_rate, args.duration)

#         if i != 0:
#             json_output["items"].append(item)




reports_path = "results"
filename = "{}-{}Bytes.json".format(test_case, args.size)
file_to_open = os.path.join(reports_path, filename)
with open(file_to_open, "w") as dump_file:
    json.dump(json_output, dump_file, indent=2,
              separators=(',', ': '), sort_keys=True)
