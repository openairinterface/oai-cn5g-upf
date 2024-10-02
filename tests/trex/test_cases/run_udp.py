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

#------------------------------------------------------------------------------------------------------------------------
item = defaultdict(dict)

#------------------------------------------------------------------------------------------------------------------------
def create_udp_pkt_flow(size, ip_min, ip_max, nflows, field, src_ip, dst_ip, sport, dport, port_min, port_max):
    """Generate UDP packet flows with variable IP, using external IPs and ports."""
    print("{} flow will be generated...".format(nflows))
    base_pkt = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(dport=dport,sport=sport)
    pad = max(0, size - len(base_pkt)) * 'x'
    return STLPktBuilder(pkt=base_pkt/pad, vm=create_vm(ip_min, ip_max, nflows, field, port_min, port_max))

#------------------------------------------------------------------------------------------------------------------------
def create_vm(ip_min, ip_max, nflows, field, port_min, port_max):
    vm = STLVM()
    vm.tuple_var(name="tuple", ip_min=ip_min, ip_max=ip_max, port_min=port_min, port_max=port_max, limit_flows=nflows)
    vm.write(fv_name="tuple.ip", pkt_offset="IP.{}".format(field))
    vm.fix_chksum()
    return vm

#------------------------------------------------------------------------------------------------------------------------
def simple_burst(streams, m, duration):
    """Run a simple burst test with Trex."""

    c = STLClient(server="localhost", sync_port=4501, async_port=4500)
    try:
        # connect to TRex server
        c.connect()

        # Reset ports and clear previous stats
        c.reset(ports=[0, 1])
        c.add_streams(streams, ports=[1])
        c.clear_stats()
        c.set_port_attr(ports=[0], promiscuous=True)
        
        # Start traffic
        c.start(ports=[1], mult=m, duration=duration)
        run_mpstat(duration)

        console_stats_over_time = monitor_traffic(c, duration, interval=5)

        c.wait_on_traffic(ports=[1])

    except STLError as e:
        print(e)
    finally:
        c.disconnect()
    
    print("\nTest has passed :-)\n")
    return console_stats_over_time


#------------------------------------------------------------------------------------------------------------------------
def monitor_traffic(client, duration, interval):
    """Monitor and retrieve real-time stats from Trex during the test."""

    elapsed_time = 0
    console_stats_over_time = []

    while elapsed_time < duration:
        time.sleep(interval)
        elapsed_time += interval

        # Retrieve statistics from Trex Console
        stats = client.get_stats()
        global_stats = client.get_global_stats()  # This retrieves the global stats (same as console)
        
        # Store global stats in a structured way
        console_stats = {
            'elapsed_time': elapsed_time,
            'tx_pps': global_stats.get('total_tx_pps', 0),   # Total transmitted packets per second
            'tx_bps': global_stats.get('total_tx_bps', 0),   # Total transmitted bits per second
            'rx_pps': global_stats.get('total_rx_pps', 0),   # Total received packets per second
            'rx_bps': global_stats.get('total_rx_bps', 0),   # Total received bits per second
            'cpu_util': global_stats.get('cpu_util', 0),     # CPU Utilization
            'active_flows': global_stats.get('active_flows', 0),
            'open_flows': global_stats.get('open_flows', 0),
            'drop_rate': global_stats.get('drop_rate_bps', 0)  # Drop rate in bps
        }

        console_stats_over_time.append(console_stats)  # Append to the list
        
        print(f"--- Stats at {elapsed_time} seconds ---")
        print(console_stats) 

        # Check if traffic is still running, break if not
        if not client.is_traffic_active(ports=[1]):
            break

    return console_stats_over_time        
    

#------------------------------------------------------------------------------------------------------------------------
def run_mpstat(duration):
    """Run mpstat command to monitor CPU stats on DUT."""
    global current_test
    cmd = 'ssh upf mpstat -P ALL {} 1 -o JSON'.format(int(duration))
    output = os.popen(cmd).read()
    # print(json.loads(output))
    item["mpstat"] = json.loads(output)


#------------------------------------------------------------------------------------------------------------------------
def setup_test_case(name):
    """Setup the test case name."""
    global current_test
    current_test = name
    print("Setup TestCase: {}".format(name))

#------------------------------------------------------------------------------------------------------------------------
def parse_arguments():
    """Parse command-line arguments."""
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument('-s', '--size'       , type=int       , default=64 , help="The packets length in the stream")
    parser.add_argument('-m', '--multiplier' , default='100%' , help="The throughput in mpps on port 0 (e.g. 14mpps, 90%, 1kbps")
    parser.add_argument('-d', '--duration'   , type=int       , default=10 , help="The duration of the transmission in second")
    parser.add_argument('-f', '--flows'      , default='udp'  , help="The flows type (i.e. udp or gtp)")
    parser.add_argument('-q', '--rx_queue'   , default='12'   , help="The number of RX queues")
    parser.add_argument("-a", "--auto"       , help="Ignore all arguments and run in mode automatic", action="store_true")
    parser.add_argument('-p', '--password'   , default="", help="Password of the DUT host")

    args = parser.parse_args()

    return parser.parse_args()

#------------------------------------------------------------------------------------------------------------------------
def save_results(result_dir, json_output, test_case, iteration, packet_size, queue_size, timestamp):
    """Save the test results to a JSON file."""
    filename = "{}-{}Bytes.json".format(test_case, packet_size)
    os.makedirs(result_dir, exist_ok=True)
    file_to_open = os.path.join(result_dir, filename)



    output_prefix = f"{result_dir}/UDP___TestIteration_{iteration}___PacketSize_{packet_size}Bytes___QueueSize_{queue_size}___TimeStamp_{timestamp}"

    os.makedirs(result_dir, exist_ok=True)
    file_to_open = f"{output_prefix}___throughput.log"

    
    with open(file_to_open, "w") as dump_file:
        json.dump(json_output, dump_file, indent=2, separators=(',', ': '), sort_keys=True)

    print(f"Results saved to {file_to_open}")



#------------------------------------------------------------------------------------------------------------------------
def main():
    """Main function to run the test."""
    result_dir = "/home/witcomm/workspace/new-results"

    # Global IP and port variables
    src_ip     = "16.0.0.1"
    src_ip_end = "16.0.0.254"
    dst_ip     = "192.168.10.100"
    sport      = 1025
    dport      = 12
    port_min   = 1025 
    port_max   = 2048


    global item
    json_output = {"items": []}
    args = parse_arguments()    

    test_dict = {
        "udp": {
            "createFlows": create_udp_pkt_flow,
            "testCaseName": "DownlinkMaxThoughtput",
            "ipTarget": "src"
        }
    }
    
    timestr = time.strftime("%Y%m%d-%H%M%S")

    test_case_name = test_dict[args.flows]["testCaseName"]
    flow_list = [1000]
    
    current_test = ""
    
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    iteration = 1  # Example iteration number, modify accordingly

    for flow in flow_list:
        item = defaultdict(dict)
        tx_data_rate = args.multiplier
        test_case = "{}rx-{}flow-{}".format(args.rx_queue, flow, test_case_name)
        item["testCase"] = test_case
        setup_test_case(test_case)

        s1 = STLStream(
            packet=test_dict[args.flows]["createFlows"](
                args.size, src_ip, src_ip_end , int(flow), test_dict[args.flows]["ipTarget"],
                src_ip, dst_ip, sport, dport, port_min, port_max
            ), 
            mode=STLTXCont()
        )

        console_stats_over_time = simple_burst([s1], tx_data_rate, args.duration)        

        item["console_stats"] = console_stats_over_time
        json_output["items"].append(item)

    # Save results to JSON file
    save_results(result_dir, json_output, test_case, iteration, args.size, args.rx_queue, timestamp)



#------------------------------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    main()