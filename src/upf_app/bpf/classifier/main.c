#include <stdlib.h>

int main() {
  // Define the interface and QFI parameters
  const char* interface  = "eth0";
  const int qfi1_classid = 1;
  const int qfi2_classid = 2;
  const int qfi1_rate    = 1000000;  // 1 Mbps
  const int qfi2_rate    = 2000000;  // 2 Mbps

  // Create the qdisc
  char command[100];
  sprintf(command, "tc qdisc add dev %s root handle 1: htb", interface);
  system(command);

  // Define classes for different QFIs
  sprintf(
      command, "tc class add dev %s parent 1: classid 1:%d htb rate %d",
      interface, qfi1_classid, qfi1_rate);
  system(command);

  sprintf(
      command, "tc class add dev %s parent 1: classid 1:%d htb rate %d",
      interface, qfi2_classid, qfi2_rate);
  system(command);

  // Create filters to classify packets into respective QFIs
  sprintf(
      command,
      "tc filter add dev %s parent 1: protocol ip prio 1 handle 1 fw classid "
      "1:%d",
      interface, qfi1_classid);
  system(command);

  sprintf(
      command,
      "tc filter add dev %s parent 1: protocol ip prio 1 handle 2 fw classid "
      "1:%d",
      interface, qfi2_classid);
  system(command);

  // Attach the eBPF program to the qdisc
  sprintf(
      command,
      "tc filter add dev %s parent 1: bpf obj ebpf_program.o section "
      "classifier flowid 1:1",
      interface);
  system(command);

  // Configure token bucket filter for each QFI
  sprintf(
      command,
      "tc qdisc add dev %s parent 1:%d handle 10: tbf rate %d burst 100000 "
      "latency 50",
      interface, qfi1_classid, qfi1_rate);
  system(command);

  sprintf(
      command,
      "tc qdisc add dev %s parent 1:%d handle 20: tbf rate %d burst 100000 "
      "latency 50",
      interface, qfi2_classid, qfi2_rate);
  system(command);

  return 0;
}
