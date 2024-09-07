#include <linux/bpf.h>
#include <bpf_helpers.h>

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx) {
    // Redirect to a specific interface (change ifindex to your target interface index)
    int ifindex = 4; 
    return bpf_redirect(ifindex, 0);
}

char _license[] SEC("license") = "GPL";
