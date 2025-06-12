#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <net/if.h>
#include <unistd.h>

int main(int argc, char **argv) {
    
    unsigned int net_iface;

    if (argc > 1) {
        net_iface = if_nametoindex(argv[1]); 
        if (net_iface == 0) {
            fprintf(stderr, "There is no such network interface: %s\n", argv[1]);
            return 1;
        }
    } else {
        printf("Usage: sudo ./user.ebpf <network_interface_name>\n");
        return 0;
    }

    int err  = 0;
    
    // opening
    struct bpf_object *obj = bpf_object__open_file("xgress.ebpf.o", NULL);

    if (!obj) {
        printf("Couldn't load the ebpf kernel object\n");
        return 1;
    }

    // finding the ingress program
    struct bpf_program *bpf_prog_igr = bpf_object__find_program_by_name(obj, "ingress_throughput");

    if (!bpf_prog_igr) {
        printf("Failed to find ingress program");
        return 1;
    }

    // finding the egress program
    struct bpf_program *bpf_prog_egr = bpf_object__find_program_by_name(obj, "egress_throughput");

    if (!bpf_prog_egr) {
        printf("Failed to find egress program");
        return 1;
    }

    // loading
    err = bpf_object__load(obj);

    if (err) {
        printf("Failed to load ebpf program\n");
        return err;
    }

    // INGRESS TRAFFIC 
    int igr_prog_fd = bpf_program__fd(bpf_prog_igr);
    if (!igr_prog_fd)
        printf("cannot find the program\n");

    struct bpf_tc_hook igr_hook = {0};
    igr_hook.sz = sizeof(struct bpf_tc_hook);
    igr_hook.ifindex = net_iface;
    igr_hook.attach_point = BPF_TC_INGRESS;
    
    bpf_tc_hook_create(&igr_hook);

    struct bpf_tc_opts igr_opts = {0};
    igr_opts.sz = sizeof(struct bpf_tc_opts);
    igr_opts.prog_fd = igr_prog_fd;
    igr_opts.prog_id = 0;
    igr_opts.flags = BPF_TC_F_REPLACE;
    igr_opts.priority = 1;

    bpf_tc_attach(&igr_hook, &igr_opts);

    // EGRESS TRAFFIC
    int egr_prog_fd = bpf_program__fd(bpf_prog_egr);
    if (!egr_prog_fd)
        printf("cannot find the program\n");

    struct bpf_tc_hook egr_hook = {0};
    egr_hook.sz = sizeof(struct bpf_tc_hook);
    egr_hook.ifindex = net_iface;
    egr_hook.attach_point = BPF_TC_EGRESS;
    
    bpf_tc_hook_create(&egr_hook);

    struct bpf_tc_opts egr_opts = {0};
    egr_opts.sz = sizeof(struct bpf_tc_opts);
    egr_opts.prog_fd = egr_prog_fd;
    egr_opts.prog_id = 0;
    egr_opts.flags = BPF_TC_F_REPLACE;
    egr_opts.priority = 1;
        
    bpf_tc_attach(&egr_hook, &egr_opts);

    
    int c = 0;
    printf("Press any key to quit! ");
    scanf("%d", &c);
    if (c)
        goto terminate;
    

terminate:
    bpf_tc_detach(&igr_hook, &igr_opts);
    bpf_tc_hook_destroy(&igr_hook);
    bpf_tc_detach(&egr_hook, &egr_opts);
    bpf_tc_hook_destroy(&egr_hook);

    return 0;
}