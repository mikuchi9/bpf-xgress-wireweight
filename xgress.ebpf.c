#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdint.h>
#include <linux/pkt_cls.h>

#define NS_IN_SEC       (1000 * 1000 * 1000)
#define POLL_1_SEC      1

__u32 i_sum_of_proto_tcp_headers = 0;
__u32 i_sum_of_proto_udp_headers = 0;
__u32 i_sum_of_tcp_payload = 0;
__u32 i_sum_of_udp_payload = 0;

__u32 e_sum_of_proto_tcp_headers = 0;
__u32 e_sum_of_proto_udp_headers = 0;
__u32 e_sum_of_tcp_payload = 0;
__u32 e_sum_of_udp_payload = 0;

__u32 headers_sum_tcp = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
__u32 headers_sum_udp = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

__u32 checked_time_past = 0;

SEC("classifier/ingress")
int ingress_throughput(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 packet_size = (__u32)((__u64)data_end - (__u64)data);
    struct ethhdr *eth = data; 

    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *iph = data + sizeof(struct ethhdr);
        
    if ((void *)iph + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;
        
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(struct tcphdr);
        if ((void *)tcph + sizeof(struct tcphdr) > data_end)
            return TC_ACT_OK;

        __sync_fetch_and_add(&i_sum_of_proto_tcp_headers, headers_sum_tcp);
        __sync_fetch_and_add(&i_sum_of_tcp_payload, packet_size - headers_sum_tcp);

    }    
        
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + sizeof(struct udphdr);
        if ((void *)udph + sizeof(struct udphdr) > data_end)
            return TC_ACT_OK;

        __sync_fetch_and_add(&i_sum_of_proto_udp_headers, headers_sum_udp);
        __sync_fetch_and_add(&i_sum_of_udp_payload, packet_size - headers_sum_udp);

    }

    __u32 time_now = (__u32)(bpf_ktime_get_ns() / NS_IN_SEC); // seconds after system boot (doesn't include suspended time)

    if (time_now - checked_time_past >= POLL_1_SEC) { // 1 sec is already passed. '>=' sign because just to be sure
        checked_time_past = time_now;

        bpf_printk("INGRESS TRAFFIC");
        bpf_printk("protocol header overhead, total (bits/sec): %llu", i_sum_of_proto_tcp_headers + i_sum_of_proto_udp_headers);
        bpf_printk("payload in sec, total (bits/sec): %llu", i_sum_of_tcp_payload + i_sum_of_udp_payload);
        
        bpf_printk("TCP protocol header overhead (bits/sec): %lu", i_sum_of_proto_tcp_headers);
        bpf_printk("TCP payload in sec (bits/sec): %lu", i_sum_of_tcp_payload);
        
        bpf_printk("UDP protocol header overhead (bits/_sec): %lu", i_sum_of_proto_udp_headers);
        bpf_printk("UDP payload in sec (bits/sec): %lu\n", i_sum_of_udp_payload);

        i_sum_of_proto_tcp_headers = 0;
        i_sum_of_proto_udp_headers = 0;
        i_sum_of_tcp_payload = 0;
        i_sum_of_udp_payload = 0;
    };

    return TC_ACT_OK;
}

SEC("classifier/egress")
int egress_throughput(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 packet_size = (__u32)((__u64)data_end - (__u64)data);
    struct ethhdr *eth = data; 


    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *iph = data + sizeof(struct ethhdr);
        
    if ((void *)iph + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;
        
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(struct tcphdr);
        if ((void *)tcph + sizeof(struct tcphdr) > data_end)
            return TC_ACT_OK;
        
        __sync_fetch_and_add(&e_sum_of_proto_tcp_headers, headers_sum_tcp);
        __sync_fetch_and_add(&e_sum_of_tcp_payload, packet_size - headers_sum_tcp);

    }    
        
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + sizeof(struct udphdr);
        if ((void *)udph + sizeof(struct udphdr) > data_end)
            return TC_ACT_OK;

        __sync_fetch_and_add(&e_sum_of_proto_udp_headers, headers_sum_udp);
        __sync_fetch_and_add(&e_sum_of_udp_payload, packet_size - headers_sum_udp);

    }
    
    __u32 time_now = (__u32)(bpf_ktime_get_ns() / NS_IN_SEC); // seconds after system boot (doesn't include suspended time)

    if (time_now - checked_time_past >= POLL_1_SEC) { // 1 sec is already passed. '>=' sign because just to be sure
        checked_time_past = time_now;

        bpf_printk("EGRESS TRAFFIC");
        bpf_printk("protocol header overhead, total (bits/sec): %llu", e_sum_of_proto_tcp_headers + e_sum_of_proto_udp_headers);
        bpf_printk("payload in sec, total (bits/sec): %llu", e_sum_of_tcp_payload + e_sum_of_udp_payload);
        
        bpf_printk("TCP protocol header overhead (bits/sec): %lu", e_sum_of_proto_tcp_headers);
        bpf_printk("TCP payload in sec (bits/sec): %lu", e_sum_of_tcp_payload);
        
        bpf_printk("UDP protocol header overhead (bits/sec): %lu", e_sum_of_proto_udp_headers);
        bpf_printk("UDP payload in sec (bits/sec): %lu\n", e_sum_of_udp_payload);

        e_sum_of_proto_tcp_headers = 0;
        e_sum_of_proto_udp_headers = 0;
        e_sum_of_tcp_payload = 0;
        e_sum_of_udp_payload = 0;
    };

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";