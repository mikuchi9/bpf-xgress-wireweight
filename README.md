## ebpf-xgress-wireweight — Ingress/Egress Bandwidth Profiler with Payload vs Protocol Breakdown

A bandwidth analysis tool based on eBPF, designed to attach to the Linux Traffic Control (TC) layer. 
It provides real-time statistics on ingress and egress traffic for a selected interface, breaking down total bandwidth into **payload** and **protocol overhead** components.
It consists of:

- A kernel-space eBPF program (`xgress.ebpf.c`)
- A user-space program (`user.ebpf`) that handles loading, attaching, and cleanup

### Features

- 🧠 **eBPF-powered**: Efficient kernel-space data collection via TC hooks.
- 🔀 **Ingress and Egress Monitoring**: Separately tracks both directions of traffic.
- 📊 **Payload vs Protocol Overhead**: Distinguishes between actual data and transport/network layer overhead.
- 🧼 **Clean Lifecycle Management**: Automatically detaches on keypress via the userspace program.
- 🧩 **Single Interface Focus**: Attaches to one interface at a time.

> **Note:** Currently, the tool supports only **IPv4** traffic and is limited to **UDP** and **TCP** protocols.
---

### Prerequisites

- Linux kernel 5.x+ with eBPF and TC support
- Clang/LLVM and libbpf-dev
- Root privileges

**_Before compiling_**

Before compiling `user.ebpf.c`, edit the following line to specify your network interface:

`#define NET_INTERFACE "your_net_interface_name"`

### Compile the eBPF program:
```
clang -v -O2 -g -Wall -target bpf -c xgress.ebpf.c -o xgress.ebpf.o
clang -v -O2 -g -Wall user.ebpf.c -o user.ebpf -lbpf
```

### Run the Program

After successful compilation, run the program with `sudo ./user.ebpf`

This will:
- Load the eBPF program
- Attach it to the specified network interface
- Start tracing
- Automatically detach and clean up on exit

### View the Output

To see the trace output, in a separate terminal run:

`sudo cat /sys/kernel/debug/tracing/trace_pipe`

