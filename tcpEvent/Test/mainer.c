#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>

#include "../common.h"

#define SOFILE "/usr/local/lib/libtcpEvent.so"

//prototypes
void printEvent(struct tcp_event_t *event);
void (*cleanup)();
void signalHandler(int signum);

const char *BPF_PROGRAM = R"(
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h> 
#include <bcc/proto.h>

BPF_HASH(birth, struct sock *, u64); 

#pragma pack(push, 1)
struct event_t {
    u64 EventTime;
    u64 ts_us;
    u32 pid;
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 rx_b;
    u64 tx_b;
    u32 tcpi_segs_out;
    u32 tcpi_segs_in;
    u64 span_us;
    u16 family;
    u16 SPT;
    u16 DPT;
    char task[TASK_COMM_LEN];
};
#pragma pack(pop)

BPF_PERF_OUTPUT(tcpEvents);   


struct id_t {
	u32 pid;
	u32 uid;
	char task[128];
};
BPF_HASH(whoami, struct sock *, struct id_t);  

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid =  bpf_get_current_uid_gid() >> 32;

    u16 lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;

    if (state < TCP_FIN_WAIT1) {
        u64 ts = bpf_ktime_get_ns();
        birth.update(&sk, &ts);
    }
    if (state == TCP_SYN_SENT || state == TCP_LAST_ACK) {
        struct id_t me = {.pid = pid, .uid = uid};
        bpf_get_current_comm(&me.task, sizeof(me.task));
        whoami.update(&sk, &me);
    }
    if (state != TCP_CLOSE)
        return 0;
    // calculate lifespan
    u64 *tsp, delta_us;
    tsp = birth.lookup(&sk);
    if (tsp == 0) {
        whoami.delete(&sk);     // may not exist
        return 0;               // missed create
    }
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    birth.delete(&sk);

    struct id_t *mep;
    mep = whoami.lookup(&sk);
    if (mep != 0){
        pid = mep->pid;
	uid = mep->uid;
    }

    struct event_t event = { 0 };
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    event.rx_b = tp->bytes_received;
    event.tx_b = tp->bytes_acked;
    u16 family = sk->__sk_common.skc_family;

    event.tcpi_segs_out = tp->data_segs_out;
    event.tcpi_segs_in = tp->data_segs_in;

    if (family == AF_INET) {
        event.family = AF_INET; 
        event.saddr = sk->__sk_common.skc_rcv_saddr;
        event.daddr = sk->__sk_common.skc_daddr;
    } else if (family == AF_INET6) {
        event.family = AF_INET6;
        bpf_probe_read(&event.saddr, sizeof(event.saddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&event.daddr, sizeof(event.daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    event.EventTime = bpf_ktime_get_ns();
    event.ts_us = event.EventTime / 1000;

    event.uid =  uid ;
    event.pid = pid;

    event.SPT = lport;
    event.DPT = ntohs(dport);
    if (mep == 0) {
        bpf_get_current_comm(&event.task, sizeof(event.task));
        event.uid =  bpf_get_current_uid_gid() >> 32; /* this is the best we can do here */
    } else {
        bpf_probe_read(&event.task, sizeof(event.task), (void *)mep->task);
    }

    if (event.family){
        tcpEvents.perf_submit(ctx, &event, sizeof(event));
    }
  
    if (mep != 0){
        whoami.delete(&sk);
    }

    return 0;
}
)";

int main() {
	printf("C mainer PID: %d\n", getpid());
	void *handle = dlopen(SOFILE, RTLD_LAZY);
	if (handle) {
		puts("dlopen OK!");
	} else {
		fprintf(stderr, "Failed dlopen\n");
		printf("dlerror: %s\n", dlerror());
	}
	dlerror();		/* Clear any existing error */
	void (*AddProbe)() = dlsym(handle, "AddProbe");

	char *error = dlerror();
	if (error) {
		fprintf(stderr, "%s\n", error);
		exit(EXIT_FAILURE);
	}

	dlerror();		/* Clear any existing error */
	struct tcp_event_t (*DequeuePerfEvent) () = dlsym(handle, "DequeuePerfEvent");

	error = dlerror();
	if (error) {
		fprintf(stderr, "%s\n", error);
		exit(EXIT_FAILURE);
	}
	dlerror();		/* Clear any existing error */
	cleanup = dlsym(handle, "cleanup");
	error = dlerror();
	if (error) {
		fprintf(stderr, "%s\n", error);
		exit(EXIT_FAILURE);
	}
	signal(SIGINT, signalHandler);

	puts("About to AddProbe");
	AddProbe(BPF_PROGRAM);
	puts("AddProbe done!");

	struct tcp_event_t eventThingy;
	struct tcp_event_t *event = 0;
	while (1) {
		eventThingy = DequeuePerfEvent();
		event = &eventThingy;
		printEvent(event);
		event = 0;
	}

	dlclose(handle);

	return 0;
}

void signalHandler(int signum) {
	printf("Interrupted by signal %u by %s\n", signum, __FILE__);
	cleanup();
	printf("Exit %d called by %s\n", signum, __FILE__);
	exit(signum);
}

void printEvent(struct tcp_event_t *event) {
	if (!event) {
		return;
	}
	puts("                ---               ");
	printf(" ---> In main, DEQD at %p\n", event);
	printf(" ---> PID: %d\n", event->pid);
	printf(" ---> UID: %d\n", event->UserId);
	printf(" ---> rx_b: %ld\n", event->rx_b);
	printf(" ---> tx_b: %ld\n", event->tx_b);
	printf(" ---> tcpi_segs_out: %d\n", event->tcpi_segs_out);
	printf(" ---> tcpi_segs_in: %d\n", event->tcpi_segs_in);
	printf(" ---> Command: %s\n", event->task);
	printf(" ---> SADDR: %s\n", event->SADDR);
	printf(" ---> DADDR: %s\n", event->DADDR);
	printf(" ---> SPT: %d\n", event->SPT);
	printf(" ---> DPT: %d\n", event->DPT);
	printf(" ---> EventTime: %ld\n", event->EventTime);
	puts("                ---               ");
}
