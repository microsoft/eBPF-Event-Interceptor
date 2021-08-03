#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <arpa/inet.h>
#include <deque>
#include <vector>

#include "bcc_version.h"
#include "BPF.h"
#include "common.h"

//-------------//
// Prototypes  //
//-------------//
static uint64_t whenDidWeBootUp();
void handle_output(void *cb_cookie, void *data, int data_size);
int setupBPF();

// the methods that should be visible inside the .so file:
#ifdef __cplusplus
extern "C" {
#endif
	extern void AddProbe();
	struct udp_event_t DequeuePerfEvent();
	extern void cleanup();
	extern unsigned getStatus();

#ifdef __cplusplus
}
#endif

//-----------//
// Variables //
//-----------//
uint64_t notSoLongAgo = 0;
pthread_t tid = 0;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
std::deque < event_t * >eventDeque;
std::vector < std::string > fNamesVector;
ebpf::BPF bpf;
struct udp_event_t toConsumer = { };
unsigned status = 0;

const char *version = "UDP Tracer Ver 1.04b";

//--------------//
// Definitions  //
//--------------//
#define MAX 8192
#define UPTIME "/proc/uptime"
#define MAXQSIZE 1024
#define FN_NAME "deleteME"

const char *BPF_PROGRAM = R"(
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h> 
#include <bcc/proto.h>


#pragma pack(push, 1)
struct event_t{
	u16 family;
	u32 pid;
	u32 UserId;
	u64 EventTime;
	u16 SPT;
	u16 DPT;
	char task[16];
	unsigned __int128 saddr;
	unsigned __int128 daddr;
	u64 rx_b;
	u64 tx_b;
	u32 rxPkts;
	u32 txPkts;
	uintptr_t sockPtr;
};
#pragma pack(pop)

BPF_PERF_OUTPUT(bpfPerfBuffer);   
BPF_HASH(magic, u64, unsigned long);
BPF_HASH(otherHash, uintptr_t, struct event_t);

static int debug = 0;

// do the bpf_get stuff on eventPtr.
static void bpfHelper(struct event_t *eventPtr){
	if (!eventPtr){
		return;
	}
	if (!eventPtr->pid){
		eventPtr->pid = bpf_get_current_pid_tgid() >> 32;
	}
	if (!eventPtr->UserId){
		eventPtr->UserId = bpf_get_current_uid_gid() & 0xffffffff; // take the first 32 bits. 
	}

	if (!eventPtr->EventTime){
		eventPtr->EventTime = bpf_ktime_get_ns();
	}

	if (!eventPtr->task[0]){
		bpf_get_current_comm(eventPtr->task, sizeof(eventPtr->task));
	}
	//bpf_get_current_comm(eventPtr->task, sizeof(*eventPtr->task));
}
		
// help with the sk stuff on event_t
static void skHelper(struct pt_regs *ctx, struct event_t * eventPtr, struct sock *sk){
	if (!eventPtr){
		return;
	}

	if (!eventPtr->sockPtr){
		eventPtr->sockPtr = (uintptr_t)sk;
	}

	if (!eventPtr->family){
		eventPtr->family = sk->__sk_common.skc_family;
	}

	if (!eventPtr->SPT){
		eventPtr->SPT = sk->__sk_common.skc_num;
	}

	if (!eventPtr->saddr){
		if (eventPtr->family == AF_INET){
			eventPtr->saddr = sk->__sk_common.skc_rcv_saddr;
		} else if (eventPtr->family == AF_INET6){
			unsigned __int128 tempAddr = 0;
			bpf_probe_read_kernel(&tempAddr, sizeof(tempAddr),  sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
			eventPtr->saddr = tempAddr;
		}
	}

	if (!eventPtr->daddr){
		if (eventPtr->family == AF_INET){
			eventPtr->daddr = sk->__sk_common.skc_daddr;
		} else if (eventPtr->family == AF_INET6){
			unsigned __int128 tempAddr = 0;
			bpf_probe_read_kernel(&tempAddr, sizeof(tempAddr),  sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
			eventPtr->daddr = tempAddr;
		}
	}

	if (!eventPtr->DPT){
		u16 dport = sk->__sk_common.skc_dport;
		eventPtr->DPT = ntohs(dport);
	}

	bpfPerfBuffer.perf_submit(ctx, eventPtr, sizeof(*eventPtr));
	otherHash.update(&eventPtr->sockPtr, eventPtr);
}


int kprobe_ip4_datagram_connect(struct pt_regs *ctx, struct sock *sk){
	struct event_t event = {};
	bpfHelper(&event);
	skHelper(ctx, &event, sk);
	otherHash.update(&event.sockPtr,&event);
	if (debug){
		bpf_trace_printk("kprobe_ip4_datagram_connect\n");
	}
	return 0;
}

int kprobe_ip6_datagram_connect(struct pt_regs *ctx, struct sock *sk){
	struct event_t event = {};
	bpfHelper(&event);
	skHelper(ctx, &event, sk);
	otherHash.update(&event.sockPtr,&event);
	if (debug){
		bpf_trace_printk("kprobe_ip6_datagram_connect\n");
	}
	return 0;
}

int kprobe_udp_destruct_sock(struct pt_regs *ctx, struct sock *sk){
        struct event_t *eventPtr = 0; 
	uintptr_t pointerInt = (uintptr_t)sk;
        eventPtr = otherHash.lookup(&pointerInt);
        if (eventPtr){
		bpfHelper(eventPtr);
		skHelper(ctx, eventPtr, sk);
		if (eventPtr->pid){
			bpfPerfBuffer.perf_submit(ctx, eventPtr, sizeof(*eventPtr));
			otherHash.delete(&sk);
		}
	} else {
		// new event - we have not seen this before.
		struct event_t event = { };
		event.sockPtr = pointerInt;
		bpfHelper(&event);
		skHelper(ctx, &event, sk);
		otherHash.update(&event.sockPtr,&event);
	}
	if (debug){
		bpf_trace_printk("kprobe_udp_destruct_sock\n");
	}
  	return 0;
}


int kprobe_udp_recvmsg(struct pt_regs *ctx, struct sock *sk){
	u64 pidTgid = bpf_get_current_pid_tgid();
	uintptr_t pointerInt = (uintptr_t)sk;
	magic.update(&pidTgid, &pointerInt);

        struct event_t *eventPtr = 0; 
        eventPtr = otherHash.lookup(&pointerInt);
        if (eventPtr){
		bpfHelper(eventPtr);
		skHelper(ctx, eventPtr, sk);
		bpfPerfBuffer.perf_submit(ctx, eventPtr, sizeof(*eventPtr));
		otherHash.delete(&pointerInt);
	} else {
		if (debug){
			bpf_trace_printk("new event in kprobe_udp_recvmsg\n");
		}
		struct event_t event = { };
		event.sockPtr = pointerInt;
		bpfHelper(&event);
		skHelper(ctx, &event, sk);
		otherHash.update(&event.sockPtr,&event);
	}

	if (debug){
		bpf_trace_printk("kprobe_udp_recvmsg\n");
	}
	return 0;
}

int kretprobe__udp_recvmsg(struct pt_regs *ctx){
	int ret = PT_REGS_RC(ctx);
	if (ret > 0){
		u64 pidTgid = bpf_get_current_pid_tgid();
		unsigned long *found = magic.lookup(&pidTgid);
		if (found){
			uintptr_t pointerInt = (uintptr_t)*found;
			struct sock *sk = (struct sock *)pointerInt;	
			uintptr_t sockPtr = (uintptr_t)sk;
			struct event_t *eventPtr = otherHash.lookup(&sockPtr);

			if (eventPtr){
				eventPtr->rx_b += ret;
				eventPtr->rxPkts += 1;
				bpfHelper(eventPtr);
				skHelper(ctx, eventPtr, sk);
			}
			magic.delete(&pidTgid);
		}

	}
	return 0;
}

// udpv6_recvmsg
int kprobe__udpv6_recvmsg(struct pt_regs *ctx, struct sock *sk){

	uintptr_t pointerInt = (uintptr_t)sk;

	u64 pidTgid = bpf_get_current_pid_tgid();
	magic.update(&pidTgid, &pointerInt);

        struct event_t *eventPtr = 0; 
        eventPtr = otherHash.lookup(&pointerInt);

	if (eventPtr){
		bpfHelper(eventPtr);
		skHelper(ctx, eventPtr, sk);
		eventPtr->sockPtr = pointerInt;
		skHelper(ctx, eventPtr, sk);
		otherHash.update(&eventPtr->sockPtr,eventPtr);
	} else {
		// fallback to this.
		struct event_t event = { };
		eventPtr = &event;

		bpfHelper(eventPtr);
		skHelper(ctx, eventPtr, sk);
		eventPtr->sockPtr = pointerInt;
		skHelper(ctx, eventPtr, sk);
		otherHash.update(&eventPtr->sockPtr,eventPtr);
	}

	return 0;
}

int kretprobe__udpv6_recvmsg(struct pt_regs *ctx){

        int ret = PT_REGS_RC(ctx);
        if (ret > 0){
                u64 pidTgid = bpf_get_current_pid_tgid();
                unsigned long *found = magic.lookup(&pidTgid);
                if (found){
                        uintptr_t pointerInt = (uintptr_t)*found;
			
			struct sock *sockPtr = (struct sock *)pointerInt;
                        struct event_t *eventPtr = 0;
			eventPtr = otherHash.lookup(&pointerInt);
                        magic.delete(&pidTgid);

                        if (eventPtr){
                                eventPtr->rx_b += ret;
                                eventPtr->rxPkts += 1;
                                bpfHelper(eventPtr);
                                skHelper(ctx, eventPtr, sockPtr); // derived.
				otherHash.update(&eventPtr->sockPtr,eventPtr);
                        } else {
				return 0;
			}
                }
        }

        if (debug){
                bpf_trace_printk("kretprobe__udp_recvmsg\n");
        }
        return 0;
}
// udpv6_recvmsg

int kprobe__udpv6_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len){
        struct event_t *eventPtr = 0; 

	uintptr_t pointerInt = (uintptr_t)sk;
        eventPtr = otherHash.lookup(&pointerInt);
        if (eventPtr){
		eventPtr->tx_b += len;
                eventPtr->txPkts += 1;
		bpfHelper(eventPtr);
		skHelper(ctx, eventPtr, sk);
		bpfPerfBuffer.perf_submit(ctx, eventPtr, sizeof(*eventPtr));
		if (debug){
			bpf_trace_printk("kprobe__udpv6_sendmsg pid: %d sent %d bytes\n", eventPtr->pid, len);
		}
	} else {
		// new event - we have not seen this before.
		struct event_t event = {};
		event.sockPtr = pointerInt;
		event.tx_b += len;
		event.txPkts += 1;
		bpfHelper(&event);
		skHelper(ctx, &event, sk);
		otherHash.update(&event.sockPtr,&event);
		if (debug){
			bpf_trace_printk("kprobe__udpv6_sendmsg pid: %d sent %d bytes\n", event.pid, len);
		}
	}
	return 0;
}

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len){
        struct event_t *eventPtr = 0; 

	uintptr_t pointerInt = (uintptr_t)sk;
        eventPtr = otherHash.lookup(&pointerInt);
        if (eventPtr){
		eventPtr->tx_b += len;
		eventPtr->txPkts += 1;
		bpfHelper(eventPtr);
		skHelper(ctx, eventPtr, sk);
		bpfPerfBuffer.perf_submit(ctx, eventPtr, sizeof(*eventPtr));
		if (debug){
			bpf_trace_printk("kprobe__udp_sendmsg pid: %d sent %d bytes\n", eventPtr->pid, len);
		}
	} else {
		// new event - we have not seen this before.
		struct event_t event = {};
		event.sockPtr = pointerInt;
		event.tx_b += len;
		event.txPkts += 1;
		bpfHelper(&event);
		skHelper(ctx, &event, sk);
		otherHash.update(&event.sockPtr,&event);
		if (debug){
			bpf_trace_printk("kprobe__udp_sendmsg pid:%d sent %d bytes\n", event.pid, len);
		}
	}
	return 0;
}

)";

void AddProbe() {
	std::cout << version << " with BCC " << LIBBCC_VERSION << std::endl;
	std::thread t(setupBPF);
	t.detach();
}

int setupBPF() {
	tid = pthread_self();
	auto init_res = bpf.init(BPF_PROGRAM);
	if (init_res.code()) {
		std::cerr << init_res.msg() << std::endl;
		return 1;
	}

	auto d = bpf.attach_kprobe("ip6_datagram_connect", "kprobe_ip6_datagram_connect");
	if (d.code()) {
		std::cerr << d.msg() << std::endl;
		return 1;
	}
	fNamesVector.push_back("ip6_datagram_connect");

	auto e = bpf.attach_kprobe("ip4_datagram_connect", "kprobe_ip4_datagram_connect");
	if (e.code()) {
		std::cerr << e.msg() << std::endl;
		return 1;
	}
	fNamesVector.push_back("ip4_datagram_connect");

	auto a = bpf.attach_kprobe("udp_recvmsg", "kretprobe__udp_recvmsg", 0, BPF_PROBE_RETURN, 0);
	if (a.code()) {
		std::cerr << a.msg() << std::endl;
		return 1;
	}
	fNamesVector.push_back("udp_recvmsg");

	auto b = bpf.attach_kprobe("udp_sendmsg", "kprobe__udp_sendmsg");
	if (b.code()) {
		std::cerr << b.msg() << std::endl;
		return 1;
	}
	fNamesVector.push_back("udp_sendmsg");

	auto c = bpf.attach_kprobe("udp_destruct_sock", "kprobe_udp_destruct_sock");
	if (c.code()) {
		std::cerr << c.msg() << std::endl;
		return 1;
	}
	fNamesVector.push_back("udp_destruct_sock");

	auto x = bpf.attach_kprobe("udp_recvmsg", "kprobe_udp_recvmsg");
	if (x.code()) {
		std::cerr << x.msg() << std::endl;
		return 1;
	}
	fNamesVector.push_back("udp_recvmsg");

	auto v = bpf.attach_kprobe("udpv6_sendmsg", "kprobe__udpv6_sendmsg");
	if (v.code()) {
		std::cerr << v.msg() << std::endl;
		return 1;
	}
	fNamesVector.push_back("udpv6_sendmsg");

// add kprobe__udpv6_recvmsg
	auto kprobe__udpv6_recvmsg = bpf.attach_kprobe("udpv6_recvmsg", "kprobe__udpv6_recvmsg");
	if (kprobe__udpv6_recvmsg.code()){
		std::cerr << kprobe__udpv6_recvmsg.msg() << std::endl;
                return 1;
        }
        fNamesVector.push_back("udpv6_recvmsg");

//add kretprobe__udpv6_recvmsg 
	auto kretprobe__udpv6_recvmsg  = bpf.attach_kprobe("udpv6_recvmsg", "kretprobe__udpv6_recvmsg", 0, BPF_PROBE_RETURN, 0);
	if (kretprobe__udpv6_recvmsg.code()){
		std::cerr << kretprobe__udpv6_recvmsg.msg() << std::endl;
		return 1;
	}
	fNamesVector.push_back("kretprobe__udpv6_recvmsg");


	// what have we done so far?
	for (auto probeName:fNamesVector) {
		std::cout << "Attached: " << probeName << std::endl;
	}

	auto openResults = bpf.open_perf_buffer("bpfPerfBuffer", &handle_output);
	auto openResultsCode = openResults.code();
	if (openResultsCode) {
		std::cerr << openResults.msg() << std::endl;
		exit(1);
		return 1;
	}
	puts("--> bpf.open_perf_buffer OK");

	//cleanup 
	if (bpf.free_bcc_memory()) {
		std::cerr << "Failed to free llvm/clang memory" << std::endl;
		exit(1);
		return 1;
	}


	pthread_rwlock_wrlock(&rwlock);
	status++;
	pthread_rwlock_unlock(&rwlock);

	puts("Tracing, press \"CtrlC\" to terminate..");
	while (1) {
		bpf.poll_perf_buffer("bpfPerfBuffer");
	}

	return 0;
}

unsigned getStatus() {
	pthread_rwlock_rdlock(&rwlock);
	auto x = status;
	pthread_rwlock_unlock(&rwlock);
	return x;
}

void handle_output(void *cb_cookie, void *data, int data_size) {
	(void)cb_cookie;
	(void)data_size;

	auto event = static_cast < event_t * >(data);
	if (event) {
		int shed = 0;
		pthread_mutex_lock(&mtx);
		if (eventDeque.size() > MAXQSIZE) {
			shed++;
			eventDeque.pop_front();
		}
		eventDeque.push_back(event);
		pthread_mutex_unlock(&mtx);
		pthread_cond_signal(&cond);
		if (shed) {
			puts("Shedding UDP events..");
		}
	}
}

struct udp_event_t DequeuePerfEvent() {
	while (1) {
		pthread_mutex_lock(&mtx);
		if (!eventDeque.empty()) {
			auto event = eventDeque.front();
			eventDeque.pop_front();
			if (!notSoLongAgo) {
				notSoLongAgo = whenDidWeBootUp() * 1000000000LLU;
			}
			pthread_mutex_unlock(&mtx);

			// carve toConsumer struct:
			memset(&toConsumer, 0, sizeof(toConsumer));
			toConsumer.EventTime = event->EventTime + notSoLongAgo;
			toConsumer.pid = event->pid;
			toConsumer.UserId = event->UserId;
			toConsumer.rx_b = event->rx_b;
			toConsumer.tx_b = event->tx_b;
			toConsumer.rxPkts = event->rxPkts;
			toConsumer.txPkts = event->txPkts;
			toConsumer.family = event->family;
			toConsumer.SPT = event->SPT;
			toConsumer.DPT = event->DPT;

			switch (event->family) {
			case AF_INET:
				inet_ntop(AF_INET, (struct in_addr *)&(event->saddr), toConsumer.SADDR, 128);
				inet_ntop(AF_INET, (struct in_addr *)&(event->daddr), toConsumer.DADDR, 128);
				break;
			case AF_INET6:
				inet_ntop(AF_INET6, (struct in_addr6 *)&(event->saddr), toConsumer.SADDR, 128);
				inet_ntop(AF_INET6, (struct in_addr6 *)&(event->daddr), toConsumer.DADDR, 128);
				break;
			default:
				fprintf(stderr, "Cannot determine IPV4/6 family\n");
				continue;
			}

			memcpy(toConsumer.task, event->task, strnlen(event->task, 16));
			return toConsumer;
		} else {
			// no events yet. wait on cond, mtx.
			pthread_cond_wait(&cond, &mtx);
			pthread_mutex_unlock(&mtx);
		}
	}
}

static uint64_t whenDidWeBootUp() {
	// UPTIME: The first value represents the total number of seconds the system has been up.
	// Subtract this from the current time, it gives us the time we officially finished boot up.

	FILE *fp = fopen(UPTIME, "r");
	if (!fp) {
		perror("fopen");
		exit(1);
	}

	char temp[MAX] = { 0 };
	char *mustNotbeEmpty = fgets(temp, MAX, fp);
	if (!mustNotbeEmpty) {
		fprintf(stderr, "fgets err\n");
		exit(1);
	}
	fclose(fp);
	double firstWord = 0;
	sscanf(temp, "%lf", &firstWord);
	if (!firstWord) {
		// give up, die now.
		fprintf(stderr, "failed to get uptime details\n");
		exit(1);
	}
	double weCameUpAt = ((uint64_t) time(0) - firstWord);
	return weCameUpAt;
}

void cleanup() {
	//detach 
	puts("Cleaning up!");
 	for (auto probe:fNamesVector) {
		auto detach = bpf.detach_kprobe(probe);
		auto detachCode = detach.code();
		if (detachCode) {
			std::cerr << "Detaching: " << probe << ": " << detach.msg() << std::endl;
		} else {
			std::cout << "Detached: " << probe << std::endl;
		}
	}
	if (tid) {
		std::cout << "Cancelling tid: " << tid << std::endl;
		pthread_cancel(tid);
	}
	puts("--> bpf.detach_kprobe OK");
}


