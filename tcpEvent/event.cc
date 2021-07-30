// Author: Anu Mathew <anmathew@microsoft.com> 
// last update: 04/01/2021 

#include <unistd.h>
#include <fstream>
#include <iostream>
#include <cstdint>
#include <map>
#include <deque>
#include <thread>
#include <arpa/inet.h>
#include <glob.h>

#include "bcc_version.h"
#include "BPF.h"
#include "event.h"

#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>	/* for IPv4 and IPv6 sockets */
#include <linux/tcp.h>
#include <linux/rtnetlink.h>
#include <time.h>

#define MAXQSIZE 1024
#define PROTOSIZE 2

// Global Vars 
std::deque < event_t * >eventDeque;
std::map < event_t *, int >PtrMap;
std::map < std::string, uint32_t > SockStrMap;	// our unguarded Map
ebpf::BPF bpf;
pthread_t tid = 0;
pthread_t netLinkTid = 0;
uint64_t notSoLongAgo = 0;
int netLinkInit = 0;
int socketFDArray[15] = { 0 };
int intProtos[PROTOSIZE] = { AF_INET, AF_INET6 };
char charProtos[][16] = { "AF_INET", "AF_INET6" };
struct tcp_event_t toConsumer = { };
unsigned status = 0;

pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;;
pthread_mutex_t mapMu = PTHREAD_MUTEX_INITIALIZER;;
pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

char slash[] = "/";
char version[] = "tcpTracer Ver 1.03d";

// proto types
int sendDiagMsg(int nlSocket, int family);
void handle_output(void *cb_cookie, void *data, int data_size);
static uint64_t whenDidWeBootUp();
void destroyEventPtr(event_t * eventPtr);
void netLinkProbe();
int findSocketInodes();
int askForEvents(int PROTO);
int getEvents();
int harvestEvents(int harvestSock);
void parseReply(struct inet_diag_msg *reply, int rtalen);
int readCmdLine(uint32_t pid, char *writeTo, int maxLen);
static uint64_t upSince();
void printEvent(struct event_t *ourEvent);
int findNthWord(char *line_in, int n, char *word, char *delim);

void handle_output(void *cb_cookie, void *data, int data_size) {
	(void)data_size;
	(void)cb_cookie;
	auto event = static_cast < event_t * >(data);
	if (event) {
		int shed = 0;
		struct event_t *almostGone = 0;
		pthread_mutex_lock(&mtx);
		if (eventDeque.size() > MAXQSIZE) {
			shed++;
			almostGone = eventDeque.front();
			eventDeque.pop_front();
		}
		eventDeque.push_back(event);
		pthread_mutex_unlock(&mtx);
		pthread_cond_signal(&cond);
		if (shed) {
			destroyEventPtr(almostGone);
			puts("Shedding TCP events..");
		}
	}
}

void destroyEventPtr(event_t * eventPtr) {
	if (!eventPtr) {
		return;
	}

	int found = 0;
	int erased = 0;

	pthread_mutex_lock(&mapMu);
	found = PtrMap.count(eventPtr);
	erased = PtrMap.erase(eventPtr);
	pthread_mutex_unlock(&mapMu);

	if (found && erased) {
		// we found it, and we erased it. 
		// now reclaim its mem: 
		delete(eventPtr);
		eventPtr = 0;
	}
	//printf("[%s] ptr map size: %u\n", __func__, mapSize);
}

// We touch raw nerves needling large BPF structs across - this causes Bus errors.
struct tcp_event_t DequeuePerfEvent() {
	while (1) {
		pthread_mutex_lock(&mtx);
		//std::unique_lock<std::mutex>lock{mtx};
		if (!netLinkInit) {
			netLinkInit++;
			std::thread t2(netLinkProbe);
			t2.detach();
		}

		if (!eventDeque.empty()) {
			auto event = eventDeque.front();
			eventDeque.pop_front();
			pthread_mutex_unlock(&mtx);

			if (!notSoLongAgo) {
				notSoLongAgo = whenDidWeBootUp() * 1000000000LLU;
			}

			memset(&toConsumer, 0, sizeof(toConsumer));
			toConsumer.EventTime = event->EventTime + notSoLongAgo;
			toConsumer.pid = event->pid;
			toConsumer.UserId = event->UserId;
			toConsumer.rx_b = event->rx_b;
			toConsumer.tx_b = event->tx_b;
			toConsumer.tcpi_segs_out = event->tcpi_segs_out;
			toConsumer.tcpi_segs_in = event->tcpi_segs_in;
			toConsumer.family = event->family;
			toConsumer.SPT = event->SPT;
			toConsumer.DPT = event->DPT;

			switch (event->family) {
			case AF_INET:
				inet_ntop(AF_INET, (struct in_addr *)&(event->saddr), toConsumer.SADDR, sizeof(toConsumer.SADDR));
				inet_ntop(AF_INET, (struct in_addr *)&(event->daddr), toConsumer.DADDR, sizeof(toConsumer.DADDR));
				break;
			case AF_INET6:
				inet_ntop(AF_INET6, (struct in_addr6 *)&(event->saddr), toConsumer.SADDR, sizeof(toConsumer.SADDR));
				inet_ntop(AF_INET6, (struct in_addr6 *)&(event->daddr), toConsumer.DADDR, sizeof(toConsumer.DADDR));
				break;
			default:
				fprintf(stderr, "Unknown inet family: %d\n", event->family);
				continue;
			}

			// 16 because of TASK_COMM_LEN
			memcpy(toConsumer.task, event->task, strnlen(event->task, 16));
			destroyEventPtr(event);

			return toConsumer;
		} else {
			// wait for events to fill in
			pthread_cond_wait(&cond, &mtx);
			pthread_mutex_unlock(&mtx);
		}
	}
}
void AddProbe(const char *BPF_PROGRAM) {
	std::cout << version << " with BCC " << LIBBCC_VERSION << std::endl;
	std::thread t(setupBPF, BPF_PROGRAM);
	t.detach();
}

int setupBPF(const char *BPF_PROGRAM) {
	tid = pthread_self();
	printf("Hello from %s\n", __func__);
	auto bpfPtr = &bpf;
	auto init_res = bpf.init(BPF_PROGRAM);
	if (init_res.code() != 0) {
		std::cerr << init_res.msg() << std::endl;
		exit(1);
		return 1;
	}
	puts("--> bpf.init OK");
	auto attach = bpf.attach_kprobe(FN_NAME, "kprobe__tcp_set_state");
	auto attachCode = attach.code();
	if (attachCode) {
		std::cerr << attach.msg() << std::endl;
		exit(1);
		return 1;
	}
	puts("--> bpf.attach_kprobe OK");

	auto openResults = bpfPtr->open_perf_buffer(TABLE, &handle_output);
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
		bpf.poll_perf_buffer(TABLE);
	}

	cleanup();

	return 0;
}


unsigned getStatus() {
	pthread_rwlock_rdlock(&rwlock);
	auto x = status;
	pthread_rwlock_unlock(&rwlock);
	return x;
}

void cleanup() {
	//detach 
	puts("Cleaning up!");
	auto detach = bpf.detach_kprobe(FN_NAME);
	auto detachCode = detach.code();
	if (detachCode) {
		std::cerr << detach.msg() << std::endl;
		exit(1);
	}
	if (tid) {
		pthread_cancel(tid);
	}
	puts("--> bpf.detach_kprobe OK");

	if (netLinkTid){
		puts("--> Cancelling netLinkTid");
		pthread_cancel(netLinkTid);
	}
}

void printCharArray(const char *charPtr) {
	printf("Array: %s\n", charPtr);
}

static uint64_t upSince() {
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
	return firstWord;
}

static uint64_t whenDidWeBootUp() {
	// UPTIME: The first value represents the total number of seconds the system has been up.
	// Subtract this from the current time, it gives us the time we officially finished boot up.
	auto firstWord = upSince();
	double weCameUpAt = ((uint64_t) time(0) - firstWord);
	return weCameUpAt;
}

void netLinkProbe() {
	netLinkTid = pthread_self();
	while (1) {
		findSocketInodes();
		if (!SockStrMap.size()) {
			puts("SockStrMap empty - this is bad - we do not have data to attribute events to.");
			sleep(2);
			continue;
		}
		if (getEvents()) {
			//puts("Got events!");
		} else {
			puts("Got NO netLink Events!");
		}
		sleep(NETLINKNAP);
	}
}

int getEvents() {
	// request AF_INET first:
	int rc = 0;
	int sockFd = 0;
	for (int i = 0; i < PROTOSIZE; i++) {
		sockFd = askForEvents(intProtos[i]);
		if (sockFd > 1) {
			harvestEvents(sockFd);
			rc++;
		} else {
			fprintf(stderr, "[%s] err asking for %s events\n", __func__, charProtos[i]);
		}
	}

	return rc;
}

int findSocketInodes() {
	// SockStrMap clear 1st
	SockStrMap.clear();
	glob_t globbuf;
	int ret = glob(GLOBTHIS, 0, 0, &globbuf);
	if ((ret == GLOB_NOSPACE) || (ret == GLOB_ABORTED)) {
		perror("glob fail");
		return 1;
	}

	if (ret == GLOB_NOMATCH) {
		return -1;
	}

	if (!globbuf.gl_pathc) {
		return -1;
	}

	int i = 0;
	char symlinkName[SYMLINK_LEN] = { 0 };
	char *path = 0;
	char pidTxt[BUF] = { 0 };
	uint32_t pid = 0;
	char *err = 0;

	while (globbuf.gl_pathv[i]) {
		memset(pidTxt, 0, BUF);
		memset(symlinkName, 0, SYMLINK_LEN);
		path = globbuf.gl_pathv[i];
		i++;
		if (readlink(path, symlinkName, SYMLINK_LEN_B) < 0) {
			continue;
		}
		if (memcmp(symlinkName, ISSOCK, ISSOCKLen)) {
			continue;
		}

		if (!findNthWord(path, 1, pidTxt, slash)) {
			continue;
		}

		if (!strnlen(pidTxt, 8)) {
			continue;
		}
		err = 0;
		pid = 0;
		pid = strtod(pidTxt, &err);
		if ((!*err) && (pid)) {
			// all good!
		} else {
			continue;
		}

		SockStrMap[std::string(symlinkName)] = pid;
	}

	globfree(&globbuf);
	return 0;
}

int askForEvents(int PROTO) {
	// try to reuse socket fds as much as we can.
	int *fdPtr = &socketFDArray[PROTO];
	if ((!*fdPtr) || (*fdPtr < 1)) {
		*fdPtr = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_SOCK_DIAG);
		printf("[%s] proto: %u new socket: %u\n", __func__, PROTO, *fdPtr);
		sleep(3);
	}

	// check again.
	if ((!*fdPtr) || (*fdPtr < 1)) {
		perror("socket Gen failure..? ");
		// this time it is FATAL.
		abort();
	}

	if (sendDiagMsg(*fdPtr, PROTO) < 0) {
		perror("sendDiagMsg err ");
		// let us close this socket at this point.
		close(*fdPtr);
		*fdPtr = 0;
	}

	return *fdPtr;
}

int sendDiagMsg(int nlSocket, int family) {

	// We send a whole onion. With layers and layers of tear producing stuff. 

	// After the Netlink socket is created, we request information about sockets
	// we are interested in by creating a netlink message. 
	// This netlink message contains a request struct specifying information about 
	// the sockets we're interested in. 
	// For tcp and udp sockets, we use inet_diag_req_v2
	/*
	   struct inet_diag_req_v2 {
	   __u8    sdiag_family;
	   __u8    sdiag_protocol;
	   __u8    idiag_ext;
	   __u8    pad;
	   __u32   idiag_states;
	   struct inet_diag_sockid id;
	   };
	 */

	// We'd use sendmsg() and Scatter/Gather array to send this over.
	// ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);

	struct inet_diag_req_v2 connRequest = { };
	connRequest.sdiag_family = family;
	connRequest.sdiag_protocol = IPPROTO_TCP;
	connRequest.idiag_states = TCPF_ALL & ~((1 << TCP_SYN_RECV) | (1 << TCP_TIME_WAIT) | (1 << TCP_CLOSE));
	connRequest.idiag_ext |= (1 << (INET_DIAG_INFO - 1));

	struct nlmsghdr nlh = { };
	nlh.nlmsg_len = NLMSG_LENGTH(sizeof(connRequest));
	nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;

	struct sockaddr_nl sa = { };
	sa.nl_family = AF_NETLINK;

	struct iovec iov[3] = { };
	iov[0].iov_base = (void *)&nlh;
	iov[0].iov_len = sizeof(nlh);
	iov[1].iov_base = (void *)&connRequest;
	iov[1].iov_len = sizeof(connRequest);

	struct msghdr msg = { };

	msg.msg_name = (void *)&sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov[0];
	msg.msg_iovlen = 2;

	int retval = sendmsg(nlSocket, &msg, 0);
	return retval;
}

int harvestEvents(int harvestSock) {
	// time to reap what we have sown:
	char readInto[MAX] = { 0 };
	int bytesRead = 0;
	struct nlmsghdr *nlh = 0;
	struct inet_diag_msg *reply = 0;
	int rtalen = 0;

	while (1) {
		memset(readInto, 0, MAX);
		nlh = 0;
		bytesRead = 0;

		bytesRead = recv(harvestSock, readInto, MAX, 0);
		if (bytesRead < 1) {
			printf("Err 33.1 Bytes Read: %u \n", bytesRead);
			return 0;
		}
		nlh = (struct nlmsghdr *)readInto;

		// NLMSG_OK(struct nlmsghdr *nlh, int len);
		// true if the netlink message is not truncated and is parse-able.
		while (NLMSG_OK(nlh, bytesRead)) {
			if (nlh->nlmsg_type == NLMSG_DONE) {
				// We done tinkering!.
				// puts("NLMSG_DONE");
				return 0;
			}

			if (nlh->nlmsg_type == NLMSG_ERROR) {
				perror("NLMSG_ERROR");
				return 1;
			}
			// We gotta dig deeper. 

			// NLMSG_DATA() - gives us the pointer to the payload associated with the passed nlh;
			reply = (struct inet_diag_msg *)NLMSG_DATA(nlh);
			if (!reply) {
				fprintf(stderr, "NLMSG_DATA null \n");
				return 1;
			}
			// NLMSG_LENGTH() 
			// Given the payload length, len, this macro returns the aligned length to store in the nlmsg_len field of the nlmsghdr.
			// Some rtnetlink messages have optional attributes after the initial header:
			rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*reply));
			parseReply(reply, rtalen);
			nlh = NLMSG_NEXT(nlh, bytesRead);
		}
	}

}

void parseReply(struct inet_diag_msg *reply, int rtalen) {

	if (!reply->idiag_inode) {
		// we need a valid inode to map it all.
		puts("we need a valid inode");
		return;
	}

	int ok = 0;
	pthread_mutex_lock(&mtx);
	auto curSize = eventDeque.size();
	pthread_mutex_unlock(&mtx);

	if (curSize > MAXQSIZE) {
		puts("at capacity!");
		return;
	}

	char lookThisUp[BUF] = { 0 };
	snprintf(lookThisUp, BUF, "socket:[%u]", reply->idiag_inode);
	int hit = 0;
	std::string key = lookThisUp;
	hit = SockStrMap.count(lookThisUp);
	if (!hit) {
		return;
	}

	uint32_t pid = 0;
	pid = SockStrMap[lookThisUp];
	if (!pid) {
		return;
	}

	// beyond this step, we must pay attention to reclaiming netlinkEvent:
	event_t *netlinkEvent = new event_t();

	// when did we see this? now, in microseconds.
	auto up = upSince();
	netlinkEvent->EventTime = up * 1000000000LLU;

	// which command caused this?
	if (readCmdLine(pid, netlinkEvent->task, 128) < 0) {
		goto EndofRunWay;
	}

	// check it again, another way:
	if (!strnlen(netlinkEvent->task, 12)) {
		goto EndofRunWay;
	}

	// what's its PID?
	netlinkEvent->pid = pid;
	netlinkEvent->UserId = reply->idiag_uid;
	netlinkEvent->family = reply->idiag_family;

	/*
           struct inet_diag_sockid {
               __be16  idiag_sport;
               __be16  idiag_dport;
               __be32  idiag_src[4];
               __be32  idiag_dst[4];
               __u32   idiag_if;
               __u32   idiag_cookie[2];
           };

	  if ipv4, src address is idiag_src[0], 32 bit ipv4 address
	  if ipv6, src address is idiag_src[0,1,2,3] and is 128 bits long 

	*/

	switch (netlinkEvent->family){
	case AF_INET6:
		// ipv6 address is 16 bytes, 16 * 8 = 128bits
		memcpy(&netlinkEvent->saddr, reply->id.idiag_src, 16);
		memcpy(&netlinkEvent->daddr, reply->id.idiag_dst, 16);
		break;
	default:
		netlinkEvent->saddr = *reply->id.idiag_src;
		netlinkEvent->daddr = *reply->id.idiag_dst;
		break;
	}

	netlinkEvent->SPT = ntohs(reply->id.idiag_sport);
	netlinkEvent->DPT = ntohs(reply->id.idiag_dport);
	struct rtattr *routeAttributes;
	struct anu_tcp_info *info;

	if (rtalen) {
		routeAttributes = (struct rtattr *)(reply + 1);
		while (RTA_OK(routeAttributes, rtalen)) {
			if (routeAttributes->rta_type == INET_DIAG_INFO) {
				// routeAttributes is a valid routing attribute.
				info = 0;
				info = (struct anu_tcp_info *)RTA_DATA(routeAttributes);
				//info = (struct tcp_info *)RTA_DATA(routeAttributes);
				// the mothership of tcp statistics.
				netlinkEvent->tcpi_segs_in = info->tcpi_segs_in;
				netlinkEvent->rx_b = info->tcpi_bytes_received;
				netlinkEvent->tcpi_segs_out = info->tcpi_segs_out;
				netlinkEvent->tx_b = info->tcpi_bytes_sent;	// this is the problem leaf.
				ok++;
			}
			routeAttributes = RTA_NEXT(routeAttributes, rtalen);
		}

	}

 EndofRunWay:

	if (ok) {
		// the order of these two actions is important. 

		// add the Ptr to the Map:
		pthread_mutex_lock(&mapMu);
		PtrMap[netlinkEvent] = up;
		pthread_mutex_unlock(&mapMu);

		// accept this event
		pthread_mutex_lock(&mtx);
		eventDeque.push_back(netlinkEvent);
		pthread_mutex_unlock(&mtx);
		pthread_cond_signal(&cond);
	} else {
		delete(netlinkEvent);
	}
	return;
}

void printEvent(struct event_t *ourEvent) {
	printf("   -> PID       : %u\n", ourEvent->pid);
	printf("   -> UID       : %u\n", ourEvent->UserId);
	printf("   -> SPT       : %u\n", ourEvent->SPT);
	printf("   -> DPT       : %u\n", ourEvent->DPT);
	printf("   -> TX_BYTES  : %ld\n", ourEvent->tx_b);
	printf("   -> RX_BYTES  : %ld\n", ourEvent->rx_b);
	printf("   -> EPOCHNS   : %ld\n", ourEvent->EventTime);
	printf("   -> RX_PACKETS: %u\n", ourEvent->tcpi_segs_in);
	printf("   -> TX_PACKETS: %u\n", ourEvent->tcpi_segs_out);
	printf("   -> Command   : %s\n", ourEvent->task);
}

int readCmdLine(uint32_t pid, char *writeTo, int maxLen) {
	if (!pid) {
		return -1;
	}
	if (maxLen > MAX) {
		fprintf(stderr, "[%s] maxLen %u larger than MAX: %u\n", __func__, maxLen, MAX);
		return -1;
	}

	char cmdLine[MAX] = { 0 };
	snprintf(cmdLine, 128, "/proc/%u/cmdline", pid);
	//printf("Opening: %s\n", cmdLine);
	FILE *fp = fopen(cmdLine, "r");
	if (!fp) {
		perror("fopen");
		return -1;
	}
	int weRead = fread(writeTo, maxLen, 1, fp);
	fclose(fp);
	return weRead;
}

// max len: BUF
// RETURN VALUE: Success: >= 1. Failure: 0.
int findNthWord(char *line_in, int n, char *word, char *delim) {

	// since we decay, copy the incoming to another buffer
	char line[BUF * 2] = { 0 };
	memcpy(line, line_in, strnlen(line_in, BUF));

	int hits = 0;
	int i = 0;
	int _len = 0;

	char *LinePtr = strtok(line, delim);
	while (LinePtr) {
		_len = strnlen(LinePtr, BUF - 1);
		if (i == n) {
			strncpy(word, LinePtr, _len + 1);
			hits++;
			break;
		}

		i++;
		LinePtr = strtok(0, delim);
	}

	return hits;
}
