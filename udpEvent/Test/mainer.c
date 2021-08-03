// Anu Mathew <anmathew@microsoft.com> 

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>

#define SOFILE "/opt/RealTimeKql/lib/libudpEvent.so"
#define VERSION "udp mainer ver 1.03b"

#include "../common.h"

// prototypes for mainer:
void printEvent(struct udp_event_t *event);
void signalHandler(int signum);
void (*cleanup)();

// global
void *handle = 0;

int main() {
	printf("%s PID: %d\n", VERSION, getpid());
        printf("dlopen: %s\n", SOFILE);
	handle = dlopen(SOFILE, RTLD_LAZY);
	if (handle) {
		puts("dlopen OK!");
	} else {
		fprintf(stderr, "Failed dlopen\n");
		exit(EXIT_FAILURE);
	}

	dlerror();		/* Clear any existing error */
	void (*AddProbe)() = dlsym(handle, "AddProbe");
	char *err = dlerror();
	if (err) {
		fprintf(stderr, "%s\n", err);
		exit(EXIT_FAILURE);
	}

	dlerror();		/* Clear any existing error */
	struct udp_event_t (*DequeuePerfEvent) () = dlsym(handle, "DequeuePerfEvent");
	err = dlerror();
	if (err) {
		fprintf(stderr, "%s\n", err);
		exit(EXIT_FAILURE);
	}

	dlerror();		/* Clear any existing error */
	cleanup = dlsym(handle, "cleanup");
	err = dlerror();
	if (err) {
		fprintf(stderr, "%s\n", err);
		exit(EXIT_FAILURE);
	}

        dlerror();              /* Clear any existing error */
	unsigned (*getStatus)() = dlsym(handle, "getStatus");
        err = dlerror();
        if (err) {
                fprintf(stderr, "%s (err resolving symbol getStatus)\n", err);
                exit(EXIT_FAILURE);
        }

	signal(SIGINT, signalHandler);

	puts("About to AddProbe");
	AddProbe();
	puts("AddProbe done!");

	while(!getStatus()){
		puts("Waiting on getStatus()..");
		sleep(1);
	}

	struct udp_event_t mainerEvent = {0};
	while (1) {
		mainerEvent = DequeuePerfEvent();
		printEvent(&mainerEvent);
	}

}

void signalHandler(int signum) {
	printf("Interrupted by signal %u by %s\n", signum, __FILE__);
	cleanup();
	if (dlclose(handle)){
		puts("error closing dlhandle, but that's ok as we are on our way out!");
	}
	printf("Exit %d called by %s\n", signum, __FILE__);
	exit(signum);
}

void printEvent(struct udp_event_t *event) {
	if (!event) {
		return;
	}
	puts("                ---               ");
	printf(" ---> In main, DEQD at %p\n", event);
	printf(" ---> PID: %d\n", event->pid);
	printf(" ---> UID: %d\n", event->UserId);
	printf(" ---> family: %d\n", event->family);
	printf(" ---> rx_b: %lu\n", event->rx_b);
	printf(" ---> tx_b: %lu\n", event->tx_b);
	printf(" ---> rxPkts: %u\n", event->rxPkts);
	printf(" ---> txPkts: %u\n", event->txPkts);
	printf(" ---> Command: %s\n", event->task);
	printf(" ---> SADDR: %s\n", event->SADDR);
	printf(" ---> DADDR: %s\n", event->DADDR);
	printf(" ---> SPT: %d\n", event->SPT);
	printf(" ---> DPT: %d\n", event->DPT);
	printf(" ---> EventTime: %ld\n", event->EventTime);
	puts("                ---               ");
}
