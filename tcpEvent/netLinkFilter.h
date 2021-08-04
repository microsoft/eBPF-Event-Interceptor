#pragma once
#ifndef NETLINKFILTER_H
#define NETLINKFILTER_H

#define NETLINKFILTER_VER "1.03b"

#define SUPPRESS 0
#define PROCESS 1
#define WONKY -1 
#define MAXKEYLEN 1024
#define ADDRLEN 128
#define NF_MAP_MAXLEN 300

struct nlfStruct {

	int checkEvent(event_t * eventPtr) {
		if (!eventPtr) {
			return WONKY;
		}

		char saddr[ADDRLEN] = { };
		char daddr[ADDRLEN] = { };

		switch (eventPtr->family) {
		case AF_INET:
			inet_ntop(AF_INET, (struct in_addr *)&(eventPtr->saddr), saddr, sizeof(saddr));
			inet_ntop(AF_INET, (struct in_addr *)&(eventPtr->daddr), daddr, sizeof(daddr));
			break;
		case AF_INET6:
			inet_ntop(AF_INET6, (struct in_addr6 *)&(eventPtr->saddr), saddr, sizeof(saddr));
			inet_ntop(AF_INET6, (struct in_addr6 *)&(eventPtr->daddr), daddr, sizeof(daddr));
			break;
		default:
			fprintf(stderr, "Unknown inet family: %d\n", eventPtr->family);
			return WONKY;	// we cannot deal with this.
		}

		// presently: 
		uint64_t incomingVal = eventPtr->rx_b + eventPtr->tx_b + eventPtr->tcpi_segs_out + eventPtr->tcpi_segs_in;

		// lhs | rhs 
		// SPT:DPT:saddr:daddr:pid | incomingVal

		char key[MAXKEYLEN] = { };
		snprintf(key, MAXKEYLEN, "%d:%d:%s:%s:[%d]", eventPtr->SPT, eventPtr->DPT, saddr, daddr, eventPtr->pid);

		auto keyString = std::string(key);

		pthread_rwlock_rdlock(&lock);
		auto found = nfMap.count(keyString);
		uint64_t value = found ? nfMap[keyString] : 0;
		pthread_rwlock_unlock(&lock);

		if (found && value == incomingVal) {
			printf("[%s] stale event: %s:%ld\n", __func__, key, value);
			return SUPPRESS;
		} 

		// still here? that means: new event, or a previously known event sparkling with new activity:

		int x = 0;

		pthread_rwlock_wrlock(&lock);
		// check the Map from growing too big:
		if (nfMap.size() > NF_MAP_MAXLEN){
			x++;
			nfMap.clear();
		}
		nfMap[keyString] = incomingVal;
		pthread_rwlock_unlock(&lock);
		
		if (x){
			printf("[%s] NF_MAP_MAXLEN: emptying nfMap\n", __func__);
		}
			
		printf("[%s] new event: %s:%ld\n", __func__, key, value);
		return PROCESS;
	}

 private:
	pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
	std::map < std::string, uint64_t > nfMap;
};

#endif
