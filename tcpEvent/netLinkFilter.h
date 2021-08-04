#pragma once
#ifndef NETLINKFILTER_H
#define NETLINKFILTER_H

#define NETLINKFILTER_VER "1.03a"

#define SUPPRESS 0
#define PROCESS 1
#define WONKY -1 
#define MAXKEYLEN 1024
#define ADDRLEN 128
#define RESET_COUNT 300

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
		// SPT:DPT:saddr:daddr | incomingVal

		char key[MAXKEYLEN] = { };
		snprintf(key, MAXKEYLEN, "%d:%d:%s:%s", eventPtr->SPT, eventPtr->DPT, saddr, daddr);

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
		pthread_rwlock_wrlock(&lock);

		if (lookupCount > RESET_COUNT){
			printf("[%s] Resetting nfMap\n", __func__);
			nfMap.clear();
			lookupCount = 0;
		} else {
			lookupCount++;
		}

		nfMap[keyString] = incomingVal;
		pthread_rwlock_unlock(&lock);
		printf("[%s] new event: %s:%ld\n", __func__, key, value);
		return PROCESS;
	}

 private:
	pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
	std::map < std::string, uint64_t > nfMap;
	unsigned lookupCount = 0;
};

#endif
