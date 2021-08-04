#pragma once
#ifndef NETLINKFILTER_H
#define NETLINKFILTER_H

struct nlfStruct {

	// return 0 if we know the exact state from before. this event must be suppressed.
	// return 1 if our state is stale. process this event. 
	// if wonky, return -1. 
	int checkEvent(event_t * eventPtr) {
		if (!eventPtr) {
			return -1;
		}

		char saddr[_ADDRLEN] = { };
		char daddr[_ADDRLEN] = { };

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
			return -1;	// we cannot deal with this.
		}

		// presently: 
		uint64_t incomingVal = eventPtr->rx_b + eventPtr->tx_b + eventPtr->tcpi_segs_out + eventPtr->tcpi_segs_in;

		// lhs | rhs 
		// SPT:DPT:saddr:daddr | incomingVal

		char key[_MAXKEYLEN] = { };
		snprintf(key, _MAXKEYLEN, "%d:%d:%s:%s", eventPtr->SPT, eventPtr->DPT, saddr, daddr);

		auto keyString = std::string(key);

		pthread_rwlock_rdlock(&lock);
		auto found = nfMap.count(keyString);
		uint64_t value = found ? nfMap[keyString] : 0;
		pthread_rwlock_unlock(&lock);

		if (found && value == incomingVal) {
			printf("[%s] stale event: %s:%ld\n", __func__, key, value);
			return 0;	// we have the exact state.
		} else {
			// new event, or known event with new activity:
			pthread_rwlock_wrlock(&lock);
			nfMap[keyString] = incomingVal;
			pthread_rwlock_unlock(&lock);
			printf("[%s] new event: %s:%ld\n", __func__, key, value);
			return 1;
		}

		return 1;	// we have not seen this before.
	}

 private:
	pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
	std::map < std::string, uint64_t > nfMap;
	const int _MAXKEYLEN = 8192;
	const int _ADDRLEN = 128;
};

#endif
