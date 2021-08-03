

// curated event that goes to the consumer.
#pragma pack(push, 1)
struct udp_event_t {
        uint16_t family;
        uint32_t pid;
        uint32_t UserId;
        uint64_t EventTime;
        uint16_t SPT;
        uint16_t DPT;
        char task[16];
        uint64_t rx_b;
        uint64_t tx_b;
	uint32_t rxPkts;
	uint32_t txPkts;
        char SADDR[64];
        char DADDR[64];
};
#pragma pack(pop)


// the struct we read from the perf map
#pragma pack(push, 1)
struct event_t {
        uint16_t family;
        uint32_t pid;
        uint32_t UserId;
        uint64_t EventTime;
        uint16_t SPT;
        uint16_t DPT;
        char task[16];
        unsigned __int128 saddr;
        unsigned __int128 daddr;
        uint64_t rx_b;
        uint64_t tx_b;
	uint32_t rxPkts;
	uint32_t txPkts;
	uintptr_t sockPtr;
};
#pragma pack(pop)



