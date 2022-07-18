// +build ignore

#define DEBUG_LOG

#include "my_def.h"
#include <stdbool.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16
#define MAX_ENVENT 256
#define LOG_ENTRY_SIZE (64 - 5)

// 全局变量存到map中
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 10);
	__type(key, __u32);   // global_id
	__type(value, __u64); // packet count
} global_var_kv SEC(".maps");

static __inline void save_global_val(u32 key, u64 val) {
	bpf_map_update_elem(&global_var_kv, &key, &val, 0);
}

static __inline int fetch_global_int(u32 key) {
	int val;
	void* ptr = bpf_map_lookup_elem(&global_var_kv, &key);
	bpf_probe_read(&val, sizeof(val), ptr);
	return val;
}

enum GlobalKey {
	GLOBAL_TICK1 = 0,
	GLOBAL_RINGBUFFER_WRITE,
	GLOBAL_RINGBUFFER_ROUND,
	GLOBAL_PROC,
};

enum EventId {
	EVENT_LOG = 0,
};


// Force emitting struct event into the ELF.
struct event_comm {
	u32 val;
	u8 log[LOG_ENTRY_SIZE];
	u8 event_id;
};
const struct event_comm *unused __attribute__((unused));

// 持续的收集log
struct bpf_map_def SEC("maps") events_rb = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct event_comm),
	.max_entries = MAX_ENVENT,
};


static __inline void send_event(const struct event_comm *event) {
	int write_index = fetch_global_int(GLOBAL_RINGBUFFER_WRITE);
	bpf_map_update_elem(&events_rb, &write_index, event, 0);

	// update key
	u32 next_key = write_index + 1;
	if (next_key >= MAX_ENVENT) {
		int round = fetch_global_int(GLOBAL_RINGBUFFER_ROUND) + 1;
		save_global_val(GLOBAL_RINGBUFFER_ROUND, round);
		next_key = 0;
	}
	save_global_val(GLOBAL_RINGBUFFER_WRITE, next_key);
}

static __inline void send_event_log(int eid, int val, const char *log) {
	// 同一log只上传一次
	int last = fetch_global_int(GLOBAL_RINGBUFFER_WRITE) - 1;
	if (last >= 0) {
		struct event_comm *event = (struct event_comm *) bpf_map_lookup_elem(&events_rb, &last);
		if (event != NULL) {
			if (event->val == val && memcmp(event->log, log, LOG_ENTRY_SIZE) == 0) {
				// bpf_log("IGNORE--->%d %s\n", event->val, event->log);
				return;
			} else {
				// bpf_log("ADD--->%d %s\n", val, log);
			}
		}
	}

	struct event_comm event;
	event.event_id = eid;
	event.val = val;
	memcpy(event.log, log, LOG_ENTRY_SIZE);
	send_event(&event);
}

static __inline bool inore_process() {
	char comm[TASK_COMM_LEN] = {0};
	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_log("comm: %s\n", comm);
	// 只抓取bash进程
	// if (memcmp(comm, "sh", sizeof("sshd")) != 0
	// 	|| memcmp(comm, "bash", sizeof("bash")) != 0) {
	// 	return true;
	// }
	return false;
}


SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	if (inore_process()) return 0;
	char log[LOG_ENTRY_SIZE] = "sys_enter";
	send_event_log(EVENT_LOG, 2, log);
	return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
	if (inore_process()) return 0;
	char log[LOG_ENTRY_SIZE] = "sys_exit";
	send_event_log(EVENT_LOG, 2, log);
	return 0;
}