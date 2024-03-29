rm *_snoop
rm -rf *_log.txt

export BPF_CLANG=clang-13

compile_one() {
	flag=$1 
	bin=$2
	export BPF_CFLAGS=-D$flag
	go generate
	go build -o $bin
}


# go generate
# go build -o $APP
# sudo ./$APP

compile_one TRACE_ALL ebpf_snoop
compile_one TRACE_COMM comm_snoop
compile_one TRACE_OPENAT open_snoop
compile_one TRACE_EXECVE exec_snoop