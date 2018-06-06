/**
 * @file src/bin2llvmir/optimizations/syscalls/x86.cpp
 * @brief Implement x86 syscall identification and fixing pass @c SyscallFixer.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/IR/Constants.h>

#include "retdec/bin2llvmir/optimizations/syscalls/syscalls.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"

using namespace llvm;

/**
 * From /usr/include/asm/unistd_32.h
 * Note: x86 and x86_64 have different ABIs, therefore different syscall tables.
 * For x86_64 see /usr/include/asm/unistd_64.h.
 *
 * TODO: windows, 64-bit, Itanium, etc.:
 * https://w3challs.com/syscalls
 */
std::map<uint64_t, std::string> syscalls_x86_linux_32 =
{
	{0, "restart_syscall"},
	{1, "exit"},
	{2, "fork"},
	{3, "read"},
	{4, "write"},
	{5, "open"},
	{6, "close"},
	{7, "waitpid"},
	{8, "creat"},
	{9, "link"},
	{10, "unlink"},
	{11, "execve"},
	{12, "chdir"},
	{13, "time"},
	{14, "mknod"},
	{15, "chmod"},
	{16, "lchown"},
	{17, "break"},
	{18, "oldstat"},
	{19, "lseek"},
	{20, "getpid"},
	{21, "mount"},
	{22, "umount"},
	{23, "setuid"},
	{24, "getuid"},
	{25, "stime"},
	{26, "ptrace"},
	{27, "alarm"},
	{28, "oldfstat"},
	{29, "pause"},
	{30, "utime"},
	{31, "stty"},
	{32, "gtty"},
	{33, "access"},
	{34, "nice"},
	{35, "ftime"},
	{36, "sync"},
	{37, "kill"},
	{38, "rename"},
	{39, "mkdir"},
	{40, "rmdir"},
	{41, "dup"},
	{42, "pipe"},
	{43, "times"},
	{44, "prof"},
	{45, "brk"},
	{46, "setgid"},
	{47, "getgid"},
	{48, "signal"},
	{49, "geteuid"},
	{50, "getegid"},
	{51, "acct"},
	{52, "umount2"},
	{53, "lock"},
	{54, "ioctl"},
	{55, "fcntl"},
	{56, "mpx"},
	{57, "setpgid"},
	{58, "ulimit"},
	{59, "oldolduname"},
	{60, "umask"},
	{61, "chroot"},
	{62, "ustat"},
	{63, "dup2"},
	{64, "getppid"},
	{65, "getpgrp"},
	{66, "setsid"},
	{67, "sigaction"},
	{68, "sgetmask"},
	{69, "ssetmask"},
	{70, "setreuid"},
	{71, "setregid"},
	{72, "sigsuspend"},
	{73, "sigpending"},
	{74, "sethostname"},
	{75, "setrlimit"},
	{76, "getrlimit"},
	{77, "getrusage"},
	{78, "gettimeofday"},
	{79, "settimeofday"},
	{80, "getgroups"},
	{81, "setgroups"},
	{82, "select"},
	{83, "symlink"},
	{84, "oldlstat"},
	{85, "readlink"},
	{86, "uselib"},
	{87, "swapon"},
	{88, "reboot"},
	{89, "readdir"},
	{90, "mmap"},
	{91, "munmap"},
	{92, "truncate"},
	{93, "ftruncate"},
	{94, "fchmod"},
	{95, "fchown"},
	{96, "getpriority"},
	{97, "setpriority"},
	{98, "profil"},
	{99, "statfs"},
	{100, "fstatfs"},
	{101, "ioperm"},
	{102, "socketcall"},
	{103, "syslog"},
	{104, "setitimer"},
	{105, "getitimer"},
	{106, "stat"},
	{107, "lstat"},
	{108, "fstat"},
	{109, "olduname"},
	{110, "iopl"},
	{111, "vhangup"},
	{112, "idle"},
	{113, "vm86old"},
	{114, "wait4"},
	{115, "swapoff"},
	{116, "sysinfo"},
	{117, "ipc"},
	{118, "fsync"},
	{119, "sigreturn"},
	{120, "clone"},
	{121, "setdomainname"},
	{122, "uname"},
	{123, "modify_ldt"},
	{124, "adjtimex"},
	{125, "mprotect"},
	{126, "sigprocmask"},
	{127, "create_module"},
	{128, "init_module"},
	{129, "delete_module"},
	{130, "get_kernel_syms"},
	{131, "quotactl"},
	{132, "getpgid"},
	{133, "fchdir"},
	{134, "bdflush"},
	{135, "sysfs"},
	{136, "personality"},
	{137, "afs_syscall"},
	{138, "setfsuid"},
	{139, "setfsgid"},
	{140, "_llseek"},
	{141, "getdents"},
	{142, "_newselect"},
	{143, "flock"},
	{144, "msync"},
	{145, "readv"},
	{146, "writev"},
	{147, "getsid"},
	{148, "fdatasync"},
	{149, "_sysctl"},
	{150, "mlock"},
	{151, "munlock"},
	{152, "mlockall"},
	{153, "munlockall"},
	{154, "sched_setparam"},
	{155, "sched_getparam"},
	{156, "sched_setscheduler"},
	{157, "sched_getscheduler"},
	{158, "sched_yield"},
	{159, "sched_get_priority_max"},
	{160, "sched_get_priority_min"},
	{161, "sched_rr_get_interval"},
	{162, "nanosleep"},
	{163, "mremap"},
	{164, "setresuid"},
	{165, "getresuid"},
	{166, "vm86"},
	{167, "query_module"},
	{168, "poll"},
	{169, "nfsservctl"},
	{170, "setresgid"},
	{171, "getresgid"},
	{172, "prctl"},
	{173, "sigreturn"}, // rt_sigreturn
	{174, "sigaction"}, // rt_sigaction
	{175, "sigprocmask"}, // rt_sigprocmask
	{176, "sigpending"}, // rt_sigpending
	{177, "sigtimedwait"}, // rt_sigtimedwait
	{178, "sigqueueinfo"}, // rt_sigqueueinfo
	{179, "sigsuspend"}, // rt_sigsuspend
	{180, "pread64"},
	{181, "pwrite64"},
	{182, "chown"},
	{183, "getcwd"},
	{184, "capget"},
	{185, "capset"},
	{186, "sigaltstack"},
	{187, "sendfile"},
	{188, "getpmsg"},
	{189, "putpmsg"},
	{190, "vfork"},
	{191, "ugetrlimit"},
	{192, "mmap2"},
	{193, "truncate64"},
	{194, "ftruncate64"},
	{195, "stat64"},
	{196, "lstat64"},
	{197, "fstat64"},
	{198, "lchown32"},
	{199, "getuid32"},
	{200, "getgid32"},
	{201, "geteuid32"},
	{202, "getegid32"},
	{203, "setreuid32"},
	{204, "setregid32"},
	{205, "getgroups32"},
	{206, "setgroups32"},
	{207, "fchown32"},
	{208, "setresuid32"},
	{209, "getresuid32"},
	{210, "setresgid32"},
	{211, "getresgid32"},
	{212, "chown32"},
	{213, "setuid32"},
	{214, "setgid32"},
	{215, "setfsuid32"},
	{216, "setfsgid32"},
	{217, "pivot_root"},
	{218, "mincore"},
	{219, "madvise"},
	{220, "getdents64"},
	{221, "fcntl64"},
	{224, "gettid"},
	{225, "readahead"},
	{226, "setxattr"},
	{227, "lsetxattr"},
	{228, "fsetxattr"},
	{229, "getxattr"},
	{230, "lgetxattr"},
	{231, "fgetxattr"},
	{232, "listxattr"},
	{233, "llistxattr"},
	{234, "flistxattr"},
	{235, "removexattr"},
	{236, "lremovexattr"},
	{237, "fremovexattr"},
	{238, "tkill"},
	{239, "sendfile64"},
	{240, "futex"},
	{241, "sched_setaffinity"},
	{242, "sched_getaffinity"},
	{243, "set_thread_area"},
	{244, "get_thread_area"},
	{245, "io_setup"},
	{246, "io_destroy"},
	{247, "io_getevents"},
	{248, "io_submit"},
	{249, "io_cancel"},
	{250, "fadvise64"},
	{252, "exit_group"},
	{253, "lookup_dcookie"},
	{254, "epoll_create"},
	{255, "epoll_ctl"},
	{256, "epoll_wait"},
	{257, "remap_file_pages"},
	{258, "set_tid_address"},
	{259, "timer_create"},
	{260, "timer_settime"},
	{261, "timer_gettime"},
	{262, "timer_getoverrun"},
	{263, "timer_delete"},
	{264, "clock_settime"},
	{265, "clock_gettime"},
	{266, "clock_getres"},
	{267, "clock_nanosleep"},
	{268, "statfs64"},
	{269, "fstatfs64"},
	{270, "tgkill"},
	{271, "utimes"},
	{272, "fadvise64_64"},
	{273, "vserver"},
	{274, "mbind"},
	{275, "get_mempolicy"},
	{276, "set_mempolicy"},
	{277, "mq_open"},
	{278, "mq_unlink"},
	{279, "mq_timedsend"},
	{280, "mq_timedreceive"},
	{281, "mq_notify"},
	{282, "mq_getsetattr"},
	{283, "kexec_load"},
	{284, "waitid"},
	{286, "add_key"},
	{287, "request_key"},
	{288, "keyctl"},
	{289, "ioprio_set"},
	{290, "ioprio_get"},
	{291, "inotify_init"},
	{292, "inotify_add_watch"},
	{293, "inotify_rm_watch"},
	{294, "migrate_pages"},
	{295, "openat"},
	{296, "mkdirat"},
	{297, "mknodat"},
	{298, "fchownat"},
	{299, "futimesat"},
	{300, "fstatat64"},
	{301, "unlinkat"},
	{302, "renameat"},
	{303, "linkat"},
	{304, "symlinkat"},
	{305, "readlinkat"},
	{306, "fchmodat"},
	{307, "faccessat"},
	{308, "pselect6"},
	{309, "ppoll"},
	{310, "unshare"},
	{311, "set_robust_list"},
	{312, "get_robust_list"},
	{313, "splice"},
	{314, "sync_file_range"},
	{315, "tee"},
	{316, "vmsplice"},
	{317, "move_pages"},
	{318, "getcpu"},
	{319, "epoll_pwait"},
	{320, "utimensat"},
	{321, "signalfd"},
	{322, "timerfd_create"},
	{323, "eventfd"},
	{324, "fallocate"},
	{325, "timerfd_settime"},
	{326, "timerfd_gettime"},
	{327, "signalfd4"},
	{328, "eventfd2"},
	{329, "epoll_create1"},
	{330, "dup3"},
	{331, "pipe2"},
	{332, "inotify_init1"},
	{333, "preadv"},
	{334, "pwritev"},
	{335, "tgsigqueueinfo"}, // rt_tgsigqueueinfo
	{336, "perf_event_open"},
	{337, "recvmmsg"},
	{338, "fanotify_init"},
	{339, "fanotify_mark"},
	{340, "prlimit64"},
	{341, "name_to_handle_at"},
	{342, "open_by_handle_at"},
	{343, "clock_adjtime"},
	{344, "syncfs"},
	{345, "sendmmsg"},
	{346, "setns"},
	{347, "process_vm_readv"},
	{348, "process_vm_writev"},
	{349, "kcmp"},
	{350, "finit_module"},
	{351, "sched_setattr"},
	{352, "sched_getattr"},
	{353, "renameat2"},
	{354, "seccomp"},
	{355, "getrandom"},
	{356, "memfd_create"},
	{357, "bpf"},
	{358, "execveat"},
	{359, "socket"},
	{360, "socketpair"},
	{361, "bind"},
	{362, "connect"},
	{363, "listen"},
	{364, "accept4"},
	{365, "getsockopt"},
	{366, "setsockopt"},
	{367, "getsockname"},
	{368, "getpeername"},
	{369, "sendto"},
	{370, "sendmsg"},
	{371, "recvfrom"},
	{372, "recvmsg"},
	{373, "shutdown"},
	{374, "userfaultfd"},
	{375, "membarrier"},
	{376, "mlock2"},
	{377, "copy_file_range"},
	{378, "preadv2"},
	{379, "pwritev2"}
};

/**
 * From: /usr/include/linux/net.h
 */
std::map<uint64_t, std::string> x86SocketSyscalls =
{
	{1, "socket"}, // SYS_SOCKET -- sys_socket(2)
	{2, "bind"}, // SYS_BIND -- sys_bind(2)
	{3, "connect"}, // SYS_CONNECT -- sys_connect(2)
	{4, "listen"}, // SYS_LISTEN -- sys_listen(2)
	{5, "accept"}, // SYS_ACCEPT -- sys_accept(2)
	{6, "getsockname"}, // SYS_GETSOCKNAME -- sys_getsockname(2)
	{7, "getpeername"}, // SYS_GETPEERNAME -- sys_getpeername(2)
	{8, "socketpair"}, // SYS_SOCKETPAIR -- sys_socketpair(2)
	{9, "send"}, // SYS_SEND -- sys_send(2)
	{10, "recv"}, // SYS_RECV -- sys_recv(2)
	{11, "sendto"}, // SYS_SENDTO -- sys_sendto(2)
	{12, "recvfrom"}, // SYS_RECVFROM -- sys_recvfrom(2)
	{13, "shutdown"}, // SYS_SHUTDOWN -- sys_shutdown(2)
	{14, "setsockopt"}, // SYS_SETSOCKOPT -- sys_setsockopt(2)
	{15, "getsockopt"}, // SYS_GETSOCKOPT -- sys_getsockopt(2)
	{16, "sendmsg"}, // SYS_SENDMSG -- sys_sendmsg(2)
	{17, "recvmsg"}, // SYS_RECVMSG -- sys_recvmsg(2)
	{18, "accept4"}, // SYS_ACCEPT4 -- sys_accept4(2)
	{19, "recvmmsg"}, // SYS_RECVMMSG -- sys_recvmmsg(2)
	{20, "sendmmsg"} // SYS_SENDMMSG -- sys_sendmmsg(2)
};

namespace retdec {
namespace bin2llvmir {

bool SyscallFixer::runX86()
{
	if (_config->getConfig().fileFormat.isElf32())
	{
		return runX86_linux_32();
	}

	return false;
}

bool SyscallFixer::runX86_linux_32()
{
	bool changed = false;
	for (Function& F : *_module)
	{
		for (auto ai = AsmInstruction(&F); ai.isValid(); ai = ai.getNext())
		{
			changed |= runX86_linux_32(ai);
		}
	}
	return changed;
}

/**
 * TODO: X86_INS_SYSCALL???
 * https://www.felixcloutier.com/x86/SYSCALL.html
 */
bool SyscallFixer::runX86_linux_32(AsmInstruction ai)
{
	auto* x86Asm = ai.getCapstoneInsn();
	if (x86Asm == nullptr || x86Asm->id != X86_INS_INT)
	{
		return false;
	}

	// Find interupt ID.
	//
	auto& detail = x86Asm->detail->x86;
	if (detail.op_count != 1
			|| detail.operands[0].type != X86_OP_IMM
			|| detail.operands[0].imm != 0x80)
	{
		LOG << "\tbad interupt id" << std::endl;
		return false;
	}
	LOG << "x86 syscall @ " << ai.getAddress() << std::endl;

	// Find syscall ID.
	//
	auto* syscallIdReg = _abi->getSyscallIdRegister();
	StoreInst* store = nullptr;
	Instruction* it = ai.getLlvmToAsmInstruction()->getPrevNode();
	for (; it != nullptr; it = it->getPrevNode())
	{
		if (auto* s = dyn_cast<StoreInst>(it))
		{
			if (s->getPointerOperand() == syscallIdReg)
			{
				store = s;
				break;
			}
		}
	}
	if (store == nullptr || !isa<ConstantInt>(store->getValueOperand()))
	{
		LOG << "\tsyscall code not found" << std::endl;
		return false;
	}
	uint64_t code = cast<ConstantInt>(store->getValueOperand())->getZExtValue();
	LOG << "\tcode instruction: " << llvmObjToString(store) << std::endl;
	LOG << "\tcode : " << std::dec << code << std::endl;

	return transform(ai, code, syscalls_x86_linux_32);
}

} // namespace bin2llvmir
} // namespace retdec
