/**
 * @file src/bin2llvmir/optimizations/syscalls/arm64.cpp
 * @brief Implement ARM64 syscall identification and fixing pass @c SyscallFixer.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/Constants.h>

#include "retdec/bin2llvmir/optimizations/syscalls/syscalls.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"

using namespace llvm;

//https://thog.github.io/syscalls-table-aarch64/latest.html
//https://github.com/hugsy/cemu/blob/master/cemu/syscalls/aarch64.csv
std::map<uint64_t, std::string> syscalls_arm64_linux_64 =
{
	{0x80, "restart_syscall"}, //0
	{0x5D, "exit"}, //1
	{0x3F, "read"}, //3
	{0x40, "write"}, //4
	{0x400, "open"}, //5
	{0x39, "close"}, //6
	{0x428, "creat"}, //8
	{0x401, "link"}, //9
	{0x402, "unlink"}, //10
	{0xDD, "execve"}, //11
	{0x31, "chdir"}, //12
	{0x403, "mknod"}, //14
	{0x404, "chmod"}, //15
	{0x421, "lseek"}, //19
	{0xAC, "getpid"}, //20
	{0x28, "mount"}, //21
	{0x434, "umount"}, //22
	{0x75, "ptrace"}, //26
	{0x409, "access"}, //33
	{0x51, "sync"}, //36
	{0x81, "kill"}, //37
	{0x40A, "rename"}, //38
	{0x406, "mkdir"}, //39
	{0x407, "rmdir"}, //40
	{0x17, "dup"}, //41
	{0x410, "pipe"}, //42
	{0x99, "times"}, //43
	{0xD6, "brk"}, //45
	{0x59, "acct"}, //51
	{0x27, "umount2"}, //52
	{0x1D, "ioctl"}, //54
	{0x41C, "fcntl"}, //55
	{0x9A, "setpgid"}, //57
	{0xA6, "umask"}, //60
	{0x33, "chroot"}, //61
	{0x42E, "ustat"}, //62
	{0x411, "dup2"}, //63
	{0xAD, "getppid"}, //64
	{0x9D, "setsid"}, //66
	{0xA1, "sethostname"}, //74
	{0xA4, "setrlimit"}, //75
	{0xA5, "getrusage"}, //77
	{0xA9, "gettimeofday"}, //78
	{0xAA, "settimeofday"}, //79
	{0x40C, "symlink"}, //83
	{0x40B, "readlink"}, //85
	{0x435, "uselib"}, //86
	{0xE0, "swapon"}, //87
	{0x8E, "reboot"}, //88
	{0xD7, "munmap"}, //91
	{0x418, "truncate"}, //92
	{0x417, "ftruncate"}, //93
	{0x34, "fchmod"}, //94
	{0x8D, "getpriority"}, //96
	{0x8C, "setpriority"}, //97
	{0x420, "statfs"}, //99
	{0x41F, "fstatfs"}, //100
	{0x74, "syslog"}, //103
	{0x67, "setitimer"}, //104
	{0x66, "getitimer"}, //105
	{0x419, "stat"}, //106
	{0x41A, "lstat"}, //107
	{0x41B, "fstat"}, //108
	{0x3A, "vhangup"}, //111
	{0x104, "wait4"}, //114
	{0xE1, "swapoff"}, //115
	{0xB3, "sysinfo"}, //116
	{0x52, "fsync"}, //118
	{0xDC, "clone"}, //120
	{0xA2, "setdomainname"}, //121
	{0xA0, "uname"}, //122
	{0xAB, "adjtimex"}, //124
	{0xE2, "mprotect"}, //125
	{0x69, "init_module"}, //128
	{0x6A, "delete_module"}, //129
	{0x3C, "quotactl"}, //131
	{0x9B, "getpgid"}, //132
	{0x32, "fchdir"}, //133
	{0x433, "bdflush"}, //134
	{0x5C, "personality"}, //136
	{0x3E, "_llseek"}, //140
	{0x20, "flock"}, //143
	{0xE3, "msync"}, //144
	{0x41, "readv"}, //145
	{0x42, "writev"}, //146
	{0x9C, "getsid"}, //147
	{0x53, "fdatasync"}, //148
	{0x436, "_sysctl"}, //149
	{0xE4, "mlock"}, //150
	{0xE5, "munlock"}, //151
	{0xE6, "mlockall"}, //152
	{0xE7, "munlockall"}, //153
	{0x76, "sched_setparam"}, //154
	{0x79, "sched_getparam"}, //155
	{0x77, "sched_setscheduler"}, //156
	{0x78, "sched_getscheduler"}, //157
	{0x7C, "sched_yield"}, //158
	{0x7D, "sched_get_priority_max"}, //159
	{0x7E, "sched_get_priority_min"}, //160
	{0x65, "nanosleep"}, //162
	{0xD8, "mremap"}, //163
	{0x42C, "poll"}, //168
	{0xA7, "prctl"}, //172
	{0x86, "rt_sigaction"}, //174
	{0x87, "rt_sigprocmask"}, //175
	{0x88, "rt_sigpending"}, //176
	{0x85, "rt_sigsuspend"}, //179
	{0x43, "pread64"}, //180
	{0x44, "pwrite64"}, //181
	{0x11, "getcwd"}, //183
	{0x5A, "capget"}, //184
	{0x5B, "capset"}, //185
	{0x84, "sigaltstack"}, //186
	{0x416, "sendfile"}, //187
	{0x42F, "vfork"}, //190
	{0xA3, "ugetrlimit"}, //191
	{0x40E, "stat64"}, //195
	{0x40F, "lstat64"}, //196
	{0x50, "fstat64"}, //197
	{0x408, "lchown32"}, //198
	{0xAE, "getuid32"}, //199
	{0xB0, "getgid32"}, //200
	{0xAF, "geteuid32"}, //201
	{0xB1, "getegid32"}, //202
	{0x91, "setreuid32"}, //203
	{0x8F, "setregid32"}, //204
	{0x9E, "getgroups32"}, //205
	{0x9F, "setgroups32"}, //206
	{0x37, "fchown32"}, //207
	{0x93, "setresuid32"}, //208
	{0x94, "getresuid32"}, //209
	{0x95, "setresgid32"}, //210
	{0x96, "getresgid32"}, //211
	{0x405, "chown32"}, //212
	{0x92, "setuid32"}, //213
	{0x90, "setgid32"}, //214
	{0x97, "setfsuid32"}, //215
	{0x98, "setfsgid32"}, //216
	{0x3D, "getdents64"}, //217
	{0x29, "pivot_root"}, //218
	{0xE8, "mincore"}, //219
	{0xE9, "madvise"}, //220
	{0xB2, "gettid"}, //224
	{0xD5, "readahead"}, //225
	{0x5, "setxattr"}, //226
	{0x6, "lsetxattr"}, //227
	{0x7, "fsetxattr"}, //228
	{0x8, "getxattr"}, //229
	{0x9, "lgetxattr"}, //230
	{0xA, "fgetxattr"}, //231
	{0xB, "listxattr"}, //232
	{0xC, "llistxattr"}, //233
	{0xD, "flistxattr"}, //234
	{0xE, "removexattr"}, //235
	{0xF, "lremovexattr"}, //236
	{0x10, "fremovexattr"}, //237
	{0x82, "tkill"}, //238
	{0x47, "sendfile64"}, //239
	{0x62, "futex"}, //240
	{0x0, "io_setup"}, //243
	{0x1, "io_destroy"}, //244
	{0x4, "io_getevents"}, //245
	{0x2, "io_submit"}, //246
	{0x3, "io_cancel"}, //247
	{0x5E, "exit_group"}, //248
	{0x12, "lookup_dcookie"}, //249
	{0x412, "epoll_create"}, //250
	{0x15, "epoll_ctl"}, //251
	{0x42D, "epoll_wait"}, //252
	{0xEA, "remap_file_pages"}, //253
	{0x60, "set_tid_address"}, //256
	{0x6B, "timer_create"}, //257
	{0x6E, "timer_settime"}, //258
	{0x6C, "timer_gettime"}, //259
	{0x6D, "timer_getoverrun"}, //260
	{0x6F, "timer_delete"}, //261
	{0x70, "clock_settime"}, //262
	{0x71, "clock_gettime"}, //263
	{0x72, "clock_getres"}, //264
	{0x83, "tgkill"}, //268
	{0x40D, "utimes"}, //269
	{0xB4, "mq_open"}, //274
	{0xB5, "mq_unlink"}, //275
	{0xB6, "mq_timedsend"}, //276
	{0xB8, "mq_notify"}, //278
	{0xB9, "mq_getsetattr"}, //279
	{0x5F, "waitid"}, //280
	{0xC6, "socket"}, //281
	{0xC8, "bind"}, //282
	{0xCB, "connect"}, //283
	{0xC9, "listen"}, //284
	{0xCA, "accept"}, //285
	{0xCC, "getsockname"}, //286
	{0xCD, "getpeername"}, //287
	{0xC7, "socketpair"}, //288
	{0x432, "send"}, //289
	{0xCE, "sendto"}, //290
	{0x431, "recv"}, //291
	{0xCF, "recvfrom"}, //292
	{0xD2, "shutdown"}, //293
	{0xD0, "setsockopt"}, //294
	{0xD1, "getsockopt"}, //295
	{0xD3, "sendmsg"}, //296
	{0xD4, "recvmsg"}, //297
	{0xC1, "semop"}, //298
	{0xBE, "semget"}, //299
	{0xBF, "semctl"}, //300
	{0xBD, "msgsnd"}, //301
	{0xBC, "msgrcv"}, //302
	{0xBA, "msgget"}, //303
	{0xBB, "msgctl"}, //304
	{0xC4, "shmat"}, //305
	{0xC5, "shmdt"}, //306
	{0xC2, "shmget"}, //307
	{0xC3, "shmctl"}, //308
	{0xD9, "add_key"}, //309
	{0xDA, "request_key"}, //310
	{0xDB, "keyctl"}, //311
	{0xC0, "semtimedop"}, //312
	{0x1E, "ioprio_set"}, //314
	{0x1F, "ioprio_get"}, //315
	{0x413, "inotify_init"}, //316
	{0x1B, "inotify_add_watch"}, //317
	{0x1C, "inotify_rm_watch"}, //318
	{0xEB, "mbind"}, //319
	{0xEC, "get_mempolicy"}, //320
	{0xED, "set_mempolicy"}, //321
	{0x38, "openat"}, //322
	{0x22, "mkdirat"}, //323
	{0x21, "mknodat"}, //324
	{0x36, "fchownat"}, //325
	{0x42A, "futimesat"}, //326
	{0x4F, "fstatat64"}, //327
	{0x23, "unlinkat"}, //328
	{0x26, "renameat"}, //329
	{0x25, "linkat"}, //330
	{0x24, "symlinkat"}, //331
	{0x4E, "readlinkat"}, //332
	{0x35, "fchmodat"}, //333
	{0x30, "faccessat"}, //334
	{0x48, "pselect6"}, //335
	{0x49, "ppoll"}, //336
	{0x61, "unshare"}, //337
	{0x4C, "splice"}, //340
	{0x4D, "tee"}, //342
	{0x4B, "vmsplice"}, //343
	{0xEF, "move_pages"}, //344
	{0xA8, "getcpu"}, //345
	{0x16, "epoll_pwait"}, //346
	{0x68, "kexec_load"}, //347
	{0x58, "utimensat"}, //348
	{0x415, "signalfd"}, //349
	{0x55, "timerfd_create"}, //350
	{0x414, "eventfd"}, //351
	{0x2F, "fallocate"}, //352
	{0x4A, "signalfd4"}, //355
	{0x13, "eventfd2"}, //356
	{0x14, "epoll_create1"}, //357
	{0x18, "dup3"}, //358
	{0x3B, "pipe2"}, //359
	{0x1A, "inotify_init1"}, //360
	{0x45, "preadv"}, //361
	{0x46, "pwritev"}, //362
	{0xF1, "perf_event_open"}, //364
	{0xF3, "recvmmsg"}, //365
	{0xF2, "accept4"}, //366
	{0x106, "fanotify_init"}, //367
	{0x107, "fanotify_mark"}, //368
	{0x105, "prlimit64"}, //369
	{0x108, "name_to_handle_at"}, //370
	{0x10A, "clock_adjtime"}, //372
	{0x10B, "syncfs"}, //373
	{0x10D, "sendmmsg"}, //374
	{0x10C, "setns"}, //375
	{0x110, "kcmp"}, //378
	{0x111, "finit_module"}, //379
	{0x112, "sched_setattr"}, //380
	{0x113, "sched_getattr"}, //381
	{0x114, "renameat2"}, //382
	{0x115, "seccomp"}, //383
	{0x116, "getrandom"}, //384
	{0x117, "memfd_create"}, //385
	{0x118, "bpf"}, //386
	{0x119, "execveat"}, //387
	{0x11A, "userfaultfd"}, //388
	{0x11B, "membarrier"}, //389
	{0x11C, "mlock2"}, //390
	{0x11D, "copy_file_range"}, //391
	{0x11E, "preadv2"}, //392
	{0x11F, "pwritev2"}, //393
	{0x120, "pkey_mprotect"}, //394
	{0x121, "pkey_alloc"}, //395
	{0x122, "pkey_free"}, //396
	{0x123, "statx"}, //397
};

namespace retdec {
namespace bin2llvmir {

bool SyscallFixer::runArm64()
{
	if (_config->getConfig().fileFormat.isElf64())
	{
		return runArm64_linux_64();
	}

	return false;
}

bool SyscallFixer::runArm64_linux_64()
{
	bool changed = false;
	for (Function& F : *_module)
	{
		for (auto ai = AsmInstruction(&F); ai.isValid(); ai = ai.getNext())
		{
			changed |= runArm64_linux_64(ai);
		}
	}
	return changed;
}

/**
|           0x00400180      200080d2       movz x0, 0x1                ; [02] -r-x section size 56 named .text
|           0x00400184      61010058       ldr x1, loc._d_2            ; "Hello, world!\n"
|           0x00400188      820280d2       movz x2, 0xe
|           0x0040018c      080880d2       movz x8, 0x40               ; '@'
|           ;-- syscall.io_setup:
|           0x00400190      010000d4       svc 0
\*/
bool SyscallFixer::runArm64_linux_64(AsmInstruction ai)
{
	auto* arm64Asm = ai.getCapstoneInsn();
	if (arm64Asm == nullptr || arm64Asm->id != ARM64_INS_SVC)
	{
		return false;
	}
	LOG << "ARM64 syscall @ " << ai.getAddress() << std::endl;

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

	return transform(ai, code, syscalls_arm64_linux_64);
}

} // namespace bin2llvmir
} // namespace retdec
