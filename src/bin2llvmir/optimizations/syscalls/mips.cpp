/**
 * @file src/bin2llvmir/optimizations/syscalls/mips.cpp
 * @brief Implement MIPS syscall identification and fixing pass @c SyscallFixer.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/IR/Constants.h>

#include "retdec/bin2llvmir/optimizations/syscalls/syscalls.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"

using namespace llvm;

/*
 * Fill map from syscall codes to standard functions according to:
 *   http://www.rdos.net/svn/tags/V9.2.5/watcom/bld/clib/h/sysmips.h
 *   linux/mips/syscallent.h
 *
 * TODO: add all these:
 * https://w3challs.com/syscalls/?arch=mips_o32
 * https://w3challs.com/syscalls/?arch=mips_n32
 * https://w3challs.com/syscalls/?arch=mips_n64
 */
std::map<uint64_t, std::string> syscalls_mips_linux =
{
	{4001, "exit"},
	{4002, "fork"},
	{4003, "read"},
	{4004, "write"},
	{4005, "open"},
	{4006, "close"},
	{4007, "waitpid"},
	{4008, "creat"},
	{4009, "link"},
	{4010, "unlink"},
	{4011, "execve"},
	{4012, "chdir"},
	{4013, "time"},
	{4014, "knod"},
	{4015, "chmod"},
	{4016, "lchown"},
	{4017, "break"},
	{4018, "oldstat"},
	{4019, "lseek"},
	{4020, "getpid"},
	{4021, "mount"},
	{4022, "umount"},
	{4023, "setuid"},
	{4024, "getuid"},
	{4025, "stime"},
	{4026, "ptrace"},
	{4027, "alarm"},
	{4028, "oldfstat"},
	{4029, "pause"},
	{4030, "utime"},
	{4031, "stty"},
	{4032, "gtty"},
	{4033, "access"},
	{4034, "nice"},
	{4035, "ftime"},
	{4036, "sync"},
	{4037, "kill"},
	{4038, "rename"},
	{4039, "mkdir"},
	{4040, "rmdir"},
	{4041, "dup"},
	{4042, "pipe"},
	{4043, "times"},
	{4044, "prof"},
	{4045, "brk"},
	{4046, "setgid"},
	{4047, "getgid"},
	{4048, "signal"},
	{4049, "geteuid"},
	{4050, "getegid"},
	{4051, "acct"},
	{4052, "umount2"},
	{4053, "lock"},
	{4054, "ioctl"},
	{4055, "fcntl"},
	{4056, "mpx"},
	{4057, "setpgid"},
	{4058, "ulimit"},
	{4059, "oldolduname"},
	{4060, "umask"},
	{4061, "chroot"},
	{4062, "ustat"},
	{4063, "dup2"},
	{4064, "getppid"},
	{4065, "getpgrp"},
	{4066, "setsid"},
	{4067, "sigaction"},
	{4068, "sgetmask"},
	{4069, "ssetmask"},
	{4070, "setreuid"},
	{4071, "setregid"},
	{4072, "sigsuspend"},
	{4073, "sigpending"},
	{4074, "sethostname"},
	{4075, "setrlimit"},
	{4076, "getrlimit"},
	{4077, "getrusage"},
	{4078, "gettimeofday"},
	{4079, "settimeofday"},
	{4080, "getgroups"},
	{4081, "setgroups"},
	{4082, "select"},
	{4083, "symlink"},
	{4084, "oldlstat"},
	{4085, "readlink"},
	{4086, "uselib"},
	{4087, "swapon"},
	{4088, "reboot"},
	{4089, "readdir"},
	{4090, "mmap"},
	{4091, "munmap"},
	{4092, "truncate"},
	{4093, "ftruncate"},
	{4094, "fchmod"},
	{4095, "fchown"},
	{4096, "getpriority"},
	{4097, "setpriority"},
	{4098, "profil"},
	{4099, "statfs"},
	{4100, "fstatfs"},
	{4101, "ioperm"},
	{4102, "socketcall"},
	{4103, "syslog"},
	{4104, "setitimer"},
	{4105, "getitimer"},
	{4106, "stat"},
	{4107, "lstat"},
	{4108, "fstat"},
	{4109, "olduname"},
	{4110, "iopl"},
	{4111, "vhangup"},
	{4112, "idle"},
	{4113, "vfork"},
	{4114, "wait4"},
	{4115, "swapoff"},
	{4116, "sysinfo"},
	{4117, "ipc"},
	{4118, "fsync"},
	{4119, "sigreturn"},
	{4120, "clone"},
	{4121, "setdomainname"},
	{4122, "uname"},
	{4123, "modify_ldt"},
	{4124, "adjtimex"},
	{4125, "mprotect"},
	{4126, "sigprocmask"},
	{4127, "create_module"},
	{4128, "init_module"},
	{4129, "delete_module"},
	{4130, "get_kernel_syms"},
	{4131, "quotactl"},
	{4132, "getpgid"},
	{4133, "fchdir"},
	{4134, "bdflush"},
	{4135, "sysfs"},
	{4136, "personality"},
	{4137, "afs_syscall"},
	{4138, "setfsuid"},
	{4139, "setfsgid"},
	{4140, "_llseek"},
	{4141, "getdents"},
	{4142, "_newselect"},
	{4143, "flock"},
	{4144, "msync"},
	{4145, "readv"},
	{4146, "writev"},
	{4147, "cacheflush"},
	{4148, "cachectl"},
	{4149, "sysmips"},
	{4150, "unused150"},
	{4151, "getsid"},
	{4152, "fdatasync"},
	{4153, "_sysctl"},
	{4154, "mlock"},
	{4155, "munlock"},
	{4156, "mlockall"},
	{4157, "munlockall"},
	{4158, "sched_setparam"},
	{4159, "sched_getparam"},
	{4160, "sched_setscheduler"},
	{4161, "sched_getscheduler"},
	{4162, "sched_yield"},
	{4163, "sched_get_priority_max"},
	{4164, "sched_get_priority_min"},
	{4165, "sched_rr_get_interval"},
	{4166, "nanosleep"},
	{4167, "mremap"},
	{4168, "accept"},
	{4169, "bind"},
	{4170, "connect"},
	{4171, "getpeername"},
	{4172, "getsockname"},
	{4173, "getsockopt"},
	{4174, "listen"},
	{4175, "recv"},
	{4176, "recvfrom"},
	{4177, "recvmsg"},
	{4178, "send"},
	{4179, "sendmsg"},
	{4180, "sendto"},
	{4181, "setsockopt"},
	{4182, "shutdown"},
	{4183, "socket"},
	{4184, "socketpair"},
	{4185, "setresuid"},
	{4186, "getresuid"},
	{4187, "query_module"},
	{4188, "poll"},
	{4189, "nfsservctl"},
	{4190, "setresgid"},
	{4191, "getresgid"},
	{4192, "prctl"},
	{4193, "sigreturn"}, // rt_sigreturn
	{4194, "sigaction"}, // rt_sigaction
	{4195, "sigprocmask"}, // rt_sigprocmask
	{4196, "sigpending"}, // rt_sigpending
	{4197, "sigtimedwait"}, // rt_sigtimedwait
	{4198, "sigqueueinfo"}, // rt_sigqueueinfo
	{4199, "sigsuspend"}, // rt_sigsuspend
	{4200, "pread"},
	{4201, "pwrite"},
	{4202, "chown"},
	{4203, "getcwd"},
	{4204, "capget"},
	{4205, "capset"},
	{4206, "sigaltstack"},
	{4207, "sendfile"},
	{4208, "getpmsg"},
	{4209, "putpmsg"},

	{4264, "sys_clock_getres"},
};

namespace retdec {
namespace bin2llvmir {

bool SyscallFixer::runMips()
{
	if (_config->getConfig().fileFormat.isElf())
	{
		return runMips_linux();
	}

	return false;
}

bool SyscallFixer::runMips_linux()
{
	bool changed = false;
	for (Function& F : *_module)
	{
		for (auto ai = AsmInstruction(&F); ai.isValid(); ai = ai.getNext())
		{
			changed |= runMips_linux(ai);
		}
	}
	return changed;
}

bool SyscallFixer::runMips_linux(AsmInstruction ai)
{
	auto* mipsAsm = ai.getCapstoneInsn();
	if (mipsAsm == nullptr || mipsAsm->id != MIPS_INS_SYSCALL)
	{
		return false;
	}
	LOG << "MIPS syscall @ " << ai.getAddress() << std::endl;

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
	LOG << "\tcode: " << std::dec << code << std::endl;

	return transform(ai, code, syscalls_mips_linux);
}

} // namespace bin2llvmir
} // namespace retdec
