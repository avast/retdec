/**
* @file src/llvmir2hll/semantics/semantics/gcc_general_semantics/get_symbolic_names_for_param.cpp
* @brief Implementation of semantics::gcc_general::getSymbolicNamesForParam() for
*        GCCGeneralSemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/gcc_general_semantics/get_symbolic_names_for_param.h"
#include "retdec/llvmir2hll/semantics/semantics/impl_support/get_symbolic_names_for_param.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace gcc_general {

namespace {

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForSignals)
	// Info from: <sys/signal.h>
	symbolicNamesMap[1] = "SIGHUP";
	symbolicNamesMap[2] = "SIGINT";
	symbolicNamesMap[3] = "SIGQUIT";
	symbolicNamesMap[4] = "SIGILL";
	symbolicNamesMap[5] = "SIGTRAP";
	symbolicNamesMap[6] = "SIGABRT";
	symbolicNamesMap[7] = "SIGEMT";
	symbolicNamesMap[8] = "SIGFPE";
	symbolicNamesMap[9] = "SIGKILL";
	symbolicNamesMap[10] = "SIGBUS";
	symbolicNamesMap[11] = "SIGSEGV";
	symbolicNamesMap[12] = "SIGSYS";
	symbolicNamesMap[13] = "SIGPIPE";
	symbolicNamesMap[14] = "SIGALARM";
	symbolicNamesMap[15] = "SIGTERM";
	symbolicNamesMap[16] = "SIGURG";
	symbolicNamesMap[17] = "SIGSTOP";
	symbolicNamesMap[18] = "SIGTSTP";
	symbolicNamesMap[19] = "SIGCONT";
	symbolicNamesMap[20] = "SIGCHLD";
	symbolicNamesMap[21] = "SIGTTIN";
	symbolicNamesMap[22] = "SIGTTOU";
	symbolicNamesMap[23] = "SIGIO";
	symbolicNamesMap[24] = "SIGXCPU";
	symbolicNamesMap[25] = "SIGXFSZ";
	symbolicNamesMap[26] = "SIGVTALRM";
	symbolicNamesMap[27] = "SIGPROF";
	symbolicNamesMap[28] = "SIGWINCH";
	symbolicNamesMap[29] = "SIGINFO";
	symbolicNamesMap[30] = "SIGUSR1";
	symbolicNamesMap[31] = "SIGUSR2";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForSignalHandlers)
	// Info from: <sys/signal.h>
	symbolicNamesMap[0] = "SIG_DFL";
	symbolicNamesMap[1] = "SIG_IGN";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForErrors)
	// Info from: <asm-generic/errno-base.h>
	// Info from: <asm-generic/errno.h>
	symbolicNamesMap[1] = "EPERM";
	symbolicNamesMap[2] = "ENOENT";
	symbolicNamesMap[3] = "ESRCH";
	symbolicNamesMap[4] = "EINTR";
	symbolicNamesMap[5] = "EIO";
	symbolicNamesMap[6] = "ENXIO";
	symbolicNamesMap[7] = "E2BIG";
	symbolicNamesMap[8] = "ENOEXEC";
	symbolicNamesMap[9] = "EBADF";
	symbolicNamesMap[10] = "ECHILD";
	symbolicNamesMap[11] = "EAGAIN";
	// symbolicNamesMap[11] = "EWOULDBLOCK"; // synonym for EAGAIN
	symbolicNamesMap[12] = "ENOMEM";
	symbolicNamesMap[13] = "EACCES";
	symbolicNamesMap[14] = "EFAULT";
	symbolicNamesMap[15] = "ENOTBLK";
	symbolicNamesMap[16] = "EBUSY";
	symbolicNamesMap[17] = "EEXIST";
	symbolicNamesMap[18] = "EXDEV";
	symbolicNamesMap[19] = "ENODEV";
	symbolicNamesMap[20] = "ENOTDIR";
	symbolicNamesMap[21] = "EISDIR";
	symbolicNamesMap[22] = "EINVAL";
	symbolicNamesMap[23] = "ENFILE";
	symbolicNamesMap[24] = "EMFILE";
	symbolicNamesMap[25] = "ENOTTY";
	symbolicNamesMap[26] = "ETXTBSY";
	symbolicNamesMap[27] = "EFBIG";
	symbolicNamesMap[28] = "ENOSPC";
	symbolicNamesMap[29] = "ESPIPE";
	symbolicNamesMap[30] = "EROFS";
	symbolicNamesMap[31] = "EMLINK";
	symbolicNamesMap[32] = "EPIPE";
	symbolicNamesMap[33] = "EDOM";
	symbolicNamesMap[34] = "ERANGE";
	symbolicNamesMap[35] = "EDEADLK";
	// symbolicNamesMap[35] = "EDEADLOCK"; // synonym for EDEADLK
	symbolicNamesMap[36] = "ENAMETOOLONG";
	symbolicNamesMap[37] = "ENOLCK";
	symbolicNamesMap[38] = "ENOSYS";
	symbolicNamesMap[39] = "ENOTEMPTY";
	symbolicNamesMap[40] = "ELOOP";
	symbolicNamesMap[42] = "ENOMSG";
	symbolicNamesMap[43] = "EIDRM";
	symbolicNamesMap[44] = "ECHRNG";
	symbolicNamesMap[45] = "EL2NSYNC";
	symbolicNamesMap[46] = "EL3HLT";
	symbolicNamesMap[47] = "EL3RST";
	symbolicNamesMap[48] = "ELNRNG";
	symbolicNamesMap[49] = "EUNATCH";
	symbolicNamesMap[50] = "ENOCSI";
	symbolicNamesMap[51] = "EL2HLT";
	symbolicNamesMap[52] = "EBADE";
	symbolicNamesMap[53] = "EBADR";
	symbolicNamesMap[54] = "EXFULL";
	symbolicNamesMap[55] = "ENOANO";
	symbolicNamesMap[56] = "EBADRQC";
	symbolicNamesMap[57] = "EBADSLT";
	symbolicNamesMap[59] = "EBFONT";
	symbolicNamesMap[60] = "ENOSTR";
	symbolicNamesMap[61] = "ENODATA";
	symbolicNamesMap[62] = "ETIME";
	symbolicNamesMap[63] = "ENOSR";
	symbolicNamesMap[64] = "ENONET";
	symbolicNamesMap[65] = "ENOPKG";
	symbolicNamesMap[66] = "EREMOTE";
	symbolicNamesMap[67] = "ENOLINK";
	symbolicNamesMap[68] = "EADV";
	symbolicNamesMap[69] = "ESRMNT";
	symbolicNamesMap[70] = "ECOMM";
	symbolicNamesMap[71] = "EPROTO";
	symbolicNamesMap[72] = "EMULTIHOP";
	symbolicNamesMap[73] = "EDOTDOT";
	symbolicNamesMap[74] = "EBADMSG";
	symbolicNamesMap[75] = "EOVERFLOW";
	symbolicNamesMap[76] = "ENOTUNIQ";
	symbolicNamesMap[77] = "EBADFD";
	symbolicNamesMap[78] = "EREMCHG";
	symbolicNamesMap[79] = "ELIBACC";
	symbolicNamesMap[80] = "ELIBBAD";
	symbolicNamesMap[81] = "ELIBSCN";
	symbolicNamesMap[82] = "ELIBMAX";
	symbolicNamesMap[83] = "ELIBEXEC";
	symbolicNamesMap[84] = "EILSEQ";
	symbolicNamesMap[85] = "ERESTART";
	symbolicNamesMap[86] = "ESTRPIPE";
	symbolicNamesMap[87] = "EUSERS";
	symbolicNamesMap[88] = "ENOTSOCK";
	symbolicNamesMap[89] = "EDESTADDRREQ";
	symbolicNamesMap[90] = "EMSGSIZE";
	symbolicNamesMap[91] = "EPROTOTYPE";
	symbolicNamesMap[92] = "ENOPROTOOPT";
	symbolicNamesMap[93] = "EPROTONOSUPPORT";
	symbolicNamesMap[94] = "ESOCKTNOSUPPORT";
	symbolicNamesMap[95] = "EOPNOTSUPP";
	symbolicNamesMap[96] = "EPFNOSUPPORT";
	symbolicNamesMap[97] = "EAFNOSUPPORT";
	symbolicNamesMap[98] = "EADDRINUSE";
	symbolicNamesMap[99] = "EADDRNOTAVAIL";
	symbolicNamesMap[100] = "ENETDOWN";
	symbolicNamesMap[101] = "ENETUNREACH";
	symbolicNamesMap[102] = "ENETRESET";
	symbolicNamesMap[103] = "ECONNABORTED";
	symbolicNamesMap[104] = "ECONNRESET";
	symbolicNamesMap[105] = "ENOBUFS";
	symbolicNamesMap[106] = "EISCONN";
	symbolicNamesMap[107] = "ENOTCONN";
	symbolicNamesMap[108] = "ESHUTDOWN";
	symbolicNamesMap[109] = "ETOOMANYREFS";
	symbolicNamesMap[110] = "ETIMEDOUT";
	symbolicNamesMap[111] = "ECONNREFUSED";
	symbolicNamesMap[112] = "EHOSTDOWN";
	symbolicNamesMap[113] = "EHOSTUNREACH";
	symbolicNamesMap[114] = "EALREADY";
	symbolicNamesMap[115] = "EINPROGRESS";
	symbolicNamesMap[116] = "ESTALE";
	symbolicNamesMap[117] = "EUCLEAN";
	symbolicNamesMap[118] = "ENOTNAM";
	symbolicNamesMap[119] = "ENAVAIL";
	symbolicNamesMap[120] = "EISNAM";
	symbolicNamesMap[121] = "EREMOTEIO";
	symbolicNamesMap[122] = "EDQUOT";
	symbolicNamesMap[123] = "ENOMEDIUM";
	symbolicNamesMap[124] = "EMEDIUMTYPE";
	symbolicNamesMap[125] = "ECANCELED";
	symbolicNamesMap[126] = "ENOKEY";
	symbolicNamesMap[127] = "EKEYEXPIRED";
	symbolicNamesMap[128] = "EKEYREVOKED";
	symbolicNamesMap[129] = "EKEYREJECTED";
	symbolicNamesMap[130] = "EOWNERDEAD";
	symbolicNamesMap[131] = "ENOTRECOVERABLE";
	symbolicNamesMap[132] = "ERFKILL";
	symbolicNamesMap[133] = "EHWPOISON";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForOpenFlags)
	// Info from: <asm-generic/fcntl.h>
	symbolicNamesMap[00000000] = "O_RDONLY";
	symbolicNamesMap[00000001] = "O_WRONLY";
	symbolicNamesMap[00000002] = "O_RDWR";
	symbolicNamesMap[00000003] = "O_ACCMODE";
	symbolicNamesMap[00000100] = "O_CREAT";
	symbolicNamesMap[00000200] = "O_EXCL";
	symbolicNamesMap[00000400] = "O_NOCTTY";
	symbolicNamesMap[00001000] = "O_TRUNC";
	symbolicNamesMap[00002000] = "O_APPEND";
	symbolicNamesMap[00004000] = "O_NONBLOCK";
	symbolicNamesMap[00010000] = "O_DSYNC";
	symbolicNamesMap[00020000] = "FASYNC";
	symbolicNamesMap[00040000] = "O_DIRECT";
	symbolicNamesMap[00100000] = "O_LARGEFILE";
	symbolicNamesMap[00200000] = "O_DIRECTORY";
	symbolicNamesMap[00400000] = "O_NOFOLLOW";
	symbolicNamesMap[01000000] = "O_NOATIME";
	symbolicNamesMap[02000000] = "O_CLOEXEC";
	// Info from: <bits/fcntl-linux.h>
	symbolicNamesMap[04010000] = "O_SYNC";
	// symbolicNamesMap[04010000] = "O_FSYNC"; // synonym for O_SYNC
	// The manual page for open() mentions also the following names. However, I
	// was unable to find their values:
	// symbolicNamesMap[?] = "O_EXEC";
	// symbolicNamesMap[?] = "O_SEARCH";
	// symbolicNamesMap[?] = "O_RSYNC";
	// symbolicNamesMap[?] = "O_TTY_INIT";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForPermMode)
	// Info from: <linux/stat.h>
	symbolicNamesMap[00700] = "S_IRWXU";
	symbolicNamesMap[00400] = "S_IRUSR";
	symbolicNamesMap[00200] = "S_IWUSR";
	symbolicNamesMap[00100] = "S_IXUSR";
	symbolicNamesMap[00070] = "S_IRWXG";
	symbolicNamesMap[00040] = "S_IRGRP";
	symbolicNamesMap[00020] = "S_IWGRP";
	symbolicNamesMap[00010] = "S_IXGRP";
	symbolicNamesMap[00007] = "S_IRWXO";
	symbolicNamesMap[00004] = "S_IROTH";
	symbolicNamesMap[00002] = "S_IWOTH";
	symbolicNamesMap[00001] = "S_IXOTH";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForSignalMaskActions)
	// Info from: <asm-generic/signal-defs.h>
	symbolicNamesMap[0] = "SIG_BLOCK";
	symbolicNamesMap[1] = "SIG_UNBLOCK";
	symbolicNamesMap[2] = "SIG_SETMASK";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForPrioType)
	// Info from: <linux/resource.h>
	symbolicNamesMap[0] = "PRIO_PROCESS";
	symbolicNamesMap[1] = "PRIO_PGRP";
	symbolicNamesMap[2] = "PRIO_USER";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForAddressFamilies)
	// Info from: <bits/socket.h>
	symbolicNamesMap[0] = "AF_UNSPEC";
	symbolicNamesMap[1] = "AF_LOCAL";
	symbolicNamesMap[2] = "AF_INET";
	symbolicNamesMap[3] = "AF_AX25";
	symbolicNamesMap[4] = "AF_IPX";
	symbolicNamesMap[5] = "AF_APPLETALK";
	symbolicNamesMap[6] = "AF_NETROM";
	symbolicNamesMap[7] = "AF_BRIDGE";
	symbolicNamesMap[8] = "AF_ATMPVC";
	symbolicNamesMap[9] = "AF_X25";
	symbolicNamesMap[10] = "AF_INET6";
	symbolicNamesMap[11] = "AF_ROSE";
	symbolicNamesMap[12] = "AF_DECnet";
	symbolicNamesMap[13] = "AF_NETBEUI";
	symbolicNamesMap[14] = "AF_SECURITY";
	symbolicNamesMap[15] = "AF_KEY";
	symbolicNamesMap[16] = "AF_NETLINK";
	symbolicNamesMap[17] = "AF_PACKET";
	symbolicNamesMap[18] = "AF_ASH";
	symbolicNamesMap[19] = "AF_ECONET";
	symbolicNamesMap[20] = "AF_ATMSVC";
	symbolicNamesMap[21] = "AF_RDS";
	symbolicNamesMap[22] = "AF_SNA";
	symbolicNamesMap[23] = "AF_IRDA";
	symbolicNamesMap[24] = "AF_PPPOX";
	symbolicNamesMap[25] = "AF_WANPIPE";
	symbolicNamesMap[26] = "AF_LLC";
	symbolicNamesMap[29] = "AF_CAN";
	symbolicNamesMap[30] = "AF_TIPC";
	symbolicNamesMap[31] = "AF_BLUETOOTH";
	symbolicNamesMap[32] = "AF_IUCV";
	symbolicNamesMap[33] = "AF_RXRPC";
	symbolicNamesMap[34] = "AF_ISDN";
	symbolicNamesMap[35] = "AF_PHONET";
	symbolicNamesMap[36] = "AF_IEEE802154";
	symbolicNamesMap[37] = "AF_CAIF";
	symbolicNamesMap[38] = "AF_ALG";
	symbolicNamesMap[39] = "AF_NFC";
	symbolicNamesMap[40] = "AF_MAX";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForIPProtocols)
	// Info from: <linux/in.h>
	symbolicNamesMap[0] = "IPPROTO_IP";
	symbolicNamesMap[1] = "IPPROTO_ICMP";
	symbolicNamesMap[2] = "IPPROTO_IGMP";
	symbolicNamesMap[4] = "IPPROTO_IPIP";
	symbolicNamesMap[6] = "IPPROTO_TCP";
	symbolicNamesMap[8] = "IPPROTO_EGP";
	symbolicNamesMap[12] = "IPPROTO_PUP";
	symbolicNamesMap[17] = "IPPROTO_UDP";
	symbolicNamesMap[22] = "IPPROTO_IDP";
	symbolicNamesMap[33] = "IPPROTO_DCCP";
	symbolicNamesMap[46] = "IPPROTO_RSVP";
	symbolicNamesMap[47] = "IPPROTO_GRE";
	symbolicNamesMap[41] = "IPPROTO_IPV6";
	symbolicNamesMap[50] = "IPPROTO_ESP";
	symbolicNamesMap[51] = "IPPROTO_AH";
	symbolicNamesMap[94] = "IPPROTO_BEETPH";
	symbolicNamesMap[103] = "IPPROTO_PIM" ;
	symbolicNamesMap[108] = "IPPROTO_COMP";
	symbolicNamesMap[132] = "IPPROTO_SCTP";
	symbolicNamesMap[136] = "IPPROTO_UDPLITE";
	symbolicNamesMap[255] = "IPPROTO_RAW";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForSocketTypes)
	// Info from: <bits/socket_type.h>
	symbolicNamesMap[1] = "SOCK_STREAM";
	symbolicNamesMap[2] = "SOCK_DGRAM";
	symbolicNamesMap[3] = "SOCK_RAW";
	symbolicNamesMap[4] = "SOCK_RDM";
	symbolicNamesMap[5] = "SOCK_SEQPACKET";
	symbolicNamesMap[6] = "SOCK_DCCP";
	symbolicNamesMap[10] = "SOCK_PACKET";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForSocketLevels)
	// Info from: <bits/in.h>
	symbolicNamesMap[0] = "SOL_IP";
	symbolicNamesMap[41] = "SOL_IPV6";
	symbolicNamesMap[58] = "SOL_ICMPV6";
	// Info from: <bits/socket.h>
	symbolicNamesMap[255] = "SOL_RAW";
	symbolicNamesMap[261] = "SOL_DECNET";
	symbolicNamesMap[262] = "SOL_X25";
	symbolicNamesMap[263] = "SOL_PACKET";
	symbolicNamesMap[264] = "SOL_ATM";
	symbolicNamesMap[265] = "SOL_AAL";
	symbolicNamesMap[266] = "SOL_IRDA";
	// Info from: <asm-generic/socket.h>
	symbolicNamesMap[1] = "SOL_SOCKET";
	// Info from: <netipx/ipx.h>
	symbolicNamesMap[256] = "SOL_IPX";
	// Info from: <netax25/ax25.h>
	symbolicNamesMap[257] = "SOL_AX25";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForSocketOptions)
	// Info from: <asm-generic/socket.h>
	symbolicNamesMap[1] = "SOL_SOCKET";
	symbolicNamesMap[1] = "SO_DEBUG";
	symbolicNamesMap[2] = "SO_REUSEADDR";
	symbolicNamesMap[3] = "SO_TYPE";
	symbolicNamesMap[4] = "SO_ERROR";
	symbolicNamesMap[5] = "SO_DONTROUTE";
	symbolicNamesMap[6] = "SO_BROADCAST";
	symbolicNamesMap[7] = "SO_SNDBUF";
	symbolicNamesMap[8] = "SO_RCVBUF";
	symbolicNamesMap[9] = "SO_KEEPALIVE";
	symbolicNamesMap[10] = "SO_OOBINLINE";
	symbolicNamesMap[11] = "SO_NO_CHECK";
	symbolicNamesMap[12] = "SO_PRIORITY";
	symbolicNamesMap[13] = "SO_LINGER";
	symbolicNamesMap[14] = "SO_BSDCOMPAT";
	symbolicNamesMap[15] = "SO_REUSEPORT";
	symbolicNamesMap[16] = "SO_PASSCRED";
	symbolicNamesMap[17] = "SO_PEERCRED";
	symbolicNamesMap[18] = "SO_RCVLOWAT";
	symbolicNamesMap[19] = "SO_SNDLOWAT";
	symbolicNamesMap[20] = "SO_RCVTIMEO";
	symbolicNamesMap[21] = "SO_SNDTIMEO";
	symbolicNamesMap[22] = "SO_SECURITY_AUTHENTICATION";
	symbolicNamesMap[23] = "SO_SECURITY_ENCRYPTION_TRANSPORT";
	symbolicNamesMap[24] = "SO_SECURITY_ENCRYPTION_NETWORK";
	symbolicNamesMap[25] = "SO_BINDTODEVICE";
	symbolicNamesMap[26] = "SO_ATTACH_FILTER";
	// symbolicNamesMap[26] = "SO_GET_FILTER"; // synonym for SO_ATTACH_FILTER
	symbolicNamesMap[27] = "SO_DETACH_FILTER";
	symbolicNamesMap[28] = "SO_PEERNAME";
	symbolicNamesMap[29] = "SO_TIMESTAMP";
	symbolicNamesMap[30] = "SO_ACCEPTCONN";
	symbolicNamesMap[31] = "SO_PEERSEC";
	symbolicNamesMap[32] = "SO_SNDBUFFORCE";
	symbolicNamesMap[33] = "SO_RCVBUFFORCE";
	symbolicNamesMap[34] = "SO_PASSSEC";
	symbolicNamesMap[35] = "SO_TIMESTAMPNS";
	symbolicNamesMap[36] = "SO_MARK";
	symbolicNamesMap[37] = "SO_TIMESTAMPING";
	symbolicNamesMap[38] = "SO_PROTOCOL";
	symbolicNamesMap[39] = "SO_DOMAIN";
	symbolicNamesMap[40] = "SO_RXQ_OVFL";
	symbolicNamesMap[41] = "SO_WIFI_STATUS";
	symbolicNamesMap[42] = "SO_PEEK_OFF";
	symbolicNamesMap[43] = "SO_NOFCS";
	symbolicNamesMap[44] = "SO_LOCK_FILTER";
	symbolicNamesMap[45] = "SO_SELECT_ERR_QUEUE";
	symbolicNamesMap[46] = "SO_BUSY_POLL";
	symbolicNamesMap[47] = "SO_MAX_PACING_RATE";
	symbolicNamesMap[48] = "SO_BPF_EXTENSIONS";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForMessageFlags)
	// Info from: <bits/socket.h>
	symbolicNamesMap[0x01] = "MSG_OOB";
	symbolicNamesMap[0x02] = "MSG_PEEK";
	symbolicNamesMap[0x04] = "MSG_DONTROUTE";
	symbolicNamesMap[0x08] = "MSG_CTRUNC";
	symbolicNamesMap[0x10] = "MSG_PROXY";
	symbolicNamesMap[0x20] = "MSG_TRUNC";
	symbolicNamesMap[0x40] = "MSG_DONTWAIT";
	symbolicNamesMap[0x80] = "MSG_EOR";
	symbolicNamesMap[0x100] = "MSG_WAITALL";
	symbolicNamesMap[0x200] = "MSG_FIN";
	symbolicNamesMap[0x400] = "MSG_SYN";
	symbolicNamesMap[0x800] = "MSG_CONFIRM";
	symbolicNamesMap[0x1000] = "MSG_RST";
	symbolicNamesMap[0x2000] = "MSG_ERRQUEUE";
	symbolicNamesMap[0x4000] = "MSG_NOSIGNAL";
	symbolicNamesMap[0x8000] = "MSG_MORE";
	symbolicNamesMap[0x10000] = "MSG_WAITFORONE";
	symbolicNamesMap[0x20000000] = "MSG_FASTOPEN";
	symbolicNamesMap[0x40000000] = "MSG_CMSG_CLOEXEC";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForSystemCalls)
	// Info from: <bits/syscall.h>
	//            <asm/unistd_32.h>
	symbolicNamesMap[0] = "SYS_restart_syscall";
	symbolicNamesMap[1] = "SYS_exit";
	symbolicNamesMap[2] = "SYS_fork";
	symbolicNamesMap[3] = "SYS_read";
	symbolicNamesMap[4] = "SYS_write";
	symbolicNamesMap[5] = "SYS_open";
	symbolicNamesMap[6] = "SYS_close";
	symbolicNamesMap[7] = "SYS_waitpid";
	symbolicNamesMap[8] = "SYS_creat";
	symbolicNamesMap[9] = "SYS_link";
	symbolicNamesMap[10] = "SYS_unlink";
	symbolicNamesMap[11] = "SYS_execve";
	symbolicNamesMap[12] = "SYS_chdir";
	symbolicNamesMap[13] = "SYS_time";
	symbolicNamesMap[14] = "SYS_mknod";
	symbolicNamesMap[15] = "SYS_chmod";
	symbolicNamesMap[16] = "SYS_lchown";
	symbolicNamesMap[17] = "SYS_break";
	symbolicNamesMap[18] = "SYS_oldstat";
	symbolicNamesMap[19] = "SYS_lseek";
	symbolicNamesMap[20] = "SYS_getpid";
	symbolicNamesMap[21] = "SYS_mount";
	symbolicNamesMap[22] = "SYS_umount";
	symbolicNamesMap[23] = "SYS_setuid";
	symbolicNamesMap[24] = "SYS_getuid";
	symbolicNamesMap[25] = "SYS_stime";
	symbolicNamesMap[26] = "SYS_ptrace";
	symbolicNamesMap[27] = "SYS_alarm";
	symbolicNamesMap[28] = "SYS_oldfstat";
	symbolicNamesMap[29] = "SYS_pause";
	symbolicNamesMap[30] = "SYS_utime";
	symbolicNamesMap[31] = "SYS_stty";
	symbolicNamesMap[32] = "SYS_gtty";
	symbolicNamesMap[33] = "SYS_access";
	symbolicNamesMap[34] = "SYS_nice";
	symbolicNamesMap[35] = "SYS_ftime";
	symbolicNamesMap[36] = "SYS_sync";
	symbolicNamesMap[37] = "SYS_kill";
	symbolicNamesMap[38] = "SYS_rename";
	symbolicNamesMap[39] = "SYS_mkdir";
	symbolicNamesMap[40] = "SYS_rmdir";
	symbolicNamesMap[41] = "SYS_dup";
	symbolicNamesMap[42] = "SYS_pipe";
	symbolicNamesMap[43] = "SYS_times";
	symbolicNamesMap[44] = "SYS_prof";
	symbolicNamesMap[45] = "SYS_brk";
	symbolicNamesMap[46] = "SYS_setgid";
	symbolicNamesMap[47] = "SYS_getgid";
	symbolicNamesMap[48] = "SYS_signal";
	symbolicNamesMap[49] = "SYS_geteuid";
	symbolicNamesMap[50] = "SYS_getegid";
	symbolicNamesMap[51] = "SYS_acct";
	symbolicNamesMap[52] = "SYS_umount2";
	symbolicNamesMap[53] = "SYS_lock";
	symbolicNamesMap[54] = "SYS_ioctl";
	symbolicNamesMap[55] = "SYS_fcntl";
	symbolicNamesMap[56] = "SYS_mpx";
	symbolicNamesMap[57] = "SYS_setpgid";
	symbolicNamesMap[58] = "SYS_ulimit";
	symbolicNamesMap[59] = "SYS_oldolduname";
	symbolicNamesMap[60] = "SYS_umask";
	symbolicNamesMap[61] = "SYS_chroot";
	symbolicNamesMap[62] = "SYS_ustat";
	symbolicNamesMap[63] = "SYS_dup2";
	symbolicNamesMap[64] = "SYS_getppid";
	symbolicNamesMap[65] = "SYS_getpgrp";
	symbolicNamesMap[66] = "SYS_setsid";
	symbolicNamesMap[67] = "SYS_sigaction";
	symbolicNamesMap[68] = "SYS_sgetmask";
	symbolicNamesMap[69] = "SYS_ssetmask";
	symbolicNamesMap[70] = "SYS_setreuid";
	symbolicNamesMap[71] = "SYS_setregid";
	symbolicNamesMap[72] = "SYS_sigsuspend";
	symbolicNamesMap[73] = "SYS_sigpending";
	symbolicNamesMap[74] = "SYS_sethostname";
	symbolicNamesMap[75] = "SYS_setrlimit";
	symbolicNamesMap[76] = "SYS_getrlimit";
	symbolicNamesMap[77] = "SYS_getrusage";
	symbolicNamesMap[78] = "SYS_gettimeofday";
	symbolicNamesMap[79] = "SYS_settimeofday";
	symbolicNamesMap[80] = "SYS_getgroups";
	symbolicNamesMap[81] = "SYS_setgroups";
	symbolicNamesMap[82] = "SYS_select";
	symbolicNamesMap[83] = "SYS_symlink";
	symbolicNamesMap[84] = "SYS_oldlstat";
	symbolicNamesMap[85] = "SYS_readlink";
	symbolicNamesMap[86] = "SYS_uselib";
	symbolicNamesMap[87] = "SYS_swapon";
	symbolicNamesMap[88] = "SYS_reboot";
	symbolicNamesMap[89] = "SYS_readdir";
	symbolicNamesMap[90] = "SYS_mmap";
	symbolicNamesMap[91] = "SYS_munmap";
	symbolicNamesMap[92] = "SYS_truncate";
	symbolicNamesMap[93] = "SYS_ftruncate";
	symbolicNamesMap[94] = "SYS_fchmod";
	symbolicNamesMap[95] = "SYS_fchown";
	symbolicNamesMap[96] = "SYS_getpriority";
	symbolicNamesMap[97] = "SYS_setpriority";
	symbolicNamesMap[98] = "SYS_profil";
	symbolicNamesMap[99] = "SYS_statfs";
	symbolicNamesMap[100] = "SYS_fstatfs";
	symbolicNamesMap[101] = "SYS_ioperm";
	symbolicNamesMap[102] = "SYS_socketcall";
	symbolicNamesMap[103] = "SYS_syslog";
	symbolicNamesMap[104] = "SYS_setitimer";
	symbolicNamesMap[105] = "SYS_getitimer";
	symbolicNamesMap[106] = "SYS_stat";
	symbolicNamesMap[107] = "SYS_lstat";
	symbolicNamesMap[108] = "SYS_fstat";
	symbolicNamesMap[109] = "SYS_olduname";
	symbolicNamesMap[110] = "SYS_iopl";
	symbolicNamesMap[111] = "SYS_vhangup";
	symbolicNamesMap[112] = "SYS_idle";
	symbolicNamesMap[113] = "SYS_vm86old";
	symbolicNamesMap[114] = "SYS_wait4";
	symbolicNamesMap[115] = "SYS_swapoff";
	symbolicNamesMap[116] = "SYS_sysinfo";
	symbolicNamesMap[117] = "SYS_ipc";
	symbolicNamesMap[118] = "SYS_fsync";
	symbolicNamesMap[119] = "SYS_sigreturn";
	symbolicNamesMap[120] = "SYS_clone";
	symbolicNamesMap[121] = "SYS_setdomainname";
	symbolicNamesMap[122] = "SYS_uname";
	symbolicNamesMap[123] = "SYS_modify_ldt";
	symbolicNamesMap[124] = "SYS_adjtimex";
	symbolicNamesMap[125] = "SYS_mprotect";
	symbolicNamesMap[126] = "SYS_sigprocmask";
	symbolicNamesMap[127] = "SYS_create_module";
	symbolicNamesMap[128] = "SYS_init_module";
	symbolicNamesMap[129] = "SYS_delete_module";
	symbolicNamesMap[130] = "SYS_get_kernel_syms";
	symbolicNamesMap[131] = "SYS_quotactl";
	symbolicNamesMap[132] = "SYS_getpgid";
	symbolicNamesMap[133] = "SYS_fchdir";
	symbolicNamesMap[134] = "SYS_bdflush";
	symbolicNamesMap[135] = "SYS_sysfs";
	symbolicNamesMap[136] = "SYS_personality";
	symbolicNamesMap[137] = "SYS_afs_syscall";
	symbolicNamesMap[138] = "SYS_setfsuid";
	symbolicNamesMap[139] = "SYS_setfsgid";
	symbolicNamesMap[140] = "SYS__llseek";
	symbolicNamesMap[141] = "SYS_getdents";
	symbolicNamesMap[142] = "SYS__newselect";
	symbolicNamesMap[143] = "SYS_flock";
	symbolicNamesMap[144] = "SYS_msync";
	symbolicNamesMap[145] = "SYS_readv";
	symbolicNamesMap[146] = "SYS_writev";
	symbolicNamesMap[147] = "SYS_getsid";
	symbolicNamesMap[148] = "SYS_fdatasync";
	symbolicNamesMap[149] = "SYS__sysctl";
	symbolicNamesMap[150] = "SYS_mlock";
	symbolicNamesMap[151] = "SYS_munlock";
	symbolicNamesMap[152] = "SYS_mlockall";
	symbolicNamesMap[153] = "SYS_munlockall";
	symbolicNamesMap[154] = "SYS_sched_setparam";
	symbolicNamesMap[155] = "SYS_sched_getparam";
	symbolicNamesMap[156] = "SYS_sched_setscheduler";
	symbolicNamesMap[157] = "SYS_sched_getscheduler";
	symbolicNamesMap[158] = "SYS_sched_yield";
	symbolicNamesMap[159] = "SYS_sched_get_priority_max";
	symbolicNamesMap[160] = "SYS_sched_get_priority_min";
	symbolicNamesMap[161] = "SYS_sched_rr_get_interval";
	symbolicNamesMap[162] = "SYS_nanosleep";
	symbolicNamesMap[163] = "SYS_mremap";
	symbolicNamesMap[164] = "SYS_setresuid";
	symbolicNamesMap[165] = "SYS_getresuid";
	symbolicNamesMap[166] = "SYS_vm86";
	symbolicNamesMap[167] = "SYS_query_module";
	symbolicNamesMap[168] = "SYS_poll";
	symbolicNamesMap[169] = "SYS_nfsservctl";
	symbolicNamesMap[170] = "SYS_setresgid";
	symbolicNamesMap[171] = "SYS_getresgid";
	symbolicNamesMap[172] = "SYS_prctl";
	symbolicNamesMap[173] = "SYS_rt_sigreturn";
	symbolicNamesMap[174] = "SYS_rt_sigaction";
	symbolicNamesMap[175] = "SYS_rt_sigprocmask";
	symbolicNamesMap[176] = "SYS_rt_sigpending";
	symbolicNamesMap[177] = "SYS_rt_sigtimedwait";
	symbolicNamesMap[178] = "SYS_rt_sigqueueinfo";
	symbolicNamesMap[179] = "SYS_rt_sigsuspend";
	symbolicNamesMap[180] = "SYS_pread64";
	symbolicNamesMap[181] = "SYS_pwrite64";
	symbolicNamesMap[182] = "SYS_chown";
	symbolicNamesMap[183] = "SYS_getcwd";
	symbolicNamesMap[184] = "SYS_capget";
	symbolicNamesMap[185] = "SYS_capset";
	symbolicNamesMap[186] = "SYS_sigaltstack";
	symbolicNamesMap[187] = "SYS_sendfile";
	symbolicNamesMap[188] = "SYS_getpmsg";
	symbolicNamesMap[189] = "SYS_putpmsg";
	symbolicNamesMap[190] = "SYS_vfork";
	symbolicNamesMap[191] = "SYS_ugetrlimit";
	symbolicNamesMap[192] = "SYS_mmap2";
	symbolicNamesMap[193] = "SYS_truncate64";
	symbolicNamesMap[194] = "SYS_ftruncate64";
	symbolicNamesMap[195] = "SYS_stat64";
	symbolicNamesMap[196] = "SYS_lstat64";
	symbolicNamesMap[197] = "SYS_fstat64";
	symbolicNamesMap[198] = "SYS_lchown32";
	symbolicNamesMap[199] = "SYS_getuid32";
	symbolicNamesMap[200] = "SYS_getgid32";
	symbolicNamesMap[201] = "SYS_geteuid32";
	symbolicNamesMap[202] = "SYS_getegid32";
	symbolicNamesMap[203] = "SYS_setreuid32";
	symbolicNamesMap[204] = "SYS_setregid32";
	symbolicNamesMap[205] = "SYS_getgroups32";
	symbolicNamesMap[206] = "SYS_setgroups32";
	symbolicNamesMap[207] = "SYS_fchown32";
	symbolicNamesMap[208] = "SYS_setresuid32";
	symbolicNamesMap[209] = "SYS_getresuid32";
	symbolicNamesMap[210] = "SYS_setresgid32";
	symbolicNamesMap[211] = "SYS_getresgid32";
	symbolicNamesMap[212] = "SYS_chown32";
	symbolicNamesMap[213] = "SYS_setuid32";
	symbolicNamesMap[214] = "SYS_setgid32";
	symbolicNamesMap[215] = "SYS_setfsuid32";
	symbolicNamesMap[216] = "SYS_setfsgid32";
	symbolicNamesMap[217] = "SYS_pivot_root";
	symbolicNamesMap[218] = "SYS_mincore";
	symbolicNamesMap[219] = "SYS_madvise";
	symbolicNamesMap[220] = "SYS_getdents64";
	symbolicNamesMap[221] = "SYS_fcntl64";
	symbolicNamesMap[224] = "SYS_gettid";
	symbolicNamesMap[225] = "SYS_readahead";
	symbolicNamesMap[226] = "SYS_setxattr";
	symbolicNamesMap[227] = "SYS_lsetxattr";
	symbolicNamesMap[228] = "SYS_fsetxattr";
	symbolicNamesMap[229] = "SYS_getxattr";
	symbolicNamesMap[230] = "SYS_lgetxattr";
	symbolicNamesMap[231] = "SYS_fgetxattr";
	symbolicNamesMap[232] = "SYS_listxattr";
	symbolicNamesMap[233] = "SYS_llistxattr";
	symbolicNamesMap[234] = "SYS_flistxattr";
	symbolicNamesMap[235] = "SYS_removexattr";
	symbolicNamesMap[236] = "SYS_lremovexattr";
	symbolicNamesMap[237] = "SYS_fremovexattr";
	symbolicNamesMap[238] = "SYS_tkill";
	symbolicNamesMap[239] = "SYS_sendfile64";
	symbolicNamesMap[240] = "SYS_futex";
	symbolicNamesMap[241] = "SYS_sched_setaffinity";
	symbolicNamesMap[242] = "SYS_sched_getaffinity";
	symbolicNamesMap[243] = "SYS_set_thread_area";
	symbolicNamesMap[244] = "SYS_get_thread_area";
	symbolicNamesMap[245] = "SYS_io_setup";
	symbolicNamesMap[246] = "SYS_io_destroy";
	symbolicNamesMap[247] = "SYS_io_getevents";
	symbolicNamesMap[248] = "SYS_io_submit";
	symbolicNamesMap[249] = "SYS_io_cancel";
	symbolicNamesMap[250] = "SYS_fadvise64";
	symbolicNamesMap[252] = "SYS_exit_group";
	symbolicNamesMap[253] = "SYS_lookup_dcookie";
	symbolicNamesMap[254] = "SYS_epoll_create";
	symbolicNamesMap[255] = "SYS_epoll_ctl";
	symbolicNamesMap[256] = "SYS_epoll_wait";
	symbolicNamesMap[257] = "SYS_remap_file_pages";
	symbolicNamesMap[258] = "SYS_set_tid_address";
	symbolicNamesMap[259] = "SYS_timer_create";
	symbolicNamesMap[260] = "SYS_timer_settime";
	symbolicNamesMap[261] = "SYS_timer_gettime";
	symbolicNamesMap[262] = "SYS_timer_getoverrun";
	symbolicNamesMap[263] = "SYS_timer_delete";
	symbolicNamesMap[264] = "SYS_clock_settime";
	symbolicNamesMap[265] = "SYS_clock_gettime";
	symbolicNamesMap[266] = "SYS_clock_getres";
	symbolicNamesMap[267] = "SYS_clock_nanosleep";
	symbolicNamesMap[268] = "SYS_statfs64";
	symbolicNamesMap[269] = "SYS_fstatfs64";
	symbolicNamesMap[270] = "SYS_tgkill";
	symbolicNamesMap[271] = "SYS_utimes";
	symbolicNamesMap[272] = "SYS_fadvise64_64";
	symbolicNamesMap[273] = "SYS_vserver";
	symbolicNamesMap[274] = "SYS_mbind";
	symbolicNamesMap[275] = "SYS_get_mempolicy";
	symbolicNamesMap[276] = "SYS_set_mempolicy";
	symbolicNamesMap[277] = "SYS_mq_open";
	symbolicNamesMap[278] = "SYS_mq_unlink";
	symbolicNamesMap[279] = "SYS_mq_timedsend";
	symbolicNamesMap[280] = "SYS_mq_timedreceive";
	symbolicNamesMap[281] = "SYS_mq_notify";
	symbolicNamesMap[282] = "SYS_mq_getsetattr";
	symbolicNamesMap[283] = "SYS_kexec_load";
	symbolicNamesMap[284] = "SYS_waitid";
	symbolicNamesMap[286] = "SYS_add_key";
	symbolicNamesMap[287] = "SYS_request_key";
	symbolicNamesMap[288] = "SYS_keyctl";
	symbolicNamesMap[289] = "SYS_ioprio_set";
	symbolicNamesMap[290] = "SYS_ioprio_get";
	symbolicNamesMap[291] = "SYS_inotify_init";
	symbolicNamesMap[292] = "SYS_inotify_add_watch";
	symbolicNamesMap[293] = "SYS_inotify_rm_watch";
	symbolicNamesMap[294] = "SYS_migrate_pages";
	symbolicNamesMap[295] = "SYS_openat";
	symbolicNamesMap[296] = "SYS_mkdirat";
	symbolicNamesMap[297] = "SYS_mknodat";
	symbolicNamesMap[298] = "SYS_fchownat";
	symbolicNamesMap[299] = "SYS_futimesat";
	symbolicNamesMap[300] = "SYS_fstatat64";
	symbolicNamesMap[301] = "SYS_unlinkat";
	symbolicNamesMap[302] = "SYS_renameat";
	symbolicNamesMap[303] = "SYS_linkat";
	symbolicNamesMap[304] = "SYS_symlinkat";
	symbolicNamesMap[305] = "SYS_readlinkat";
	symbolicNamesMap[306] = "SYS_fchmodat";
	symbolicNamesMap[307] = "SYS_faccessat";
	symbolicNamesMap[308] = "SYS_pselect6";
	symbolicNamesMap[309] = "SYS_ppoll";
	symbolicNamesMap[310] = "SYS_unshare";
	symbolicNamesMap[311] = "SYS_set_robust_list";
	symbolicNamesMap[312] = "SYS_get_robust_list";
	symbolicNamesMap[313] = "SYS_splice";
	symbolicNamesMap[314] = "SYS_sync_file_range";
	symbolicNamesMap[315] = "SYS_tee";
	symbolicNamesMap[316] = "SYS_vmsplice";
	symbolicNamesMap[317] = "SYS_move_pages";
	symbolicNamesMap[318] = "SYS_getcpu";
	symbolicNamesMap[319] = "SYS_epoll_pwait";
	symbolicNamesMap[320] = "SYS_utimensat";
	symbolicNamesMap[321] = "SYS_signalfd";
	symbolicNamesMap[322] = "SYS_timerfd_create";
	symbolicNamesMap[323] = "SYS_eventfd";
	symbolicNamesMap[324] = "SYS_fallocate";
	symbolicNamesMap[325] = "SYS_timerfd_settime";
	symbolicNamesMap[326] = "SYS_timerfd_gettime";
	symbolicNamesMap[327] = "SYS_signalfd4";
	symbolicNamesMap[328] = "SYS_eventfd2";
	symbolicNamesMap[329] = "SYS_epoll_create1";
	symbolicNamesMap[330] = "SYS_dup3";
	symbolicNamesMap[331] = "SYS_pipe2";
	symbolicNamesMap[332] = "SYS_inotify_init1";
	symbolicNamesMap[333] = "SYS_preadv";
	symbolicNamesMap[334] = "SYS_pwritev";
	symbolicNamesMap[335] = "SYS_rt_tgsigqueueinfo";
	symbolicNamesMap[336] = "SYS_perf_event_open";
	symbolicNamesMap[337] = "SYS_recvmmsg";
	symbolicNamesMap[338] = "SYS_fanotify_init";
	symbolicNamesMap[339] = "SYS_fanotify_mark";
	symbolicNamesMap[340] = "SYS_prlimit64";
	symbolicNamesMap[341] = "SYS_name_to_handle_at";
	symbolicNamesMap[342] = "SYS_open_by_handle_at";
	symbolicNamesMap[343] = "SYS_clock_adjtime";
	symbolicNamesMap[344] = "SYS_syncfs";
	symbolicNamesMap[345] = "SYS_sendmmsg";
	symbolicNamesMap[346] = "SYS_setns";
	symbolicNamesMap[347] = "SYS_process_vm_readv";
	symbolicNamesMap[348] = "SYS_process_vm_writev";
	symbolicNamesMap[349] = "SYS_kcmp";
	symbolicNamesMap[350] = "SYS_finit_module";
	symbolicNamesMap[351] = "SYS_sched_setattr";
	symbolicNamesMap[352] = "SYS_sched_getattr";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForSeekWhence)
	// Info from: <stdio.h>
	symbolicNamesMap[0] = "SEEK_SET";
	symbolicNamesMap[1] = "SEEK_CUR";
	symbolicNamesMap[2] = "SEEK_END";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForLocaleCategories)
	// Info from: <bits/locale.h>
	symbolicNamesMap[0] = "LC_CTYPE";
	symbolicNamesMap[1] = "LC_NUMERIC";
	symbolicNamesMap[2] = "LC_TIME";
	symbolicNamesMap[3] = "LC_COLLATE";
	symbolicNamesMap[4] = "LC_MONETARY";
	symbolicNamesMap[5] = "LC_MESSAGES";
	symbolicNamesMap[6] = "LC_ALL";
	symbolicNamesMap[7] = "LC_PAPER";
	symbolicNamesMap[8] = "LC_NAME";
	symbolicNamesMap[9] = "LC_ADDRESS";
	symbolicNamesMap[10] = "LC_TELEPHONE";
	symbolicNamesMap[11] = "LC_MEASUREMENT";
	symbolicNamesMap[12] = "LC_IDENTIFICATION";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForSchedPolicies)
	// Info from: <bits/sched.h>
	symbolicNamesMap[0] = "SCHED_OTHER";
	symbolicNamesMap[1] = "SCHED_FIFO";
	symbolicNamesMap[2] = "SCHED_RR";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForResources)
	// Info from: <asm-generic/resource.h>
	symbolicNamesMap[0] = "RLIMIT_CPU";
	symbolicNamesMap[1] = "RLIMIT_FSIZE";
	symbolicNamesMap[2] = "RLIMIT_DATA";
	symbolicNamesMap[3] = "RLIMIT_STACK";
	symbolicNamesMap[4] = "RLIMIT_CORE";
	symbolicNamesMap[10] = "RLIMIT_LOCKS";
	symbolicNamesMap[11] = "RLIMIT_SIGPENDING";
	symbolicNamesMap[12] = "RLIMIT_MSGQUEUE";
	symbolicNamesMap[13] = "RLIMIT_NICE";
	symbolicNamesMap[14] = "RLIMIT_RTPRIO";
	symbolicNamesMap[15] = "RLIMIT_RTTIME";
	symbolicNamesMap[16] = "RLIM_NLIMITS";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForWaitOptions)
	// Info from: <linux/wait.h>
	symbolicNamesMap[0x00000001] = "WNOHANG";
	symbolicNamesMap[0x00000002] = "WUNTRACED";
	// symbolicNamesMap[0x00000002] = "WSTOPPED"; // synonym for WUNTRACED
	symbolicNamesMap[0x00000004] = "WEXITED";
	symbolicNamesMap[0x00000008] = "WCONTINUED";
	symbolicNamesMap[0x01000000] = "WNOWAIT";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForAccessTypes)
	// Info from: <linux/fcntl.h>
	symbolicNamesMap[0x100] = "AT_SYMLINK_NOFOLLOW";
	symbolicNamesMap[0x200] = "AT_REMOVEDIR";
	symbolicNamesMap[0x400] = "AT_SYMLINK_FOLLOW";
	symbolicNamesMap[0x800] = "AT_NO_AUTOMOUNT";
	symbolicNamesMap[0x1000] = "AT_EMPTY_PATH";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForAccessModes)
	// Info from: <unistd.h>
	symbolicNamesMap[0] = "F_OK";
	symbolicNamesMap[1] = "X_OK";
	symbolicNamesMap[2] = "W_OK";
	symbolicNamesMap[4] = "R_OK";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForITimers)
	// Info from: <linux/time.h>
	symbolicNamesMap[0] = "ITIMER_REAL";
	symbolicNamesMap[1] = "ITIMER_VIRTUAL";
	symbolicNamesMap[2] = "ITIMER_PROF";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForLogOptions)
	// Info from: <sys/syslog.h>
	symbolicNamesMap[0x01] = "LOG_PID";
	symbolicNamesMap[0x02] = "LOG_CONS";
	symbolicNamesMap[0x04] = "LOG_ODELAY";
	symbolicNamesMap[0x08] = "LOG_NDELAY";
	symbolicNamesMap[0x10] = "LOG_NOWAIT";
	symbolicNamesMap[0x20] = "LOG_PERROR";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForLogFacilities)
	// Info from: <sys/syslog.h>
	symbolicNamesMap[0<<3] = "LOG_KERN";
	symbolicNamesMap[1<<3] = "LOG_USER";
	symbolicNamesMap[2<<3] = "LOG_MAIL";
	symbolicNamesMap[3<<3] = "LOG_DAEMON";
	symbolicNamesMap[4<<3] = "LOG_AUTH";
	symbolicNamesMap[5<<3] = "LOG_SYSLOG";
	symbolicNamesMap[6<<3] = "LOG_LPR";
	symbolicNamesMap[7<<3] = "LOG_NEWS";
	symbolicNamesMap[8<<3] = "LOG_UUCP";
	symbolicNamesMap[9<<3] = "LOG_CRON";
	symbolicNamesMap[10<<3] = "LOG_AUTHPRIV";
	symbolicNamesMap[11<<3] = "LOG_FTP";
	symbolicNamesMap[16<<3] = "LOG_LOCAL0";
	symbolicNamesMap[17<<3] = "LOG_LOCAL1";
	symbolicNamesMap[18<<3] = "LOG_LOCAL2";
	symbolicNamesMap[19<<3] = "LOG_LOCAL3";
	symbolicNamesMap[20<<3] = "LOG_LOCAL4";
	symbolicNamesMap[21<<3] = "LOG_LOCAL5";
	symbolicNamesMap[22<<3] = "LOG_LOCAL6";
	symbolicNamesMap[23<<3] = "LOG_LOCAL7";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForLogLevels)
	// Info from: <sys/syslog.h>
	symbolicNamesMap[0] = "LOG_EMERG";
	symbolicNamesMap[1] = "LOG_ALERT";
	symbolicNamesMap[2] = "LOG_CRIT";
	symbolicNamesMap[3] = "LOG_ERR";
	symbolicNamesMap[4] = "LOG_WARNING";
	symbolicNamesMap[5] = "LOG_NOTICE";
	symbolicNamesMap[6] = "LOG_INFO";
	symbolicNamesMap[7] = "LOG_DEBUG";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForLogPriorities)
	// From `man syslog`: The priority argument is formed by ORing the facility
	//                    and the level values.
	const IntStringMap &logFacilityNames(getSymbolicNamesForLogFacilities());
	symbolicNamesMap.insert(logFacilityNames.begin(), logFacilityNames.end());
	const IntStringMap &logLevelNames(getSymbolicNamesForLogLevels());
	symbolicNamesMap.insert(logLevelNames.begin(), logLevelNames.end());
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForTimeFlags)
	// Info from: <linux/time.h>
	symbolicNamesMap[0x01] = "TIMER_ABSTIME";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForPathConfs)
	// Info from: <bits/confname.h>
	symbolicNamesMap[0] = "_PC_LINK_MAX";
	symbolicNamesMap[1] = "_PC_MAX_CANON";
	symbolicNamesMap[2] = "_PC_MAX_INPUT";
	symbolicNamesMap[3] = "_PC_NAME_MAX";
	symbolicNamesMap[4] = "_PC_PATH_MAX";
	symbolicNamesMap[5] = "_PC_PIPE_BUF";
	symbolicNamesMap[6] = "_PC_CHOWN_RESTRICTED";
	symbolicNamesMap[7] = "_PC_NO_TRUNC";
	symbolicNamesMap[8] = "_PC_VDISABLE";
	symbolicNamesMap[9] = "_PC_SYNC_IO";
	symbolicNamesMap[10] = "_PC_ASYNC_IO";
	symbolicNamesMap[11] = "_PC_PRIO_IO";
	symbolicNamesMap[12] = "_PC_SOCK_MAXBUF";
	symbolicNamesMap[13] = "_PC_FILESIZEBITS";
	symbolicNamesMap[14] = "_PC_REC_INCR_XFER_SIZE";
	symbolicNamesMap[15] = "_PC_REC_MAX_XFER_SIZE";
	symbolicNamesMap[16] = "_PC_REC_MIN_XFER_SIZE";
	symbolicNamesMap[17] = "_PC_REC_XFER_ALIGN";
	symbolicNamesMap[18] = "_PC_ALLOC_SIZE_MIN";
	symbolicNamesMap[19] = "_PC_SYMLINK_MAX";
	symbolicNamesMap[20] = "_PC_2_SYMLINKS";
DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()

/**
* @brief This function is used to initialize FUNC_PARAMS_MAP later in the file.
*/
const FuncParamsMap &initFuncParamsMap() {
	static FuncParamsMap funcParamsMap;

	// Temporary maps used to store the symbols for the current parameter of
	// the current function. In this way, we don't have to keep separate maps
	// for every function and every parameter. The only downside is that before
	// adding new data into it, it has to be cleared.
	ParamSymbolsMap paramSymbolsMap;
	IntStringMap symbolicNamesMap;

	//
	// #include <aio.h>
	// int aio_fsync(int operation, struct aiocb *aiocbp);
	//
	paramSymbolsMap.clear();
	// operation
	paramSymbolsMap[1] = getSymbolicNamesForOpenFlags();
	funcParamsMap["aio_fsync"] = paramSymbolsMap;

	//
	// #include <aio.h>
	// int lio_listio(int mode, struct aiocb *const aiocb_list[],
	//                int nitems, struct sigevent *sevp);
	//
	paramSymbolsMap.clear();
	// mode
	symbolicNamesMap.clear();
	// Info from: <aio.h>
	symbolicNamesMap[0] = "LIO_WAIT";
	symbolicNamesMap[1] = "LIO_NOWAIT";
	paramSymbolsMap[1] = symbolicNamesMap;
	funcParamsMap["aio_fsync"] = paramSymbolsMap;

	//
	// #include <arpa/inet.h>
	// int inet_net_pton(int address_family, const char *pres,
	//                   void *netp, size_t nsize);
	//
	paramSymbolsMap.clear();
	// address_family
	paramSymbolsMap[1] = getSymbolicNamesForAddressFamilies();
	funcParamsMap["inet_net_pton"] = paramSymbolsMap;

	//
	// #include <arpa/inet.h>
	// int inet_net_ntop(int address_family, const void *netp,
	//                   int bits, char *pres, size_t psize);
	//
	paramSymbolsMap.clear();
	// address_family
	paramSymbolsMap[1] = getSymbolicNamesForAddressFamilies();
	funcParamsMap["inet_net_ntop"] = paramSymbolsMap;

	//
	// #include <arpa/inet.h>
	// const char *inet_ntop(int address_family, const void *src,
	//                       char *dst, socklen_t size);
	//
	paramSymbolsMap.clear();
	// address_family
	paramSymbolsMap[1] = getSymbolicNamesForAddressFamilies();
	funcParamsMap["inet_ntop"] = paramSymbolsMap;

	//
	// #include <arpa/inet.h>
	// const char *inet_pton(int address_family, const char *src, void *dst);
	//
	paramSymbolsMap.clear();
	// address_family
	paramSymbolsMap[1] = getSymbolicNamesForAddressFamilies();
	funcParamsMap["inet_pton"] = paramSymbolsMap;

	//
	// #include <dlfcn.h>
	// void *dlopen(const char *filename, int flag);
	//
	paramSymbolsMap.clear();
	// flag
	symbolicNamesMap.clear();
	// Info from: <bits/dlfcn.h>
	symbolicNamesMap[0x00000] = "RTLD_LOCAL";
	symbolicNamesMap[0x00001] = "RTLD_LAZY";
	symbolicNamesMap[0x00002] = "RTLD_NOW";
	symbolicNamesMap[0x00003] = "RTLD_BINDING_MASK";
	symbolicNamesMap[0x00004] = "RTLD_NOLOAD";
	symbolicNamesMap[0x00008] = "RTLD_DEEPBIND";
	symbolicNamesMap[0x00100] = "RTLD_GLOBAL";
	symbolicNamesMap[0x01000] = "RTLD_NODELETE";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["dlopen"] = paramSymbolsMap;

	//
	// #include "error.h"
	// void error(int status, int err_num, const char *format, ...);
	//
	paramSymbolsMap.clear();
	// err_num
	paramSymbolsMap[2] = getSymbolicNamesForErrors();
	funcParamsMap["error"] = paramSymbolsMap;

	//
	// #include "error.h"
	// void error_at_line(int status, int errnum, const char *filename,
	//                    unsigned int linenum, const char *format, ...);
	//
	paramSymbolsMap.clear();
	// err_num
	paramSymbolsMap[2] = getSymbolicNamesForSignals();
	funcParamsMap["error_at_line"] = paramSymbolsMap;

	//
	// #include <fcntl.h>
	// int open(const char *path, int oflag, ...);
	//
	paramSymbolsMap.clear();
	// oflag
	paramSymbolsMap[2] = getSymbolicNamesForOpenFlags();
	funcParamsMap["open"] = paramSymbolsMap;

	//
	// #include <fcntl.h>
	// int fcntl(int fildes, int cmd, ...);
	//
	paramSymbolsMap.clear();
	// cmd
	symbolicNamesMap.clear();
	// Info from: <asm-generic/fcntl.h>
	symbolicNamesMap[0] = "F_DUPFD";
	symbolicNamesMap[1] = "F_GETFD";
	symbolicNamesMap[2] = "F_SETFD";
	symbolicNamesMap[3] = "F_GETFL";
	symbolicNamesMap[4] = "F_SETFL";
	symbolicNamesMap[5] = "F_GETLK";
	symbolicNamesMap[6] = "F_SETLK";
	symbolicNamesMap[7] = "F_SETLKW";
	symbolicNamesMap[8] = "F_SETOWN";
	symbolicNamesMap[9] = "F_GETOWN";
	symbolicNamesMap[10] = "F_SETSIG";
	symbolicNamesMap[11] = "F_GETSIG";
	symbolicNamesMap[12] = "F_GETLK64";
	symbolicNamesMap[13] = "F_SETLK64";
	symbolicNamesMap[14] = "F_SETLKW64";
	symbolicNamesMap[15] = "F_SETOWN_EX";
	symbolicNamesMap[16] = "F_GETOWN_EX";
	symbolicNamesMap[17] = "F_GETOWNER_UIDS";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["fcntl"] = paramSymbolsMap;

	//
	// #include <mqueue.h>
	// mqd_t mq_open(const char *name, int oflag);
	// mqd_t mq_open(const char *name, int oflag, mode_t mode,
	//               struct mq_attr *attr);
	//
	paramSymbolsMap.clear();
	// oflag
	paramSymbolsMap[2] = getSymbolicNamesForOpenFlags();
	// mode
	paramSymbolsMap[3] = getSymbolicNamesForPermMode();
	funcParamsMap["mq_open"] = paramSymbolsMap;

	//
	// #include <fcntl.h>
	// int openat(int fd, const char *path, int oflag, ...);
	//
	paramSymbolsMap.clear();
	// oflag
	paramSymbolsMap[3] = getSymbolicNamesForOpenFlags();
	funcParamsMap["openat"] = paramSymbolsMap;

	//
	// #include <fcntl.h>
	// int posix_fadvise(int fd, off_t offset, off_t len, int advice);
	//
	paramSymbolsMap.clear();
	// advice
	symbolicNamesMap.clear();
	// Info from: <linux/fadvise.h>
	symbolicNamesMap[0] = "POSIX_FADV_NORMAL";
	symbolicNamesMap[1] = "POSIX_FADV_RANDOM";
	symbolicNamesMap[2] = "POSIX_FADV_SEQUENTIAL";
	symbolicNamesMap[3] = "POSIX_FADV_WILLNEED";
	symbolicNamesMap[6] = "POSIX_FADV_DONTNEED";
	symbolicNamesMap[7] = "POSIX_FADV_NOREUSE";
	symbolicNamesMap[4] = "POSIX_FADV_DONTNEED";
	symbolicNamesMap[5] = "POSIX_FADV_NOREUSE";
	paramSymbolsMap[4] = symbolicNamesMap;
	funcParamsMap["posix_fadvise"] = paramSymbolsMap;

	//
	// #include <semaphore.h>
	// sem_t *sem_open(const char *name, int oflag);
	// sem_t *sem_open(const char *name, int oflag,
	//                 mode_t mode, unsigned int value);
	paramSymbolsMap.clear();
	// oflag
	paramSymbolsMap[2] = getSymbolicNamesForOpenFlags();
	// mode
	paramSymbolsMap[3] = getSymbolicNamesForPermMode();
	funcParamsMap["sem_open"] = paramSymbolsMap;

	//
	// #include <fmtmsg.h>
	// int fmtmsg(long classification, const char *label, int severity,
	//            const char *text, const char *action, const char *tag);
	//
	paramSymbolsMap.clear();
	// classification
	symbolicNamesMap.clear();
	// Info from: <fmtmsg.h>
	symbolicNamesMap[0x001] = "MM_HARD";
	symbolicNamesMap[0x002] = "MM_SOFT";
	symbolicNamesMap[0x004] = "MM_FIRM";
	symbolicNamesMap[0x008] = "MM_APPL";
	symbolicNamesMap[0x010] = "MM_UTIL";
	symbolicNamesMap[0x020] = "MM_OPSYS";
	symbolicNamesMap[0x040] = "MM_RECOVER";
	symbolicNamesMap[0x080] = "MM_NRECOV";
	symbolicNamesMap[0x100] = "MM_PRINT";
	symbolicNamesMap[0x200] = "MM_CONSOLE";
	paramSymbolsMap[1] = symbolicNamesMap;
	// severity
	symbolicNamesMap.clear();
	// Info from: <fmtmsg.h>
	symbolicNamesMap[0] = "MM_NOSEV";
	symbolicNamesMap[1] = "MM_HALT";
	symbolicNamesMap[2] = "MM_ERROR";
	symbolicNamesMap[3] = "MM_WARNING";
	symbolicNamesMap[4] = "MM_INFO";
	paramSymbolsMap[3] = symbolicNamesMap;
	funcParamsMap["fmtmsg"] = paramSymbolsMap;

	//
	// #include <fnmatch.h>
	// int fnmatch(const char *pattern, const char *string, int flags);
	//
	paramSymbolsMap.clear();
	// flags
	symbolicNamesMap.clear();
	// Info from: <fnmatch.h>
	symbolicNamesMap[1 << 0] = "FNM_PATHNAME";
	// symbolicNamesMap[1 << 0] = "FNM_FILE_NAME"; // synonym for FNM_PATHNAME
	symbolicNamesMap[1 << 1] = "FNM_NOESCAPE";
	symbolicNamesMap[1 << 3] = "FNM_LEADING_DIR ";
	symbolicNamesMap[1 << 4] = "FNM_CASEFOLD";
	symbolicNamesMap[1 << 5] = "FNM_EXTMATCH";
	paramSymbolsMap[3] = symbolicNamesMap;
	funcParamsMap["fnmatch"] = paramSymbolsMap;

	//
	// #include <locale.h>
	// locale_t newlocale(int locale_category, const char *locale, locale_t base);
	//
	paramSymbolsMap.clear();
	// category_mask
	paramSymbolsMap[1] = getSymbolicNamesForLocaleCategories();
	funcParamsMap["newlocale"] = paramSymbolsMap;

	//
	// #include <locale.h>
	// char *setlocale(int locale_category, const char *locale);
	//
	paramSymbolsMap.clear();
	// category_mask
	paramSymbolsMap[1] = getSymbolicNamesForLocaleCategories();
	funcParamsMap["setlocale"] = paramSymbolsMap;

	//
	// #include <ndbm.h>
	// DBM *dbm_open(const char *file, int open_flags, mode_t file_mode);
	//
	paramSymbolsMap.clear();
	// open_flags
	paramSymbolsMap[2] = getSymbolicNamesForOpenFlags();
	funcParamsMap["dbm_open"] = paramSymbolsMap;

	//
	// #include <ndbm.h>
	// int dbm_store(DBM *db, datum key, datum content, int store_mode);
	//
	paramSymbolsMap.clear();
	// store_mode
	symbolicNamesMap.clear();
	// Info from: <db.h>
	symbolicNamesMap[0] = "DBM_INSERT";
	symbolicNamesMap[1] = "DBM_REPLACE";
	paramSymbolsMap[4] = symbolicNamesMap;
	funcParamsMap["dbm_store"] = paramSymbolsMap;

	//
	// #include <netdb.h>
	// struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type);
	//
	paramSymbolsMap.clear();
	// type
	paramSymbolsMap[3] = getSymbolicNamesForAddressFamilies();
	funcParamsMap["gethostbyaddr"] = paramSymbolsMap;

	//
	// #include <netdb.h>
	// int gethostbyaddr_r(const void *addr, socklen_t len, int type,
	//                     struct hostent *ret, char *buf, size_t buflen,
	//                     struct hostent **result, int *h_errnop);
	//
	paramSymbolsMap.clear();
	// type
	paramSymbolsMap[3] = getSymbolicNamesForAddressFamilies();
	funcParamsMap["gethostbyaddr_r"] = paramSymbolsMap;

	//
	// #include <netdb.h>
	// struct hostent *gethostbyname2(const char *name, int address_family);
	//
	paramSymbolsMap.clear();
	// address_family
	paramSymbolsMap[2] = getSymbolicNamesForAddressFamilies();
	funcParamsMap["gethostbyname2"] = paramSymbolsMap;

	//
	// #include <netdb.h>
	// int gethostbyname2_r(const char *name, int address_family,
	//                      struct hostent *ret, char *buf, size_t buflen,
	//                      struct hostent **result, int *h_errnop);
	//
	paramSymbolsMap.clear();
	// address_family
	paramSymbolsMap[2] = getSymbolicNamesForAddressFamilies();
	funcParamsMap["gethostbyname2_r"] = paramSymbolsMap;

	//
	// #include <netdb.h>
	// struct netent *getnetbyaddr(uint32_t net, int type);
	//
	paramSymbolsMap.clear();
	// type
	paramSymbolsMap[2] = getSymbolicNamesForAddressFamilies();
	funcParamsMap["getnetbyaddr"] = paramSymbolsMap;

	//
	// #include <netdb.h>
	// int getnetbyaddr_r(uint32_t net, int type, struct netent *result_buf,
	//                    char *buf, size_t buflen, struct netent **result,
	//                    int *h_errnop);
	//
	paramSymbolsMap.clear();
	// type
	paramSymbolsMap[2] = getSymbolicNamesForAddressFamilies();
	funcParamsMap["getnetbyaddr_r"] = paramSymbolsMap;

	//
	// #include "error.h"
	// const char *hstrerror(int err_num);
	//
	paramSymbolsMap.clear();
	// err_num
	paramSymbolsMap[2] = getSymbolicNamesForErrors();
	funcParamsMap["hstrerror"] = paramSymbolsMap;

	//
	// #include <nl_types.h>
	// nl_catd catopen(const char *name, int flag);
	//
	paramSymbolsMap.clear();
	// flag
	symbolicNamesMap.clear();
	// Info from: <nl_types.h>
	symbolicNamesMap[1] = "NL_CAT_LOCALE";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["catopen"] = paramSymbolsMap;

	//
	// #include <pthread.h>
	// int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate);
	//
	paramSymbolsMap.clear();
	// detachstate
	symbolicNamesMap.clear();
	// Info from: <pthread.h>
	symbolicNamesMap[0] = "PTHREAD_CREATE_JOINABLE";
	symbolicNamesMap[1] = "PTHREAD_CREATE_DETACHED";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["pthread_attr_setdetachstate"] = paramSymbolsMap;

	//
	// #include "error.h"
	// int pthread_attr_setinheritsched(pthread_attr_t *attr, int inheritsched);
	//
	paramSymbolsMap.clear();
	// inheritsched
	symbolicNamesMap.clear();
	// Info from: <pthread.h>
	symbolicNamesMap[0] = "PTHREAD_INHERIT_SCHED";
	symbolicNamesMap[1] = "PTHREAD_EXPLICIT_SCHED";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["pthread_attr_setinheritsched"] = paramSymbolsMap;

	//
	// #include <pthread.h>
	// int pthread_attr_setschedpolicy(pthread_attr_t *attr, int policy);
	//
	paramSymbolsMap.clear();
	// policy
	paramSymbolsMap[2] = getSymbolicNamesForSchedPolicies();
	funcParamsMap["pthread_attr_setschedpolicy"] = paramSymbolsMap;

	//
	// #include "error.h"
	// int pthread_attr_setscope(pthread_attr_t *attr, int scope);
	//
	paramSymbolsMap.clear();
	// scope
	symbolicNamesMap.clear();
	// Info from: <pthread.h>
	symbolicNamesMap[0] = "PTHREAD_SCOPE_SYSTEM";
	symbolicNamesMap[1] = "PTHREAD_SCOPE_PROCESS";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["pthread_attr_setscope"] = paramSymbolsMap;

	//
	// #include <pthread.h>
	// int pthread_mutexattr_setprotocol(pthread_mutexattr_t *attr, int protocol);
	//
	paramSymbolsMap.clear();
	// protocol
	symbolicNamesMap.clear();
	// Info from: <pthread.h>
	symbolicNamesMap[0] = "PTHREAD_PRIO_NONE";
	symbolicNamesMap[1] = "PTHREAD_PRIO_INHERIT";
	symbolicNamesMap[1] = "PTHREAD_PRIO_PROTECT";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["pthread_mutexattr_setprotocol"] = paramSymbolsMap;

	//
	// #include "error.h"
	// int pthread_mutexattr_setrobust(pthread_mutexattr_t *attr, int robust);
	//
	paramSymbolsMap.clear();
	// robust
	symbolicNamesMap.clear();
	// Info from: <pthread.h>
	symbolicNamesMap[0] = "PTHREAD_MUTEX_STALLED";
	symbolicNamesMap[1] = "PTHREAD_MUTEX_ROBUST";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["pthread_mutexattr_setrobust"] = paramSymbolsMap;

	//
	// #include <pthread.h>
	// int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type);
	//
	paramSymbolsMap.clear();
	// type
	symbolicNamesMap.clear();
	// Info from: <pthread.h>
	symbolicNamesMap[0] = "PTHREAD_MUTEX_NORMAL";
	// symbolicNamesMap[0] = "PTHREAD_MUTEX_DEFAULT"; // synonym for PTHREAD_MUTEX_NORMAL
	symbolicNamesMap[1] = "PTHREAD_MUTEX_RECURSIVE";
	symbolicNamesMap[2] = "PTHREAD_MUTEX_ERRORCHECK";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["pthread_mutexattr_settype"] = paramSymbolsMap;

	//
	// #include <pthread.h>
	// int pthread_setcancelstate(int state, int *oldstate);
	//
	paramSymbolsMap.clear();
	// state
	symbolicNamesMap.clear();
	// Info from: <pthread.h>
	symbolicNamesMap[0] = "PTHREAD_CANCEL_ENABLE";
	symbolicNamesMap[1] = "PTHREAD_CANCEL_DISABLE";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["pthread_setcancelstate"] = paramSymbolsMap;

	//
	// #include <pthread.h>
	// int pthread_setcanceltype(int type, int *oldtype);
	//
	paramSymbolsMap.clear();
	// type
	symbolicNamesMap.clear();
	// Info from: <pthread.h>
	symbolicNamesMap[0] = "PTHREAD_CANCEL_DEFERRED";
	symbolicNamesMap[1] = "PTHREAD_CANCEL_ASYNCHRONOUS";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["pthread_setcanceltype"] = paramSymbolsMap;

	//
	// #include <pthread.h>
	// int pthread_setschedparam(pthread_t thread, int policy,
	//                           const struct sched_param *param);
	//
	paramSymbolsMap.clear();
	// policy
	paramSymbolsMap[2] = getSymbolicNamesForSchedPolicies();
	funcParamsMap["pthread_setschedparam"] = paramSymbolsMap;

	//
	// #include <spawn.h>
	// int posix_spawnattr_setschedpolicy(posix_spawnattr_t *attr, int policy);
	//
	paramSymbolsMap.clear();
	// policy
	paramSymbolsMap[2] = getSymbolicNamesForSchedPolicies();
	funcParamsMap["posix_spawnattr_setschedpolicy"] = paramSymbolsMap;

	//
	// #include <pthread.h>
	// int sched_get_priority_max(int policy);
	//
	paramSymbolsMap.clear();
	// policy
	paramSymbolsMap[1] = getSymbolicNamesForSchedPolicies();
	funcParamsMap["sched_get_priority_max"] = paramSymbolsMap;

	//
	// #include <pthread.h>
	// int sched_get_priority_min(int policy);
	//
	paramSymbolsMap.clear();
	// policy
	paramSymbolsMap[1] = getSymbolicNamesForSchedPolicies();
	funcParamsMap["sched_get_priority_min"] = paramSymbolsMap;

	//
	// #include <sched.h>
	// int sched_setscheduler(pid_t pid, int policy,
	//                        const struct sched_param *param);
	//
	paramSymbolsMap.clear();
	// policy
	paramSymbolsMap[2] = getSymbolicNamesForSchedPolicies();
	funcParamsMap["sched_setscheduler"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// sighandler_t signal(int sig, sighandler_t handler);
	//
	paramSymbolsMap.clear();
	// sig
	paramSymbolsMap[1] = getSymbolicNamesForSignals();
	// handler
	paramSymbolsMap[2] = getSymbolicNamesForSignalHandlers();
	funcParamsMap["signal"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// int gsignal(int sig);
	//
	paramSymbolsMap.clear();
	// sig
	paramSymbolsMap[1] = getSymbolicNamesForSignals();
	funcParamsMap["gsignal"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// int kill(pid_t pid, int sig);
	//
	paramSymbolsMap.clear();
	// sig
	paramSymbolsMap[2] = getSymbolicNamesForSignals();
	funcParamsMap["kill"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// int killpg(pid_t pgrp, int sig);
	//
	paramSymbolsMap.clear();
	// sig
	paramSymbolsMap[2] = getSymbolicNamesForSignals();
	funcParamsMap["killpg"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// void psignal(int sig, const char *s);
	//
	paramSymbolsMap.clear();
	// sig
	paramSymbolsMap[1] = getSymbolicNamesForSignals();
	funcParamsMap["psignal"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// int pthread_kill(pthread_t thread, int sig);
	//
	paramSymbolsMap.clear();
	// sig
	paramSymbolsMap[2] = getSymbolicNamesForSignals();
	funcParamsMap["pthread_kill"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset);
	//
	paramSymbolsMap.clear();
	// how
	paramSymbolsMap[1] = getSymbolicNamesForSignalMaskActions();
	funcParamsMap["pthread_sigmask"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// int sigaction(int sig, const struct sigaction *restrict act,
	//               struct sigaction *restrict oact);
	//
	paramSymbolsMap.clear();
	// sig
	paramSymbolsMap[1] = getSymbolicNamesForSignals();
	funcParamsMap["sigaction"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// int sigaddset(sigset_t *set, int sig);
	//
	paramSymbolsMap.clear();
	// sig
	paramSymbolsMap[2] = getSymbolicNamesForSignals();
	funcParamsMap["sigaddset"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// int sigdelset(sigset_t *set, int sig);
	//
	paramSymbolsMap.clear();
	// sig
	paramSymbolsMap[2] = getSymbolicNamesForSignals();
	funcParamsMap["sigdelset"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// int siginterrupt(int sig, int flag);
	//
	paramSymbolsMap.clear();
	// sig
	paramSymbolsMap[1] = getSymbolicNamesForSignals();
	funcParamsMap["siginterrupt"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// int sigismember(const sigset_t *set, int sig);
	//
	paramSymbolsMap.clear();
	// sig
	paramSymbolsMap[2] = getSymbolicNamesForSignals();
	funcParamsMap["sigismember"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
	//
	paramSymbolsMap.clear();
	// how
	paramSymbolsMap[1] = getSymbolicNamesForSignalMaskActions();
	funcParamsMap["sigprocmask"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// int sigqueue(pid_t pid, int sig, const union sigval value);
	//
	paramSymbolsMap.clear();
	// sig
	paramSymbolsMap[2] = getSymbolicNamesForSignals();
	funcParamsMap["sigqueue"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// int sigvec(int sig, const struct sigvec *vec, struct sigvec *ovec);
	//
	paramSymbolsMap.clear();
	// sig
	paramSymbolsMap[1] = getSymbolicNamesForSignals();
	funcParamsMap["sigvec"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// sighandler_t ssignal(int sig, sighandler_t action);
	//
	paramSymbolsMap.clear();
	// sig
	paramSymbolsMap[1] = getSymbolicNamesForSignals();
	// action
	symbolicNamesMap.clear();
	paramSymbolsMap[2] = getSymbolicNamesForSignalHandlers();
	funcParamsMap["ssignal"] = paramSymbolsMap;

	//
	// #include <spawn.h>
	// int posix_spawn_file_actions_addopen(
	//         posix_spawn_file_actions_t *restrict file_actions,
	//         int fildes,
	//         const char *restrict path,
	//         int oflag,
	//         mode_t mode);
	//
	paramSymbolsMap.clear();
	// oflag
	paramSymbolsMap[4] = getSymbolicNamesForOpenFlags();
	// mode
	paramSymbolsMap[5] = getSymbolicNamesForPermMode();
	funcParamsMap["posix_spawn_file_actions_addopen"] = paramSymbolsMap;

	//
	// #include <stdio.h>
	// int fseeko(FILE *stream, off_t offset, int whence);
	//
	paramSymbolsMap.clear();
	// whence
	paramSymbolsMap[3] = getSymbolicNamesForSeekWhence();
	funcParamsMap["fseeko"] = paramSymbolsMap;

	//
	// #include <signal.h>
	// char *strsignal(int sig);
	//
	paramSymbolsMap.clear();
	// sig
	paramSymbolsMap[1] = getSymbolicNamesForSignals();
	funcParamsMap["strsignal"] = paramSymbolsMap;

	//
	// #include <stropts.h>
	// int putmsg(int fildes, const struct strbuf *ctlptr,
	//            const struct strbuf *dataptr, int flags);
	//
	paramSymbolsMap.clear();
	// flags
	symbolicNamesMap.clear();
	// Info from: <bits/stropts.h>
	symbolicNamesMap[0x01] = "RS_HIPRI";
	paramSymbolsMap[4] = symbolicNamesMap;
	funcParamsMap["putmsg"] = paramSymbolsMap;

	//
	// #include <stropts.h>
	// int putpmsg(int fildes, const struct strbuf *ctlptr,
	//             const struct strbuf *dataptr, int band, int flags);
	//
	paramSymbolsMap.clear();
	// flags
	symbolicNamesMap.clear();
	// Info from: <bits/stropts.h>
	symbolicNamesMap[0x01] = "MSG_HIPRI";
	symbolicNamesMap[0x02] = "MSG_ANY";
	symbolicNamesMap[0x04] = "MSG_BAND";
	paramSymbolsMap[5] = symbolicNamesMap;
	funcParamsMap["putpmsg"] = paramSymbolsMap;

	//
	// #include "sys/file.h"
	// int flock(int fd, int operation);
	//
	paramSymbolsMap.clear();
	// operation
	symbolicNamesMap.clear();
	// Info from: <sys/file.h>
	symbolicNamesMap[1] = "LOCK_SH";
	symbolicNamesMap[2] = "LOCK_EX";
	symbolicNamesMap[4] = "LOCK_NB";
	symbolicNamesMap[8] = "LOCK_UN";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["flock"] = paramSymbolsMap;

	//
	// #include <sys/mman.h>
	// int mlockall(int flags);
	//
	paramSymbolsMap.clear();
	// flags
	symbolicNamesMap.clear();
	// Info from: <asm-generic/mman.h>
	symbolicNamesMap[1] = "MCL_CURRENT";
	symbolicNamesMap[2] = "MCL_FUTURE";
	paramSymbolsMap[1] = symbolicNamesMap;
	funcParamsMap["mlockall"] = paramSymbolsMap;

	//
	// #include <sys/mman.h>
	// int shm_open(const char *name, int oflag, mode_t mode);
	//
	paramSymbolsMap.clear();
	// oflag
	paramSymbolsMap[2] = getSymbolicNamesForOpenFlags();
	// mode
	paramSymbolsMap[3] = getSymbolicNamesForPermMode();
	funcParamsMap["shm_open"] = paramSymbolsMap;

	//
	// #include <sys/msg.h>
	// int msgctl(int msqid, int cmd, struct msqid_ds *buf);
	//
	paramSymbolsMap.clear();
	// cmd
	symbolicNamesMap.clear();
	// Info from: <bits/ipc.h>
	symbolicNamesMap[0] = "IPC_RMID";
	symbolicNamesMap[1] = "IPC_SET";
	symbolicNamesMap[2] = "IPC_STAT";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["msgctl"] = paramSymbolsMap;

	//
	// #include "sys/prctl.h"
	// #include "linux/prctl.h"
	// int prctl(int option, unsigned long arg2, unsigned long arg3,
	//           unsigned long arg4, unsigned long arg5);
	//
	paramSymbolsMap.clear();
	// option
	symbolicNamesMap.clear();
	// Info from: <linux/prctl.h>
	symbolicNamesMap[1] = "PR_SET_PDEATHSIG";
	symbolicNamesMap[2] = "PR_GET_PDEATHSIG";
	symbolicNamesMap[3] = "PR_GET_DUMPABLE";
	symbolicNamesMap[4] = "PR_SET_DUMPABLE";
	symbolicNamesMap[5] = "PR_GET_UNALIGN";
	symbolicNamesMap[6] = "PR_SET_UNALIGN";
	symbolicNamesMap[7] = "PR_GET_KEEPCAPS";
	symbolicNamesMap[8] = "PR_SET_KEEPCAPS";
	symbolicNamesMap[9] = "PR_GET_FPEMU";
	symbolicNamesMap[10] = "PR_SET_FPEMU";
	symbolicNamesMap[11] = "PR_GET_FPEXC";
	symbolicNamesMap[12] = "PR_SET_FPEXC";
	symbolicNamesMap[13] = "PR_GET_TIMING";
	symbolicNamesMap[14] = "PR_SET_TIMING";
	symbolicNamesMap[15] = "PR_SET_NAME";
	symbolicNamesMap[16] = "PR_GET_NAME";
	symbolicNamesMap[19] = "PR_GET_ENDIAN";
	symbolicNamesMap[20] = "PR_SET_ENDIAN";
	symbolicNamesMap[21] = "PR_GET_SECCOMP";
	symbolicNamesMap[22] = "PR_SET_SECCOMP";
	symbolicNamesMap[23] = "PR_CAPBSET_READ";
	symbolicNamesMap[24] = "PR_CAPBSET_DROP";
	symbolicNamesMap[25] = "PR_GET_TSC";
	symbolicNamesMap[26] = "PR_SET_TSC";
	symbolicNamesMap[27] = "PR_GET_SECUREBITS";
	symbolicNamesMap[28] = "PR_SET_SECUREBITS";
	symbolicNamesMap[29] = "PR_SET_TIMERSLACK";
	symbolicNamesMap[30] = "PR_GET_TIMERSLACK";
	symbolicNamesMap[31] = "PR_TASK_PERF_EVENTS_DISABLE";
	symbolicNamesMap[32] = "PR_TASK_PERF_EVENTS_ENABLE";
	symbolicNamesMap[33] = "PR_MCE_KILL";
	symbolicNamesMap[34] = "PR_MCE_KILL_GET";
	symbolicNamesMap[35] = "PR_SET_MM";
	symbolicNamesMap[36] = "PR_SET_CHILD_SUBREAPER";
	symbolicNamesMap[37] = "PR_GET_CHILD_SUBREAPER";
	symbolicNamesMap[38] = "PR_SET_NO_NEW_PRIVS";
	symbolicNamesMap[39] = "PR_GET_NO_NEW_PRIVS";
	symbolicNamesMap[40] = "PR_GET_TID_ADDRESS";
	paramSymbolsMap[1] = symbolicNamesMap;
	funcParamsMap["prctl"] = paramSymbolsMap;

	//
	// #include <sys/resource.h>
	// int getpriority(int which, id_t who);
	//
	paramSymbolsMap.clear();
	// which
	paramSymbolsMap[1] = getSymbolicNamesForPrioType();
	funcParamsMap["getpriority"] = paramSymbolsMap;

	//
	// #include <sys/resource.h>
	// int getrlimit(int resource, struct rlimit *rlp);
	//
	paramSymbolsMap.clear();
	// resource
	paramSymbolsMap[1] = getSymbolicNamesForResources();
	funcParamsMap["getrlimit"] = paramSymbolsMap;

	//
	// #include <sys/resource.h>
	// int setrlimit(int resource, struct rlimit *rlp);
	//
	paramSymbolsMap.clear();
	// resource
	paramSymbolsMap[1] = getSymbolicNamesForResources();
	funcParamsMap["setrlimit"] = paramSymbolsMap;

	//
	// #include <sys/resource.h>
	// int getrusage(int who, struct rusage *r_usage);
	//
	// who
	symbolicNamesMap.clear();
	// Info from: <bits/resource.h>
	symbolicNamesMap[0] = "RUSAGE_SELF";
	symbolicNamesMap[-1] = "RUSAGE_CHILDREN";
	symbolicNamesMap[1] = "RUSAGE_THREAD";
	paramSymbolsMap[3] = symbolicNamesMap;
	funcParamsMap["getrusage"] = paramSymbolsMap;

	//
	// #include <sys/resource.h>
	// int setpriority(int which, id_t who, int value);
	//
	paramSymbolsMap.clear();
	// which
	paramSymbolsMap[1] = getSymbolicNamesForPrioType();
	funcParamsMap["setpriority"] = paramSymbolsMap;

	//
	// #include <sys/sem.h>
	// int semctl(int semid, int semnum, int cmd, ...);
	//
	paramSymbolsMap.clear();
	// cmd
	symbolicNamesMap.clear();
	// Info from: <bits/sem.h>
	symbolicNamesMap[11] = "GETPID";
	symbolicNamesMap[12] = "GETVAL";
	symbolicNamesMap[13] = "GETALL";
	symbolicNamesMap[14] = "GETNCNT";
	symbolicNamesMap[15] = "GETZCNT";
	symbolicNamesMap[16] = "SETVAL";
	symbolicNamesMap[17] = "SETALL";
	// Info from: <bits/ipc.h>
	symbolicNamesMap[0] = "IPC_RMID";
	symbolicNamesMap[1] = "IPC_SET";
	symbolicNamesMap[2] = "IPC_STAT";
	paramSymbolsMap[3] = symbolicNamesMap;
	funcParamsMap["semctl"] = paramSymbolsMap;

	//
	// #include <sys/shm.h>
	// int shmctl(int shmid, int cmd, struct shmid_ds *buf);
	//
	paramSymbolsMap.clear();
	// cmd
	symbolicNamesMap.clear();
	// Info from: <bits/ipc.h>
	symbolicNamesMap[0] = "IPC_RMID";
	symbolicNamesMap[1] = "IPC_SET";
	symbolicNamesMap[2] = "IPC_STAT";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["shmctl"] = paramSymbolsMap;

	//
	// #include <sys/socket.h>
	// #include <netdb.h>
	// int getnameinfo(const struct sockaddr *sa, socklen_t salen,
	//                 char *host, socklen_t hostlen, char *serv,
	//                 socklen_t servlen, int flags);
	//
	paramSymbolsMap.clear();
	// flags
	symbolicNamesMap.clear();
	// Info from: <netdb.h>
	symbolicNamesMap[1] = "NI_NUMERICHOST";
	symbolicNamesMap[2] = "NI_NUMERICSERV";
	symbolicNamesMap[4] = "NI_NOFQDN";
	symbolicNamesMap[8] = "NI_NAMEREQD";
	symbolicNamesMap[16] = "NI_DGRAM";
	symbolicNamesMap[32] = "NI_IDN";
	symbolicNamesMap[64] = "NI_IDN_ALLOW_UNASSIGNED";
	symbolicNamesMap[128] = "NI_IDN_USE_STD3_ASCII_RULES";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["getnameinfo"] = paramSymbolsMap;

	//
	// #include <sys/socket.h>
	//
	// int getsockopt(int socket, int level, int option_name,
	//                void *restrict option_value,
	//                socklen_t *restrict option_len);
	//
	paramSymbolsMap.clear();
	// level
	paramSymbolsMap[1] = getSymbolicNamesForSocketLevels();
	// option_name
	paramSymbolsMap[2] = getSymbolicNamesForSocketOptions();
	funcParamsMap["getsockopt"] = paramSymbolsMap;

	//
	// #include <sys/socket.h>
	// ssize_t recv(int socket, void *buffer, size_t length, int flags);
	//
	paramSymbolsMap.clear();
	// flags
	paramSymbolsMap[4] = getSymbolicNamesForMessageFlags();
	funcParamsMap["recv"] = paramSymbolsMap;

	//
	// #include <sys/socket.h>
	// ssize_t recvfrom(int socket, void *restrict buffer, size_t length,
	//                  int flags, struct sockaddr *restrict address,
	//                  socklen_t *restrict address_len);
	//
	paramSymbolsMap.clear();
	// flags
	paramSymbolsMap[4] = getSymbolicNamesForMessageFlags();
	funcParamsMap["recvfrom"] = paramSymbolsMap;

	//
	// #include <sys/socket.h>
	// ssize_t recvmsg(int socket, struct msghdr *message, int flags);
	//
	paramSymbolsMap.clear();
	// flags
	paramSymbolsMap[3] = getSymbolicNamesForMessageFlags();
	funcParamsMap["recvmsg"] = paramSymbolsMap;

	//
	// #include <sys/socket.h>
	// ssize_t send(int socket, const void *buffer, size_t length, int flags);
	//
	paramSymbolsMap.clear();
	// flags
	paramSymbolsMap[4] = getSymbolicNamesForMessageFlags();
	funcParamsMap["send"] = paramSymbolsMap;

	//
	// #include <sys/socket.h>
	// ssize_t send(int socket, const void *buffer, size_t length, int flags);
	//
	paramSymbolsMap.clear();
	// flags
	paramSymbolsMap[4] = getSymbolicNamesForMessageFlags();
	funcParamsMap["send"] = paramSymbolsMap;

	//
	// #include <sys/socket.h>
	// ssize_t sendto(int socket, const void *message, size_t length, int flags,
	//                const struct sockaddr *dest_addr, socklen_t dest_len);
	//
	paramSymbolsMap.clear();
	// flags
	paramSymbolsMap[4] = getSymbolicNamesForMessageFlags();
	funcParamsMap["sendto"] = paramSymbolsMap;

	//
	// #include <sys/socket.h>
	//
	// int setsockopt(int socket, int level, int option_name,
	//                const void *option_value, socklen_t option_len);
	//
	paramSymbolsMap.clear();
	// level
	paramSymbolsMap[1] = getSymbolicNamesForSocketLevels();
	// option_name
	paramSymbolsMap[2] = getSymbolicNamesForSocketOptions();
	funcParamsMap["setsockopt"] = paramSymbolsMap;

	//
	// #include <sys/socket.h>
	// int shutdown(int socket, int how);
	//
	// how
	symbolicNamesMap.clear();
	// Info from: <sys/socket.h>
	symbolicNamesMap[0] = "SHUT_RD";
	symbolicNamesMap[1] = "SHUT_WR";
	symbolicNamesMap[2] = "SHUT_RDWR";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["shutdown"] = paramSymbolsMap;

	//
	// #include <sys/socket.h>
	// int socket(int domain, int type, int protocol);
	//
	paramSymbolsMap.clear();
	// domain
	paramSymbolsMap[1] = getSymbolicNamesForAddressFamilies();
	// type
	paramSymbolsMap[2] = getSymbolicNamesForSocketTypes();
	// protocol
	paramSymbolsMap[3] = getSymbolicNamesForIPProtocols();
	funcParamsMap["socket"] = paramSymbolsMap;

	//
	// #include <sys/socket.h>
	// int socketpair(int domain, int type, int protocol, int socket_vector[2]);
	//
	paramSymbolsMap.clear();
	// domain
	paramSymbolsMap[1] = getSymbolicNamesForAddressFamilies();
	// type
	paramSymbolsMap[2] = getSymbolicNamesForSocketTypes();
	// protocol
	paramSymbolsMap[3] = getSymbolicNamesForIPProtocols();
	funcParamsMap["socketpair"] = paramSymbolsMap;

	//
	// #include <sys/stat.h>
	// int fchmodat(int fd, const char *path, mode_t mode, int flag);
	//
	paramSymbolsMap.clear();
	// flag
	paramSymbolsMap[2] = getSymbolicNamesForAccessTypes();
	funcParamsMap["fchmodat"] = paramSymbolsMap;

	//
	// #include <sys/stat.h>
	// int fstatat(int fd, const char *restrict path,
	//             struct stat *restrict buf, int flag);
	//
	paramSymbolsMap.clear();
	// flag
	paramSymbolsMap[4] = getSymbolicNamesForAccessTypes();
	funcParamsMap["fstatat"] = paramSymbolsMap;

	//
	// #include <sys/stat.h>
	// int utimensat(int fd, const char *path,
	//               const struct timespec times[2], int flag);
	//
	paramSymbolsMap.clear();
	// flag
	paramSymbolsMap[4] = getSymbolicNamesForAccessTypes();
	funcParamsMap["utimensat"] = paramSymbolsMap;

	//
	// #include <sys/time.h>
	// int getitimer(int which, struct itimerval *value);
	//
	paramSymbolsMap.clear();
	// which
	paramSymbolsMap[1] = getSymbolicNamesForITimers();
	funcParamsMap["getitimer"] = paramSymbolsMap;

	//
	// #include <sys/time.h>
	// int setitimer(int which, const struct itimerval *restrict value,
	//               struct itimerval *restrict ovalue);
	//
	paramSymbolsMap.clear();
	// which
	paramSymbolsMap[1] = getSymbolicNamesForITimers();
	funcParamsMap["setitimer"] = paramSymbolsMap;

	//
	// #include <regex.h>
	// int regcomp(regex_t *preg, const char *regex, int cflags);
	//
	paramSymbolsMap.clear();
	// cflags
	symbolicNamesMap.clear();
	// Info from: <regex.h>
	symbolicNamesMap[1] = "REG_EXTENDED";
	symbolicNamesMap[2] = "REG_ICASE";
	symbolicNamesMap[4] = "REG_NEWLINE";
	symbolicNamesMap[8] = "REG_NOSUB";
	paramSymbolsMap[1] = symbolicNamesMap;
	funcParamsMap["regcomp"] = paramSymbolsMap;

	//
	// #include <regex.h>
	// int regexec(const regex_t *preg, const char *string, size_t nmatch,
	//             regmatch_t pmatch[], int eflags);
	//
	paramSymbolsMap.clear();
	// eflags
	symbolicNamesMap.clear();
	// Info from: <regex.h>
	symbolicNamesMap[1] = "REG_NOTBOL";
	symbolicNamesMap[2] = "REG_NOTEOL";
	symbolicNamesMap[4] = "REG_STARTEND";
	paramSymbolsMap[5] = symbolicNamesMap;
	funcParamsMap["regexec"] = paramSymbolsMap;

	//
	// #include <sys/wait.h>
	// pid_t waitpid(pid_t pid, int *status, int options);
	//
	paramSymbolsMap.clear();
	// options
	paramSymbolsMap[3] = getSymbolicNamesForWaitOptions();
	funcParamsMap["waitpid"] = paramSymbolsMap;

	//
	// #include <sys/wait.h>
	// int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
	//
	paramSymbolsMap.clear();
	// options
	paramSymbolsMap[4] = getSymbolicNamesForWaitOptions();
	funcParamsMap["waitid"] = paramSymbolsMap;

	//
	// #include <sys/wait.h>
	// pid_t wait3(int *status, int options, struct rusage *rusage);
	//
	paramSymbolsMap.clear();
	// options
	paramSymbolsMap[2] = getSymbolicNamesForWaitOptions();
	funcParamsMap["wait3"] = paramSymbolsMap;

	//
	// #include <sys/wait.h>
	// pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage);
	//
	paramSymbolsMap.clear();
	// options
	paramSymbolsMap[3] = getSymbolicNamesForWaitOptions();
	funcParamsMap["wait4"] = paramSymbolsMap;

	//
	// #include <syslog.h>
	// void openlog(const char *ident, int option, int facility);
	//
	paramSymbolsMap.clear();
	// option
	paramSymbolsMap[2] = getSymbolicNamesForLogOptions();
	// facility
	paramSymbolsMap[3] = getSymbolicNamesForLogFacilities();
	funcParamsMap["openlog"] = paramSymbolsMap;

	//
	// #include <syslog.h>
	// void syslog(int priority, const char *format, ...);
	//
	paramSymbolsMap.clear();
	// priority
	paramSymbolsMap[1] = getSymbolicNamesForLogPriorities();
	funcParamsMap["syslog"] = paramSymbolsMap;

	//
	// #include <syslog.h>
	// void vsyslog(int priority, const char *format, va_list ap);
	//
	paramSymbolsMap.clear();
	// priority
	paramSymbolsMap[1] = getSymbolicNamesForLogPriorities();
	funcParamsMap["vsyslog"] = paramSymbolsMap;

	//
	// #include <termios.h>
	// int tcsetattr(int fd, int optional_actions,
	//               const struct termios *termios_p);
	//
	paramSymbolsMap.clear();
	// optional_actions
	symbolicNamesMap.clear();
	// Info from: <bits/termios.h>
	symbolicNamesMap[0] = "TCSANOW";
	symbolicNamesMap[1] = "TCSADRAIN";
	symbolicNamesMap[2] = "TCSAFLUSH";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["tcsetattr"] = paramSymbolsMap;

	//
	// #include <termios.h>
	// int tcflow(int fd, int action);
	//
	paramSymbolsMap.clear();
	// action
	symbolicNamesMap.clear();
	// Info from: <bits/termios.h>
	symbolicNamesMap[0] = "TCOOFF";
	symbolicNamesMap[1] = "TCOON";
	symbolicNamesMap[2] = "TCIOFF";
	symbolicNamesMap[3] = "TCION";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["tcflow"] = paramSymbolsMap;

	//
	// #include <termios.h>
	// int tcflush(int fd, int queue_selector);
	//
	paramSymbolsMap.clear();
	// queue_selector
	symbolicNamesMap.clear();
	// Info from: <bits/termios.h>
	symbolicNamesMap[0] = "TCIFLUSH";
	symbolicNamesMap[1] = "TCOFLUSH";
	symbolicNamesMap[2] = "TCIOFLUSH";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["tcflush"] = paramSymbolsMap;

	//
	// #include <time.h>
	// int clock_nanosleep(clockid_t clock_id, int flags,
	//                     const struct timespec *rqtp,
	//                     struct timespec *rmtp);
	//
	paramSymbolsMap.clear();
	// flags
	paramSymbolsMap[2] = getSymbolicNamesForTimeFlags();
	funcParamsMap["clock_nanosleep"] = paramSymbolsMap;

	//
	// #include <time.h>
	// int timer_settime(timer_t timerid, int flags,
	//                   const struct itimerspec *restrict value,
	//                   struct itimerspec *restrict ovalue);
	//
	paramSymbolsMap.clear();
	// flags
	paramSymbolsMap[2] = getSymbolicNamesForTimeFlags();
	funcParamsMap["timer_settime"] = paramSymbolsMap;

	//
	// #include <ulimit.h>
	// long ulimit(int cmd, long newlimit);
	//
	paramSymbolsMap.clear();
	// cmd
	symbolicNamesMap.clear();
	// Info from: <fcntl.h>
	symbolicNamesMap[1] = "UL_GETFSIZE";
	symbolicNamesMap[2] = "UL_SETFSIZE";
	paramSymbolsMap[1] = symbolicNamesMap;
	funcParamsMap["ulimit"] = paramSymbolsMap;

	//
	// #include <unistd.h>
	// int access(const char *path, int amode);
	//
	paramSymbolsMap.clear();
	// amode
	paramSymbolsMap[2] = getSymbolicNamesForAccessModes();
	funcParamsMap["access"] = paramSymbolsMap;

	//
	// #include <unistd.h>
	// size_t confstr(int name, char *buf, size_t len);
	//
	paramSymbolsMap.clear();
	// name
	symbolicNamesMap.clear();
	// Info from: <bits/confname.h>
	symbolicNamesMap[0] = "_CS_PATH";
	symbolicNamesMap[2] = "_CS_GNU_LIBC_VERSION";
	symbolicNamesMap[3] = "_CS_GNU_LIBPTHREAD_VERSION";
	paramSymbolsMap[1] = symbolicNamesMap;
	funcParamsMap["confstr"] = paramSymbolsMap;

	//
	// #include <unistd.h>
	// int faccessat(int fd, const char *path, int amode, int flag);
	//
	paramSymbolsMap.clear();
	// amode
	paramSymbolsMap[3] = getSymbolicNamesForAccessModes();
	// flag
	paramSymbolsMap[4] = getSymbolicNamesForAccessTypes();
	funcParamsMap["faccessat"] = paramSymbolsMap;

	//
	// #include <unistd.h>
	// int fchownat(int fd, const char *path, uid_t owner,
	//              gid_t group, int flag);
	//
	paramSymbolsMap.clear();
	// flag
	paramSymbolsMap[5] = getSymbolicNamesForAccessTypes();
	funcParamsMap["fchownat"] = paramSymbolsMap;

	//
	// #include <unistd.h>
	// long fpathconf(int fd, int name);
	//
	paramSymbolsMap.clear();
	// name
	paramSymbolsMap[2] = getSymbolicNamesForPathConfs();
	funcParamsMap["fpathconf"] = paramSymbolsMap;

	//
	// #include <unistd.h>
	// long pathconf(const char *path, int name);
	//
	paramSymbolsMap.clear();
	// name
	paramSymbolsMap[2] = getSymbolicNamesForPathConfs();
	funcParamsMap["pathconf"] = paramSymbolsMap;

	//
	// #include <unistd.h>
	// int linkat(int fd1, const char *path1, int fd2,
	//            const char *path2, int flag);
	//
	paramSymbolsMap.clear();
	// flag
	paramSymbolsMap[5] = getSymbolicNamesForAccessTypes();
	funcParamsMap["linkat"] = paramSymbolsMap;

	//
	// #include <unistd.h>
	// int lockf(int fd, int cmd, off_t len);
	//
	paramSymbolsMap.clear();
	// cmd
	symbolicNamesMap.clear();
	// Info from: <fcntl.h>
	symbolicNamesMap[0] = "F_UNLOCK";
	symbolicNamesMap[1] = "F_LOCK";
	symbolicNamesMap[2] = "F_TLOCK";
	symbolicNamesMap[3] = "F_TEST";
	paramSymbolsMap[2] = symbolicNamesMap;
	funcParamsMap["lockf"] = paramSymbolsMap;

	//
	// #include <unistd.h>
	// off_t lseek(int fildes, off_t offset, int whence);
	//
	paramSymbolsMap.clear();
	// whence
	paramSymbolsMap[3] = getSymbolicNamesForSeekWhence();
	funcParamsMap["lseek"] = paramSymbolsMap;

	//
	// #include <unistd.h>
	// long syscall(long number, ...);
	//
	paramSymbolsMap.clear();
	// number
	paramSymbolsMap[1] = getSymbolicNamesForSystemCalls();
	funcParamsMap["syscall"] = paramSymbolsMap;

	//
	// #include <unistd.h>
	// long sysconf(int name);
	//
	paramSymbolsMap.clear();
	// name
	symbolicNamesMap.clear();
	// Info from: <bits/confname.h>
	symbolicNamesMap[0] = "_SC_ARG_MAX";
	symbolicNamesMap[1] = "_SC_CHILD_MAX";
	symbolicNamesMap[2] = "_SC_CLK_TCK";
	symbolicNamesMap[3] = "_SC_NGROUPS_MAX";
	symbolicNamesMap[4] = "_SC_OPEN_MAX";
	symbolicNamesMap[5] = "_SC_STREAM_MAX";
	symbolicNamesMap[6] = "_SC_TZNAME_MAX";
	symbolicNamesMap[7] = "_SC_JOB_CONTROL";
	symbolicNamesMap[8] = "_SC_SAVED_IDS";
	symbolicNamesMap[9] = "_SC_REALTIME_SIGNALS";
	symbolicNamesMap[10] = "_SC_PRIORITY_SCHEDULING";
	symbolicNamesMap[11] = "_SC_TIMERS";
	symbolicNamesMap[12] = "_SC_ASYNCHRONOUS_IO";
	symbolicNamesMap[13] = "_SC_PRIORITIZED_IO";
	symbolicNamesMap[14] = "_SC_SYNCHRONIZED_IO";
	symbolicNamesMap[15] = "_SC_FSYNC";
	symbolicNamesMap[16] = "_SC_MAPPED_FILES";
	symbolicNamesMap[17] = "_SC_MEMLOCK";
	symbolicNamesMap[18] = "_SC_MEMLOCK_RANGE";
	symbolicNamesMap[19] = "_SC_MEMORY_PROTECTION";
	symbolicNamesMap[20] = "_SC_MESSAGE_PASSING";
	symbolicNamesMap[21] = "_SC_SEMAPHORES";
	symbolicNamesMap[22] = "_SC_SHARED_MEMORY_OBJECTS";
	symbolicNamesMap[23] = "_SC_AIO_LISTIO_MAX";
	symbolicNamesMap[24] = "_SC_AIO_MAX";
	symbolicNamesMap[25] = "_SC_AIO_PRIO_DELTA_MAX";
	symbolicNamesMap[26] = "_SC_DELAYTIMER_MAX";
	symbolicNamesMap[27] = "_SC_MQ_OPEN_MAX";
	symbolicNamesMap[28] = "_SC_MQ_PRIO_MAX";
	symbolicNamesMap[29] = "_SC_VERSION";
	symbolicNamesMap[30] = "_SC_PAGESIZE";
	symbolicNamesMap[31] = "_SC_RTSIG_MAX";
	symbolicNamesMap[32] = "_SC_SEM_NSEMS_MAX";
	symbolicNamesMap[33] = "_SC_SEM_VALUE_MAX";
	symbolicNamesMap[34] = "_SC_SIGQUEUE_MAX";
	symbolicNamesMap[35] = "_SC_TIMER_MAX";
	symbolicNamesMap[36] = "_SC_BC_BASE_MAX";
	symbolicNamesMap[37] = "_SC_BC_DIM_MAX";
	symbolicNamesMap[38] = "_SC_BC_SCALE_MAX";
	symbolicNamesMap[39] = "_SC_BC_STRING_MAX";
	symbolicNamesMap[40] = "_SC_COLL_WEIGHTS_MAX";
	symbolicNamesMap[41] = "_SC_EQUIV_CLASS_MAX";
	symbolicNamesMap[42] = "_SC_EXPR_NEST_MAX";
	symbolicNamesMap[43] = "_SC_LINE_MAX";
	symbolicNamesMap[44] = "_SC_RE_DUP_MAX";
	symbolicNamesMap[45] = "_SC_CHARCLASS_NAME_MAX";
	symbolicNamesMap[46] = "_SC_2_VERSION";
	symbolicNamesMap[47] = "_SC_2_C_BIND";
	symbolicNamesMap[48] = "_SC_2_C_DEV";
	symbolicNamesMap[49] = "_SC_2_FORT_DEV";
	symbolicNamesMap[50] = "_SC_2_FORT_RUN";
	symbolicNamesMap[51] = "_SC_2_SW_DEV";
	symbolicNamesMap[52] = "_SC_2_LOCALEDEF";
	symbolicNamesMap[53] = "_SC_PII";
	symbolicNamesMap[54] = "_SC_PII_XTI";
	symbolicNamesMap[55] = "_SC_PII_SOCKET";
	symbolicNamesMap[56] = "_SC_PII_INTERNET";
	symbolicNamesMap[57] = "_SC_PII_OSI";
	symbolicNamesMap[58] = "_SC_POLL";
	symbolicNamesMap[59] = "_SC_SELECT";
	symbolicNamesMap[60] = "_SC_UIO_MAXIOV";
	symbolicNamesMap[61] = "_SC_IOV_MAX = _SC_UIO_MAXIOV";
	symbolicNamesMap[62] = "_SC_PII_INTERNET_STREAM";
	symbolicNamesMap[63] = "_SC_PII_INTERNET_DGRAM";
	symbolicNamesMap[64] = "_SC_PII_OSI_COTS";
	symbolicNamesMap[65] = "_SC_PII_OSI_CLTS";
	symbolicNamesMap[66] = "_SC_PII_OSI_M";
	symbolicNamesMap[67] = "_SC_T_IOV_MAX";
	symbolicNamesMap[68] = "_SC_THREADS";
	symbolicNamesMap[69] = "_SC_THREAD_SAFE_FUNCTIONS";
	symbolicNamesMap[70] = "_SC_GETGR_R_SIZE_MAX";
	symbolicNamesMap[71] = "_SC_GETPW_R_SIZE_MAX";
	symbolicNamesMap[72] = "_SC_LOGIN_NAME_MAX";
	symbolicNamesMap[73] = "_SC_TTY_NAME_MAX";
	symbolicNamesMap[74] = "_SC_THREAD_DESTRUCTOR_ITERATIONS";
	symbolicNamesMap[75] = "_SC_THREAD_KEYS_MAX";
	symbolicNamesMap[76] = "_SC_THREAD_STACK_MIN";
	symbolicNamesMap[77] = "_SC_THREAD_THREADS_MAX";
	symbolicNamesMap[78] = "_SC_THREAD_ATTR_STACKADDR";
	symbolicNamesMap[79] = "_SC_THREAD_ATTR_STACKSIZE";
	symbolicNamesMap[80] = "_SC_THREAD_PRIORITY_SCHEDULING";
	symbolicNamesMap[81] = "_SC_THREAD_PRIO_INHERIT";
	symbolicNamesMap[82] = "_SC_THREAD_PRIO_PROTECT";
	symbolicNamesMap[83] = "_SC_THREAD_PROCESS_SHARED";
	symbolicNamesMap[84] = "_SC_NPROCESSORS_CONF";
	symbolicNamesMap[85] = "_SC_NPROCESSORS_ONLN";
	symbolicNamesMap[86] = "_SC_PHYS_PAGES";
	symbolicNamesMap[87] = "_SC_AVPHYS_PAGES";
	symbolicNamesMap[88] = "_SC_ATEXIT_MAX";
	symbolicNamesMap[89] = "_SC_PASS_MAX";
	symbolicNamesMap[90] = "_SC_XOPEN_VERSION";
	symbolicNamesMap[91] = "_SC_XOPEN_XCU_VERSION";
	symbolicNamesMap[92] = "_SC_XOPEN_UNIX";
	symbolicNamesMap[93] = "_SC_XOPEN_CRYPT";
	symbolicNamesMap[94] = "_SC_XOPEN_ENH_I18N";
	symbolicNamesMap[95] = "_SC_XOPEN_SHM";
	symbolicNamesMap[96] = "_SC_2_CHAR_TERM";
	symbolicNamesMap[97] = "_SC_2_C_VERSION";
	symbolicNamesMap[98] = "_SC_2_UPE";
	symbolicNamesMap[99] = "_SC_XOPEN_XPG2";
	symbolicNamesMap[100] = "_SC_XOPEN_XPG3";
	symbolicNamesMap[101] = "_SC_XOPEN_XPG4";
	symbolicNamesMap[102] = "_SC_CHAR_BIT";
	symbolicNamesMap[103] = "_SC_CHAR_MAX";
	symbolicNamesMap[104] = "_SC_CHAR_MIN";
	symbolicNamesMap[105] = "_SC_INT_MAX";
	symbolicNamesMap[106] = "_SC_INT_MIN";
	symbolicNamesMap[107] = "_SC_LONG_BIT";
	symbolicNamesMap[108] = "_SC_WORD_BIT";
	symbolicNamesMap[109] = "_SC_MB_LEN_MAX";
	symbolicNamesMap[110] = "_SC_NZERO";
	symbolicNamesMap[111] = "_SC_SSIZE_MAX";
	symbolicNamesMap[112] = "_SC_SCHAR_MAX";
	symbolicNamesMap[113] = "_SC_SCHAR_MIN";
	symbolicNamesMap[114] = "_SC_SHRT_MAX";
	symbolicNamesMap[115] = "_SC_SHRT_MIN";
	symbolicNamesMap[116] = "_SC_UCHAR_MAX";
	symbolicNamesMap[117] = "_SC_UINT_MAX";
	symbolicNamesMap[118] = "_SC_ULONG_MAX";
	symbolicNamesMap[119] = "_SC_USHRT_MAX";
	symbolicNamesMap[120] = "_SC_NL_ARGMAX";
	symbolicNamesMap[121] = "_SC_NL_LANGMAX";
	symbolicNamesMap[122] = "_SC_NL_MSGMAX";
	symbolicNamesMap[123] = "_SC_NL_NMAX";
	symbolicNamesMap[124] = "_SC_NL_SETMAX";
	symbolicNamesMap[125] = "_SC_NL_TEXTMAX";
	symbolicNamesMap[126] = "_SC_XBS5_ILP32_OFF32";
	symbolicNamesMap[127] = "_SC_XBS5_ILP32_OFFBIG";
	symbolicNamesMap[128] = "_SC_XBS5_LP64_OFF64";
	symbolicNamesMap[129] = "_SC_XBS5_LPBIG_OFFBIG";
	symbolicNamesMap[130] = "_SC_XOPEN_LEGACY";
	symbolicNamesMap[131] = "_SC_XOPEN_REALTIME";
	symbolicNamesMap[132] = "_SC_XOPEN_REALTIME_THREADS";
	symbolicNamesMap[133] = "_SC_ADVISORY_INFO";
	symbolicNamesMap[134] = "_SC_BARRIERS";
	symbolicNamesMap[135] = "_SC_BASE";
	symbolicNamesMap[136] = "_SC_C_LANG_SUPPORT";
	symbolicNamesMap[137] = "_SC_C_LANG_SUPPORT_R";
	symbolicNamesMap[138] = "_SC_CLOCK_SELECTION";
	symbolicNamesMap[139] = "_SC_CPUTIME";
	symbolicNamesMap[140] = "_SC_THREAD_CPUTIME";
	symbolicNamesMap[141] = "_SC_DEVICE_IO";
	symbolicNamesMap[142] = "_SC_DEVICE_SPECIFIC";
	symbolicNamesMap[143] = "_SC_DEVICE_SPECIFIC_R";
	symbolicNamesMap[144] = "_SC_FD_MGMT";
	symbolicNamesMap[145] = "_SC_FIFO";
	symbolicNamesMap[146] = "_SC_PIPE";
	symbolicNamesMap[147] = "_SC_FILE_ATTRIBUTES";
	symbolicNamesMap[148] = "_SC_FILE_LOCKING";
	symbolicNamesMap[149] = "_SC_FILE_SYSTEM";
	symbolicNamesMap[150] = "_SC_MONOTONIC_CLOCK";
	symbolicNamesMap[151] = "_SC_MULTI_PROCESS";
	symbolicNamesMap[152] = "_SC_SINGLE_PROCESS";
	symbolicNamesMap[153] = "_SC_NETWORKING";
	symbolicNamesMap[154] = "_SC_READER_WRITER_LOCKS";
	symbolicNamesMap[155] = "_SC_SPIN_LOCKS";
	symbolicNamesMap[156] = "_SC_REGEXP";
	symbolicNamesMap[157] = "_SC_REGEX_VERSION";
	symbolicNamesMap[158] = "_SC_SHELL";
	symbolicNamesMap[159] = "_SC_SIGNALS";
	symbolicNamesMap[160] = "_SC_SPAWN";
	symbolicNamesMap[161] = "_SC_SPORADIC_SERVER";
	symbolicNamesMap[162] = "_SC_THREAD_SPORADIC_SERVER";
	symbolicNamesMap[163] = "_SC_SYSTEM_DATABASE";
	symbolicNamesMap[164] = "_SC_SYSTEM_DATABASE_R";
	symbolicNamesMap[165] = "_SC_TIMEOUTS";
	symbolicNamesMap[166] = "_SC_TYPED_MEMORY_OBJECTS";
	symbolicNamesMap[167] = "_SC_USER_GROUPS";
	symbolicNamesMap[168] = "_SC_USER_GROUPS_R";
	symbolicNamesMap[169] = "_SC_2_PBS";
	symbolicNamesMap[170] = "_SC_2_PBS_ACCOUNTING";
	symbolicNamesMap[171] = "_SC_2_PBS_LOCATE";
	symbolicNamesMap[172] = "_SC_2_PBS_MESSAGE";
	symbolicNamesMap[173] = "_SC_2_PBS_TRACK";
	symbolicNamesMap[174] = "_SC_SYMLOOP_MAX";
	symbolicNamesMap[175] = "_SC_STREAMS";
	symbolicNamesMap[176] = "_SC_2_PBS_CHECKPOINT";
	symbolicNamesMap[177] = "_SC_V6_ILP32_OFF32";
	symbolicNamesMap[178] = "_SC_V6_ILP32_OFFBIG";
	symbolicNamesMap[179] = "_SC_V6_LP64_OFF64";
	symbolicNamesMap[180] = "_SC_V6_LPBIG_OFFBIG";
	symbolicNamesMap[181] = "_SC_HOST_NAME_MAX";
	symbolicNamesMap[182] = "_SC_TRACE";
	symbolicNamesMap[183] = "_SC_TRACE_EVENT_FILTER";
	symbolicNamesMap[184] = "_SC_TRACE_INHERIT";
	symbolicNamesMap[185] = "_SC_TRACE_LOG";
	symbolicNamesMap[186] = "_SC_LEVEL1_ICACHE_SIZE";
	symbolicNamesMap[187] = "_SC_LEVEL1_ICACHE_ASSOC";
	symbolicNamesMap[188] = "_SC_LEVEL1_ICACHE_LINESIZE";
	symbolicNamesMap[189] = "_SC_LEVEL1_DCACHE_SIZE";
	symbolicNamesMap[190] = "_SC_LEVEL1_DCACHE_ASSOC";
	symbolicNamesMap[191] = "_SC_LEVEL1_DCACHE_LINESIZE";
	symbolicNamesMap[192] = "_SC_LEVEL2_CACHE_SIZE";
	symbolicNamesMap[193] = "_SC_LEVEL2_CACHE_ASSOC";
	symbolicNamesMap[194] = "_SC_LEVEL2_CACHE_LINESIZE";
	symbolicNamesMap[195] = "_SC_LEVEL3_CACHE_SIZE";
	symbolicNamesMap[196] = "_SC_LEVEL3_CACHE_ASSOC";
	symbolicNamesMap[197] = "_SC_LEVEL3_CACHE_LINESIZE";
	symbolicNamesMap[198] = "_SC_LEVEL4_CACHE_SIZE";
	symbolicNamesMap[199] = "_SC_LEVEL4_CACHE_ASSOC";
	symbolicNamesMap[200] = "_SC_LEVEL4_CACHE_LINESIZE";
	// Here is a deliberate room for more cache levels.
	symbolicNamesMap[236] = "_SC_IPV6";
	symbolicNamesMap[237] = "_SC_RAW_SOCKETS";
	symbolicNamesMap[238] = "_SC_V7_ILP32_OFF32";
	symbolicNamesMap[239] = "_SC_V7_ILP32_OFFBIG";
	symbolicNamesMap[240] = "_SC_V7_LP64_OFF64";
	symbolicNamesMap[241] = "_SC_V7_LPBIG_OFFBIG";
	symbolicNamesMap[242] = "_SC_SS_REPL_MAX";
	symbolicNamesMap[243] = "_SC_TRACE_EVENT_NAME_MAX";
	symbolicNamesMap[244] = "_SC_TRACE_NAME_MAX";
	symbolicNamesMap[245] = "_SC_TRACE_SYS_MAX";
	symbolicNamesMap[246] = "_SC_TRACE_USER_EVENT_MAX";
	symbolicNamesMap[247] = "_SC_XOPEN_STREAMS";
	symbolicNamesMap[248] = "_SC_THREAD_ROBUST_PRIO_INHERIT";
	symbolicNamesMap[249] = "_SC_THREAD_ROBUST_PRIO_PROTECT";
	paramSymbolsMap[1] = symbolicNamesMap;
	funcParamsMap["sysconf"] = paramSymbolsMap;

	//
	// #include <unistd.h>
	// int unlinkat(int fd, const char *path, int flag);
	//
	paramSymbolsMap.clear();
	// flag
	paramSymbolsMap[3] = getSymbolicNamesForAccessTypes();
	funcParamsMap["unlinkat"] = paramSymbolsMap;

	//
	// #include <wordexp.h>
	// int wordexp(const char *s, wordexp_t *p, int flags);
	//
	paramSymbolsMap.clear();
	// flags
	symbolicNamesMap.clear();
	// Info from: <wordexp.h>
	symbolicNamesMap[1 << 0] = "WRDE_DOOFFS";
	symbolicNamesMap[1 << 1] = "WRDE_APPEND";
	symbolicNamesMap[1 << 2] = "WRDE_NOCMD";
	symbolicNamesMap[1 << 3] = "WRDE_REUSE";
	symbolicNamesMap[1 << 4] = "WRDE_SHOWERR";
	symbolicNamesMap[1 << 5] = "WRDE_UNDEF";
	paramSymbolsMap[3] = symbolicNamesMap;
	funcParamsMap["wordexp"] = paramSymbolsMap;

	return funcParamsMap;
}

/// Mapping of function names into symbolic names of their parameters.
const FuncParamsMap &FUNC_PARAMS_MAP(initFuncParamsMap());

} // anonymous namespace

/**
* @brief Implements getSymbolicNamesForParam() for GCCGeneralSemantics.
*
* See its description for more details.
*/
Maybe<IntStringMap> getSymbolicNamesForParam(const std::string &funcName,
		unsigned paramPos) {
	return getSymbolicNamesForParamFromMap(funcName, paramPos, FUNC_PARAMS_MAP);
}

} // namespace gcc_general
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
