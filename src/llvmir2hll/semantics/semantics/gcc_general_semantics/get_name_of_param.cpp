/**
* @file src/llvmir2hll/semantics/semantics/gcc_general_semantics/get_name_of_param.cpp
* @brief Implementation of semantics::gcc_general::getNameOfParam() for
*        GCCGeneralSemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/gcc_general_semantics/get_name_of_param.h"
#include "retdec/llvmir2hll/semantics/semantics/impl_support/get_name_of_param.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace gcc_general {

namespace {

/**
* @brief This function is used to initialize FUNC_PARAM_NAMES_MAP later in the
*        file.
*/
const FuncParamNamesMap &initFuncParamNamesMap() {
	static FuncParamNamesMap funcParamNamesMap;

	//
	// The base of the information below has been obtained by using the
	// scripts/backend/semantics/func_var_names/gen_semantics_from_man_pages.py
	// script over the functions in
	// GCCGeneralSemantics/getCHeaderFileForFunc.cpp that are not in
	// LibcSemantics/getCHeaderFileForFunc.cpp. The resulting semantics has
	// been updated manually. Useless mappings have been commented out.
	//

	//
	// aio.h
	//
	ADD_PARAM_NAME("aio_cancel", 1, "fd"); // int
	ADD_PARAM_NAME("aio_cancel", 2, "aiocbp"); // struct aiocb *
	ADD_PARAM_NAME("aio_error", 1, "aiocbp"); // const struct aiocb *
	ADD_PARAM_NAME("aio_fsync", 1, "operation"); // int
	ADD_PARAM_NAME("aio_fsync", 2, "aiocbp"); // struct aiocb *
	ADD_PARAM_NAME("aio_read", 1, "aiocbp"); // struct aiocb *
	ADD_PARAM_NAME("aio_return", 1, "aiocbp"); // struct aiocb *
	ADD_PARAM_NAME("aio_suspend", 1, "aiocb_list"); // const struct aiocb * const []
	ADD_PARAM_NAME("aio_suspend", 2, "nitems"); // int
	ADD_PARAM_NAME("aio_suspend", 3, "timeout"); // const struct timespec *
	ADD_PARAM_NAME("aio_write", 1, "aiocbp"); // struct aiocb *
	ADD_PARAM_NAME("lio_listio", 1, "mode"); // int
	ADD_PARAM_NAME("lio_listio", 2, "aiocb_list"); // struct aiocb * const []
	ADD_PARAM_NAME("lio_listio", 3, "nitems"); // int
	ADD_PARAM_NAME("lio_listio", 4, "sevp"); // struct sigevent *

	//
	// alloca.h
	//
	ADD_PARAM_NAME("alloca", 1, "size"); // size_t

	//
	// arpa/inet.h
	//
	ADD_PARAM_NAME("htonl", 1, "host_long"); // uint32_t
	ADD_PARAM_NAME("htons", 1, "host_short"); // uint16_t
	ADD_PARAM_NAME("inet_net_ntop", 1, "address_family"); // int
	ADD_PARAM_NAME("inet_net_ntop", 2, "netp"); // const void *
	ADD_PARAM_NAME("inet_net_ntop", 3, "bits"); // int
	ADD_PARAM_NAME("inet_net_ntop", 4, "pres"); // char *
	ADD_PARAM_NAME("inet_net_ntop", 5, "psize"); // size_t
	ADD_PARAM_NAME("inet_net_pton", 1, "address_family"); // int
	ADD_PARAM_NAME("inet_net_pton", 2, "pres"); // const char *
	ADD_PARAM_NAME("inet_net_pton", 3, "netp"); // void *
	ADD_PARAM_NAME("inet_net_pton", 4, "nsize"); // size_t
	ADD_PARAM_NAME("inet_neta", 1, "address"); // in_addr_t
	ADD_PARAM_NAME("inet_neta", 2, "address_str"); // char *
	ADD_PARAM_NAME("inet_neta", 3, "size"); // size_t
	ADD_PARAM_NAME("inet_ntop", 1, "address_family"); // int
	ADD_PARAM_NAME("inet_ntop", 2, "address"); // const void *
	ADD_PARAM_NAME("inet_ntop", 3, "address_str"); // char *
	ADD_PARAM_NAME("inet_ntop", 4, "size"); // socklen_t
	ADD_PARAM_NAME("inet_pton", 1, "address_family"); // int
	ADD_PARAM_NAME("inet_pton", 2, "str"); // const char *
	ADD_PARAM_NAME("inet_pton", 3, "address"); // void *
	ADD_PARAM_NAME("ntohl", 1, "net_long"); // uint32_t
	ADD_PARAM_NAME("ntohs", 1, "net_short"); // uint16_t

	//
	// ctype.h
	//
	ADD_PARAM_NAME("_tolower", 1, "c"); // int
	ADD_PARAM_NAME("_toupper", 1, "c"); // int
	ADD_PARAM_NAME("isalnum_l", 1, "c"); // int
	ADD_PARAM_NAME("isalnum_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("isalpha_l", 1, "c"); // int
	ADD_PARAM_NAME("isalpha_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("isascii", 1, "c"); // int
	ADD_PARAM_NAME("isblank_l", 1, "c"); // int
	ADD_PARAM_NAME("isblank_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("iscntrl_l", 1, "c"); // int
	ADD_PARAM_NAME("iscntrl_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("isdigit_l", 1, "c"); // int
	ADD_PARAM_NAME("isdigit_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("isgraph_l", 1, "c"); // int
	ADD_PARAM_NAME("isgraph_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("islower_l", 1, "c"); // int
	ADD_PARAM_NAME("islower_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("isprint_l", 1, "c"); // int
	ADD_PARAM_NAME("isprint_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("ispunct_l", 1, "c"); // int
	ADD_PARAM_NAME("ispunct_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("isspace_l", 1, "c"); // int
	ADD_PARAM_NAME("isspace_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("isupper_l", 1, "c"); // int
	ADD_PARAM_NAME("isupper_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("isxdigit_l", 1, "c"); // int
	ADD_PARAM_NAME("isxdigit_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("toascii", 1, "c"); // int
	ADD_PARAM_NAME("tolower_l", 1, "c"); // int
	ADD_PARAM_NAME("tolower_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("toupper_l", 1, "c"); // int
	ADD_PARAM_NAME("toupper_l", 2, "locale"); // locale_t

	//
	// dirent.h
	//
	ADD_PARAM_NAME("getdirentries", 1, "fd"); // int
	ADD_PARAM_NAME("getdirentries", 2, "buf"); // char *
	ADD_PARAM_NAME("getdirentries", 3, "nbytes"); // size_t
	ADD_PARAM_NAME("getdirentries", 4, "basep"); // off_t *
	ADD_PARAM_NAME("readdir", 1, "dirp"); // DIR *
	ADD_PARAM_NAME("readdir_r", 1, "dirp"); // DIR *
	ADD_PARAM_NAME("readdir_r", 2, "dir"); // struct dirent *
	ADD_PARAM_NAME("readdir_r", 3, "dir"); // struct dirent **
	ADD_PARAM_NAME("seekdir", 1, "dirp"); // DIR *
	ADD_PARAM_NAME("seekdir", 2, "loc"); // long
	ADD_PARAM_NAME("telldir", 1, "dirp"); // DIR *

	//
	// dlfcn.h
	//
	ADD_PARAM_NAME("dlopen", 1, "file_path"); // const char *
	ADD_PARAM_NAME("dlopen", 2, "dlopen_flag"); // int

	//
	// error.h
	//
	ADD_PARAM_NAME("error", 1, "status"); // int
	ADD_PARAM_NAME("error", 2, "err_num"); // int
	ADD_PARAM_NAME("error", 3, "format"); // const char *
	ADD_PARAM_NAME("error_at_line", 1, "status"); // int
	ADD_PARAM_NAME("error_at_line", 2, "err_num"); // int
	ADD_PARAM_NAME("error_at_line", 3, "file_name"); // const char *
	ADD_PARAM_NAME("error_at_line", 4, "line_num"); // unsigned int
	ADD_PARAM_NAME("error_at_line", 5, "format"); // const char *

	//
	// fcntl.h
	//
	ADD_PARAM_NAME("fcntl", 1, "fd"); // int
	ADD_PARAM_NAME("fcntl", 2, "cmd"); // int
	ADD_PARAM_NAME("futimens", 1, "fd"); // int
	ADD_PARAM_NAME("futimens", 2, "times"); // const struct timespec [2]
	ADD_PARAM_NAME("mq_open", 1, "name"); // const char *
	ADD_PARAM_NAME("mq_open", 2, "oflag"); // int
	ADD_PARAM_NAME("openat", 1, "fd"); // int
	ADD_PARAM_NAME("openat", 2, "path"); // const char *
	ADD_PARAM_NAME("openat", 3, "oflag"); // int
	ADD_PARAM_NAME("posix_fadvise", 1, "fd"); // int
	ADD_PARAM_NAME("posix_fadvise", 2, "offset"); // off_t
	ADD_PARAM_NAME("posix_fadvise", 3, "length"); // off_t
	ADD_PARAM_NAME("posix_fadvise", 4, "advice"); // int
	ADD_PARAM_NAME("posix_fallocate", 1, "fd"); // int
	ADD_PARAM_NAME("posix_fallocate", 2, "offset"); // off_t
	ADD_PARAM_NAME("posix_fallocate", 3, "length"); // off_t
	ADD_PARAM_NAME("sem_open", 1, "name"); // const char *
	ADD_PARAM_NAME("sem_open", 2, "oflag"); // int

	//
	// fmtmsg.h
	//
	ADD_PARAM_NAME("addseverity", 1, "severity"); // int
	ADD_PARAM_NAME("addseverity", 2, "str"); // const char *
	ADD_PARAM_NAME("fmtmsg", 1, "classification"); // long
	ADD_PARAM_NAME("fmtmsg", 2, "label"); // const char *
	ADD_PARAM_NAME("fmtmsg", 3, "severity"); // int
	ADD_PARAM_NAME("fmtmsg", 4, "text"); // const char *
	ADD_PARAM_NAME("fmtmsg", 5, "action"); // const char *
	ADD_PARAM_NAME("fmtmsg", 6, "tag"); // const char *

	//
	// fnmatch.h
	//
	ADD_PARAM_NAME("fnmatch", 1, "pattern"); // const char *
	ADD_PARAM_NAME("fnmatch", 2, "str"); // const char *
	ADD_PARAM_NAME("fnmatch", 3, "fnmatch_flags"); // int

	//
	// ftw.h
	//
	ADD_PARAM_NAME("ftw", 1, "dir_path"); // const char*
	ADD_PARAM_NAME("ftw", 2, "ftw_func"); // int (*)(const char *, const struct stat *, int)
	ADD_PARAM_NAME("ftw", 3, "nopenfd"); // int

	//
	// gdbm.h
	//
	// From http://www.gnu.org.ua/software/gdbm/manual/gdbm.html
	ADD_PARAM_NAME("gdbm_open", 1, "name");
	ADD_PARAM_NAME("gdbm_open", 2, "block_size");
	ADD_PARAM_NAME("gdbm_open", 3, "flags");
	ADD_PARAM_NAME("gdbm_open", 4, "mode");
	ADD_PARAM_NAME("gdbm_open", 4, "fatal_func");
	ADD_PARAM_NAME("gdbm_close", 1, "dbf");
	ADD_PARAM_NAME("gdbm_store", 1, "dbf");
	ADD_PARAM_NAME("gdbm_store", 2, "key");
	ADD_PARAM_NAME("gdbm_store", 3, "content");
	ADD_PARAM_NAME("gdbm_store", 4, "flag");
	ADD_PARAM_NAME("gdbm_fetch", 1, "dbf");
	ADD_PARAM_NAME("gdbm_fetch", 2, "key");
	ADD_PARAM_NAME("gdbm_delete", 1, "dbf");
	ADD_PARAM_NAME("gdbm_delete", 2, "key");
	ADD_PARAM_NAME("gdbm_firstkey", 1, "dbf");
	ADD_PARAM_NAME("gdbm_nextkey", 1, "dbf");
	ADD_PARAM_NAME("gdbm_nextkey", 2, "key");
	ADD_PARAM_NAME("gdbm_reorganize", 1, "dbf");
	ADD_PARAM_NAME("gdbm_sync", 1, "dbf");
	ADD_PARAM_NAME("gdbm_exists", 1, "dbf");
	ADD_PARAM_NAME("gdbm_exists", 2, "key");
	ADD_PARAM_NAME("gdbm_strerror", 1, "errno");
	ADD_PARAM_NAME("gdbm_setopt", 1, "dbf");
	ADD_PARAM_NAME("gdbm_setopt", 2, "option");
	ADD_PARAM_NAME("gdbm_setopt", 3, "value");
	ADD_PARAM_NAME("gdbm_setopt", 4, "size");
	ADD_PARAM_NAME("gdbm_fdesc", 1, "dbf");
	ADD_PARAM_NAME("gdbm_export", 1, "dbf"); // GDBM_FILE
	ADD_PARAM_NAME("gdbm_export", 2, "file_path"); // const char *
	ADD_PARAM_NAME("gdbm_export", 3, "flag"); // int
	ADD_PARAM_NAME("gdbm_export", 4, "mode"); // int
	ADD_PARAM_NAME("gdbm_export_to_file", 1, "dbf"); // GDBM_FILE
	ADD_PARAM_NAME("gdbm_export_to_file", 2, "file"); // FILE *
	ADD_PARAM_NAME("gdbm_import", 1, "dbf"); // GDBM_FILE
	ADD_PARAM_NAME("gdbm_import", 2, "file_path"); // const char *
	ADD_PARAM_NAME("gdbm_import", 3, "flag"); // int
	ADD_PARAM_NAME("gdbm_import_from_file", 1, "dbf"); // GDBM_FILE
	ADD_PARAM_NAME("gdbm_import_from_file", 2, "file"); // FILE *
	ADD_PARAM_NAME("gdbm_import_from_file", 3, "flag"); // int
	ADD_PARAM_NAME("gdbm_count", 1, "dbf"); // GDBM_FILE
	ADD_PARAM_NAME("gdbm_count", 2, "pcount"); // gdbm_count_t *
	ADD_PARAM_NAME("gdbm_version_cmp", 1, "version"); // int const []
	ADD_PARAM_NAME("gdbm_version_cmp", 2, "version"); // int const []

	//
	// glob.h
	//
	ADD_PARAM_NAME("globfree", 1, "pglob"); // glob_t *

	//
	// grp.h
	//
	ADD_PARAM_NAME("fgetgrent_r", 1, "file"); // FILE *
	ADD_PARAM_NAME("fgetgrent_r", 2, "gbuf"); // struct group *
	ADD_PARAM_NAME("fgetgrent_r", 3, "buf"); // char *
	ADD_PARAM_NAME("fgetgrent_r", 4, "buf_len"); // size_t
	ADD_PARAM_NAME("fgetgrent_r", 5, "gbufp"); // struct group **
	ADD_PARAM_NAME("getgrouplist", 1, "user"); // const char *
	ADD_PARAM_NAME("getgrouplist", 2, "group"); // gid_t
	ADD_PARAM_NAME("getgrouplist", 3, "groups"); // gid_t *
	ADD_PARAM_NAME("getgrouplist", 4, "ngroups"); // int *

	//
	// iconv.h
	//
	ADD_PARAM_NAME("iconv", 1, "cd"); // iconv_t
	ADD_PARAM_NAME("iconv", 2, "inbuf"); // char **
	ADD_PARAM_NAME("iconv", 3, "inbytesleft"); // size_t *
	ADD_PARAM_NAME("iconv", 4, "outbuf"); // char **
	ADD_PARAM_NAME("iconv", 5, "outbytesleft"); // size_t *
	ADD_PARAM_NAME("iconv_close", 1, "cd"); // iconv_t
	ADD_PARAM_NAME("iconv_open", 1, "tocode"); // const char *
	ADD_PARAM_NAME("iconv_open", 2, "fromcode"); // const char *

	//
	// inttypes.h
	//
	ADD_PARAM_NAME("strtoimax", 1, "str"); // const char *
	ADD_PARAM_NAME("strtoimax", 2, "endptr"); // char **
	ADD_PARAM_NAME("strtoimax", 3, "base"); // int
	ADD_PARAM_NAME("strtoumax", 1, "str"); // const char *
	ADD_PARAM_NAME("strtoumax", 2, "endptr"); // char **
	ADD_PARAM_NAME("strtoumax", 3, "base"); // int

	//
	// langinfo.h
	//
	ADD_PARAM_NAME("nl_langinfo", 1, "item"); // nl_item
	ADD_PARAM_NAME("nl_langinfo_l", 1, "item"); // nl_item
	ADD_PARAM_NAME("nl_langinfo_l", 2, "locale"); // locale_t

	//
	// libgen.h
	//
	ADD_PARAM_NAME("dirname", 1, "path"); // char *

	//
	// limits.h
	//
	ADD_PARAM_NAME("realpath", 1, "path"); // const char *
	ADD_PARAM_NAME("realpath", 2, "resolved_path"); // char *

	//
	// locale.h
	//
	ADD_PARAM_NAME("duplocale", 1, "locobj"); // locale_t
	ADD_PARAM_NAME("freelocale", 1, "locobj"); // locale_t
	ADD_PARAM_NAME("newlocale", 1, "locale_category"); // int
	ADD_PARAM_NAME("newlocale", 2, "locale"); // const char *
	ADD_PARAM_NAME("newlocale", 3, "base"); // locale_t
	ADD_PARAM_NAME("uselocale", 1, "locale"); // locale_t

	//
	// math.h
	//
	// ADD_PARAM_NAME("acosf", 1, "x"); // float
	// ADD_PARAM_NAME("acoshf", 1, "x"); // float
	// ADD_PARAM_NAME("acoshl", 1, "x"); // long double
	// ADD_PARAM_NAME("acosl", 1, "x"); // long double
	// ADD_PARAM_NAME("asinf", 1, "x"); // float
	// ADD_PARAM_NAME("asinhf", 1, "x"); // float
	// ADD_PARAM_NAME("asinhl", 1, "x"); // long double
	// ADD_PARAM_NAME("asinl", 1, "x"); // long double
	// ADD_PARAM_NAME("atan2f", 1, "y"); // float
	// ADD_PARAM_NAME("atan2f", 2, "x"); // float
	// ADD_PARAM_NAME("atan2l", 1, "y"); // long double
	// ADD_PARAM_NAME("atan2l", 2, "x"); // long double
	// ADD_PARAM_NAME("atanf", 1, "x"); // float
	// ADD_PARAM_NAME("atanhf", 1, "x"); // float
	// ADD_PARAM_NAME("atanhl", 1, "x"); // long double
	// ADD_PARAM_NAME("atanl", 1, "x"); // long double
	// ADD_PARAM_NAME("cbrtf", 1, "x"); // float
	// ADD_PARAM_NAME("cbrtl", 1, "x"); // long double
	// ADD_PARAM_NAME("ceilf", 1, "x"); // float
	// ADD_PARAM_NAME("ceill", 1, "x"); // long double
	// ADD_PARAM_NAME("copysignf", 1, "x"); // float
	// ADD_PARAM_NAME("copysignf", 2, "y"); // float
	// ADD_PARAM_NAME("copysignl", 1, "x"); // long double
	// ADD_PARAM_NAME("copysignl", 2, "y"); // long double
	// ADD_PARAM_NAME("cosf", 1, "x"); // float
	// ADD_PARAM_NAME("coshf", 1, "x"); // float
	// ADD_PARAM_NAME("coshl", 1, "x"); // long double
	// ADD_PARAM_NAME("cosl", 1, "x"); // long double
	// ADD_PARAM_NAME("drem", 1, "x"); // double
	// ADD_PARAM_NAME("drem", 2, "y"); // double
	// ADD_PARAM_NAME("dremf", 1, "x"); // float
	// ADD_PARAM_NAME("dremf", 2, "y"); // float
	// ADD_PARAM_NAME("dreml", 1, "x"); // long double
	// ADD_PARAM_NAME("dreml", 2, "y"); // long double
	// ADD_PARAM_NAME("erfcf", 1, "x"); // float
	// ADD_PARAM_NAME("erfcl", 1, "x"); // long double
	// ADD_PARAM_NAME("erff", 1, "x"); // float
	// ADD_PARAM_NAME("erfl", 1, "x"); // long double
	// ADD_PARAM_NAME("exp2f", 1, "x"); // float
	// ADD_PARAM_NAME("exp2l", 1, "x"); // long double
	// ADD_PARAM_NAME("expf", 1, "x"); // float
	// ADD_PARAM_NAME("expl", 1, "x"); // long double
	// ADD_PARAM_NAME("expm1f", 1, "x"); // float
	// ADD_PARAM_NAME("expm1l", 1, "x"); // long double
	// ADD_PARAM_NAME("fabsf", 1, "x"); // float
	// ADD_PARAM_NAME("fabsl", 1, "x"); // long double
	// ADD_PARAM_NAME("fdimf", 1, "x"); // float
	// ADD_PARAM_NAME("fdimf", 2, "y"); // float
	// ADD_PARAM_NAME("fdiml", 1, "x"); // long double
	// ADD_PARAM_NAME("fdiml", 2, "y"); // long double
	// ADD_PARAM_NAME("finite", 1, "x"); // double
	// ADD_PARAM_NAME("finitef", 1, "x"); // float
	// ADD_PARAM_NAME("finitel", 1, "x"); // long double
	// ADD_PARAM_NAME("floorf", 1, "x"); // float
	// ADD_PARAM_NAME("floorl", 1, "x"); // long double
	// ADD_PARAM_NAME("fmaf", 1, "x"); // float
	// ADD_PARAM_NAME("fmaf", 2, "y"); // float
	// ADD_PARAM_NAME("fmaf", 3, "z"); // float
	// ADD_PARAM_NAME("fmal", 1, "x"); // long double
	// ADD_PARAM_NAME("fmal", 2, "y"); // long double
	// ADD_PARAM_NAME("fmal", 3, "z"); // long double
	// ADD_PARAM_NAME("fmaxf", 1, "x"); // float
	// ADD_PARAM_NAME("fmaxf", 2, "y"); // float
	// ADD_PARAM_NAME("fmaxl", 1, "x"); // long double
	// ADD_PARAM_NAME("fmaxl", 2, "y"); // long double
	// ADD_PARAM_NAME("fminf", 1, "x"); // float
	// ADD_PARAM_NAME("fminf", 2, "y"); // float
	// ADD_PARAM_NAME("fminl", 1, "x"); // long double
	// ADD_PARAM_NAME("fminl", 2, "y"); // long double
	// ADD_PARAM_NAME("fmodf", 1, "x"); // float
	// ADD_PARAM_NAME("fmodf", 2, "y"); // float
	// ADD_PARAM_NAME("fmodl", 1, "x"); // long double
	// ADD_PARAM_NAME("fmodl", 2, "y"); // long double
	// ADD_PARAM_NAME("frexpf", 1, "x"); // float
	// ADD_PARAM_NAME("frexpf", 2, "exp"); // int *
	// ADD_PARAM_NAME("frexpl", 1, "x"); // long double
	// ADD_PARAM_NAME("frexpl", 2, "exp"); // int *
	// ADD_PARAM_NAME("gamma", 1, "x"); // double
	// ADD_PARAM_NAME("gammaf", 1, "x"); // float
	// ADD_PARAM_NAME("gammal", 1, "x"); // long double
	// ADD_PARAM_NAME("hypotf", 1, "x"); // float
	// ADD_PARAM_NAME("hypotf", 2, "y"); // float
	// ADD_PARAM_NAME("hypotl", 1, "x"); // long double
	// ADD_PARAM_NAME("hypotl", 2, "y"); // long double
	// ADD_PARAM_NAME("ilogbf", 1, "x"); // float
	// ADD_PARAM_NAME("ilogbl", 1, "x"); // long double
	// ADD_PARAM_NAME("isinff", 1, "x"); // float
	// ADD_PARAM_NAME("isinfl", 1, "x"); // long double
	// ADD_PARAM_NAME("isnanf", 1, "x"); // float
	// ADD_PARAM_NAME("isnanl", 1, "x"); // long double
	// ADD_PARAM_NAME("j0", 1, "x"); // double
	// ADD_PARAM_NAME("j0f", 1, "x"); // float
	// ADD_PARAM_NAME("j0l", 1, "x"); // long double
	// ADD_PARAM_NAME("j1", 1, "x"); // double
	// ADD_PARAM_NAME("j1f", 1, "x"); // float
	// ADD_PARAM_NAME("j1l", 1, "x"); // long double
	// ADD_PARAM_NAME("jn", 1, "n"); // int
	// ADD_PARAM_NAME("jn", 2, "x"); // double
	// ADD_PARAM_NAME("jnf", 1, "n"); // int
	// ADD_PARAM_NAME("jnf", 2, "x"); // float
	// ADD_PARAM_NAME("jnl", 1, "n"); // int
	// ADD_PARAM_NAME("jnl", 2, "x"); // long double
	// ADD_PARAM_NAME("ldexpf", 1, "x"); // float
	// ADD_PARAM_NAME("ldexpf", 2, "exp"); // int
	// ADD_PARAM_NAME("ldexpl", 1, "x"); // long double
	// ADD_PARAM_NAME("ldexpl", 2, "exp"); // int
	// ADD_PARAM_NAME("lgamma_r", 1, "x"); // double
	// ADD_PARAM_NAME("lgamma_r", 2, "signp"); // int *
	// ADD_PARAM_NAME("lgammaf", 1, "x"); // float
	// ADD_PARAM_NAME("lgammaf_r", 1, "x"); // float
	// ADD_PARAM_NAME("lgammaf_r", 2, "signp"); // int *
	// ADD_PARAM_NAME("lgammal", 1, "x"); // long double
	// ADD_PARAM_NAME("lgammal_r", 1, "x"); // long double
	// ADD_PARAM_NAME("lgammal_r", 2, "signp"); // int *
	// ADD_PARAM_NAME("llrintf", 1, "x"); // float
	// ADD_PARAM_NAME("llrintl", 1, "x"); // long double
	// ADD_PARAM_NAME("llroundf", 1, "x"); // float
	// ADD_PARAM_NAME("llroundl", 1, "x"); // long double
	// ADD_PARAM_NAME("log10f", 1, "x"); // float
	// ADD_PARAM_NAME("log10l", 1, "x"); // long double
	// ADD_PARAM_NAME("log1pf", 1, "x"); // float
	// ADD_PARAM_NAME("log1pl", 1, "x"); // long double
	// ADD_PARAM_NAME("log2f", 1, "x"); // float
	// ADD_PARAM_NAME("log2l", 1, "x"); // long double
	// ADD_PARAM_NAME("logbf", 1, "x"); // float
	// ADD_PARAM_NAME("logbl", 1, "x"); // long double
	// ADD_PARAM_NAME("logf", 1, "x"); // float
	// ADD_PARAM_NAME("logl", 1, "x"); // long double
	// ADD_PARAM_NAME("lrintf", 1, "x"); // float
	// ADD_PARAM_NAME("lrintl", 1, "x"); // long double
	// ADD_PARAM_NAME("lroundf", 1, "x"); // float
	// ADD_PARAM_NAME("lroundl", 1, "x"); // long double
	// ADD_PARAM_NAME("matherr", 1, "exc"); // struct exception *
	// ADD_PARAM_NAME("modff", 1, "x"); // float
	// ADD_PARAM_NAME("modff", 2, "iptr"); // float *
	// ADD_PARAM_NAME("modfl", 1, "x"); // long double
	// ADD_PARAM_NAME("modfl", 2, "iptr"); // long double *
	// ADD_PARAM_NAME("nearbyintf", 1, "x"); // float
	// ADD_PARAM_NAME("nearbyintl", 1, "x"); // long double
	// ADD_PARAM_NAME("nextafterf", 1, "x"); // float
	// ADD_PARAM_NAME("nextafterf", 2, "y"); // float
	// ADD_PARAM_NAME("nextafterl", 1, "x"); // long double
	// ADD_PARAM_NAME("nextafterl", 2, "y"); // long double
	// ADD_PARAM_NAME("nexttowardf", 1, "x"); // float
	// ADD_PARAM_NAME("nexttowardf", 2, "y"); // long double
	// ADD_PARAM_NAME("nexttowardl", 1, "x"); // long double
	// ADD_PARAM_NAME("nexttowardl", 2, "y"); // long double
	// ADD_PARAM_NAME("powf", 1, "x"); // float
	// ADD_PARAM_NAME("powf", 2, "y"); // float
	// ADD_PARAM_NAME("powl", 1, "x"); // long double
	// ADD_PARAM_NAME("powl", 2, "y"); // long double
	// ADD_PARAM_NAME("remainderf", 1, "x"); // float
	// ADD_PARAM_NAME("remainderf", 2, "y"); // float
	// ADD_PARAM_NAME("remainderl", 1, "x"); // long double
	// ADD_PARAM_NAME("remainderl", 2, "y"); // long double
	// ADD_PARAM_NAME("remquof", 1, "x"); // float
	// ADD_PARAM_NAME("remquof", 2, "y"); // float
	// ADD_PARAM_NAME("remquof", 3, "quo"); // int *
	// ADD_PARAM_NAME("remquol", 1, "x"); // long double
	// ADD_PARAM_NAME("remquol", 2, "y"); // long double
	// ADD_PARAM_NAME("remquol", 3, "quo"); // int *
	// ADD_PARAM_NAME("rintf", 1, "x"); // float
	// ADD_PARAM_NAME("rintl", 1, "x"); // long double
	// ADD_PARAM_NAME("roundf", 1, "x"); // float
	// ADD_PARAM_NAME("roundl", 1, "x"); // long double
	// ADD_PARAM_NAME("scalb", 1, "x"); // double
	// ADD_PARAM_NAME("scalb", 2, "exp"); // double
	// ADD_PARAM_NAME("scalbf", 1, "x"); // float
	// ADD_PARAM_NAME("scalbf", 2, "exp"); // float
	// ADD_PARAM_NAME("scalbl", 1, "x"); // long double
	// ADD_PARAM_NAME("scalbl", 2, "exp"); // long double
	// ADD_PARAM_NAME("scalblnf", 1, "x"); // float
	// ADD_PARAM_NAME("scalblnf", 2, "exp"); // long int
	// ADD_PARAM_NAME("scalblnl", 1, "x"); // long double
	// ADD_PARAM_NAME("scalblnl", 2, "exp"); // long int
	// ADD_PARAM_NAME("scalbnf", 1, "x"); // float
	// ADD_PARAM_NAME("scalbnf", 2, "exp"); // int
	// ADD_PARAM_NAME("scalbnl", 1, "x"); // long double
	// ADD_PARAM_NAME("scalbnl", 2, "exp"); // int
	// ADD_PARAM_NAME("significand", 1, "x"); // double
	// ADD_PARAM_NAME("significandf", 1, "x"); // float
	// ADD_PARAM_NAME("significandl", 1, "x"); // long double
	// ADD_PARAM_NAME("sinf", 1, "x"); // float
	// ADD_PARAM_NAME("sinhf", 1, "x"); // float
	// ADD_PARAM_NAME("sinhl", 1, "x"); // long double
	// ADD_PARAM_NAME("sinl", 1, "x"); // long double
	// ADD_PARAM_NAME("sqrtf", 1, "x"); // float
	// ADD_PARAM_NAME("sqrtl", 1, "x"); // long double
	// ADD_PARAM_NAME("tanf", 1, "x"); // float
	// ADD_PARAM_NAME("tanhf", 1, "x"); // float
	// ADD_PARAM_NAME("tanhl", 1, "x"); // long double
	// ADD_PARAM_NAME("tanl", 1, "x"); // long double
	// ADD_PARAM_NAME("tgammaf", 1, "x"); // float
	// ADD_PARAM_NAME("tgammal", 1, "x"); // long double
	// ADD_PARAM_NAME("truncf", 1, "x"); // float
	// ADD_PARAM_NAME("truncl", 1, "x"); // long double
	// ADD_PARAM_NAME("y0", 1, "x"); // double
	// ADD_PARAM_NAME("y0f", 1, "x"); // float
	// ADD_PARAM_NAME("y0l", 1, "x"); // long double
	// ADD_PARAM_NAME("y1", 1, "x"); // double
	// ADD_PARAM_NAME("y1f", 1, "x"); // float
	// ADD_PARAM_NAME("y1l", 1, "x"); // long double
	// ADD_PARAM_NAME("yn", 1, "n"); // int
	// ADD_PARAM_NAME("yn", 2, "x"); // double
	// ADD_PARAM_NAME("ynf", 1, "n"); // int
	// ADD_PARAM_NAME("ynf", 2, "x"); // float
	// ADD_PARAM_NAME("ynl", 1, "n"); // int
	// ADD_PARAM_NAME("ynl", 2, "x"); // long double

	//
	// monetary.h
	//
	ADD_PARAM_NAME("strfmon", 1, "str"); // char *
	ADD_PARAM_NAME("strfmon", 2, "max_size"); // size_t
	ADD_PARAM_NAME("strfmon", 3, "format"); // const char *
	ADD_PARAM_NAME("strfmon_l", 1, "str"); // char * restrict
	ADD_PARAM_NAME("strfmon_l", 2, "max_size"); // size_t
	ADD_PARAM_NAME("strfmon_l", 3, "locale"); // locale_t
	ADD_PARAM_NAME("strfmon_l", 4, "format"); // const char * restrict

	//
	// mqueue.h
	//
	ADD_PARAM_NAME("mq_close", 1, "mqdes"); // mqd_t
	ADD_PARAM_NAME("mq_getattr", 1, "mqdes"); // mqd_t
	ADD_PARAM_NAME("mq_getattr", 2, "attr"); // struct mq_attr *
	ADD_PARAM_NAME("mq_notify", 1, "mqdes"); // mqd_t
	ADD_PARAM_NAME("mq_notify", 2, "sevp"); // const struct sigevent *
	ADD_PARAM_NAME("mq_receive", 1, "mqdes"); // mqd_t
	ADD_PARAM_NAME("mq_receive", 2, "msg_ptr"); // char *
	ADD_PARAM_NAME("mq_receive", 3, "msg_len"); // size_t
	ADD_PARAM_NAME("mq_receive", 4, "msg_prio"); // unsigned int *
	ADD_PARAM_NAME("mq_send", 1, "mqdes"); // mqd_t
	ADD_PARAM_NAME("mq_send", 2, "msg_ptr"); // const char *
	ADD_PARAM_NAME("mq_send", 3, "msg_len"); // size_t
	ADD_PARAM_NAME("mq_send", 4, "msg_prio"); // unsigned int
	ADD_PARAM_NAME("mq_setattr", 1, "mqdes"); // mqd_t
	ADD_PARAM_NAME("mq_setattr", 2, "attr"); // struct mq_attr *
	ADD_PARAM_NAME("mq_setattr", 3, "attr"); // struct mq_attr *
	ADD_PARAM_NAME("mq_timedreceive", 1, "mqdes"); // mqd_t
	ADD_PARAM_NAME("mq_timedreceive", 2, "msg_ptr"); // char *
	ADD_PARAM_NAME("mq_timedreceive", 3, "msg_len"); // size_t
	ADD_PARAM_NAME("mq_timedreceive", 4, "msg_prio"); // unsigned int *
	ADD_PARAM_NAME("mq_timedreceive", 5, "abs_timeout"); // const struct timespec *
	ADD_PARAM_NAME("mq_timedsend", 1, "mqdes"); // mqd_t
	ADD_PARAM_NAME("mq_timedsend", 2, "msg_ptr"); // const char *
	ADD_PARAM_NAME("mq_timedsend", 3, "msg_len"); // size_t
	ADD_PARAM_NAME("mq_timedsend", 4, "msg_prio"); // unsigned int
	ADD_PARAM_NAME("mq_timedsend", 5, "abs_timeout"); // const struct timespec *
	ADD_PARAM_NAME("mq_unlink", 1, "name"); // const char *

	//
	// ndbm.h
	//
	ADD_PARAM_NAME("dbm_clearerr", 1, "db"); // DBM *
	ADD_PARAM_NAME("dbm_close", 1, "db"); // DBM *
	ADD_PARAM_NAME("dbm_delete", 1, "db"); // DBM *
	ADD_PARAM_NAME("dbm_delete", 2, "key"); // datum
	ADD_PARAM_NAME("dbm_dirfno", 1, "db"); // DBM *
	ADD_PARAM_NAME("dbm_error", 1, "db"); // DBM *
	ADD_PARAM_NAME("dbm_fetch", 1, "db"); // DBM *
	ADD_PARAM_NAME("dbm_fetch", 2, "key"); // datum
	ADD_PARAM_NAME("dbm_firstkey", 1, "db"); // DBM *
	ADD_PARAM_NAME("dbm_nextkey", 1, "db"); // DBM *
	ADD_PARAM_NAME("dbm_open", 1, "file"); // const char *
	ADD_PARAM_NAME("dbm_open", 2, "open_flags"); // int
	ADD_PARAM_NAME("dbm_open", 3, "file_mode"); // mode_t
	ADD_PARAM_NAME("dbm_pagfno", 1, "db"); // DBM *
	ADD_PARAM_NAME("dbm_rdonly", 1, "db"); // DBM *
	ADD_PARAM_NAME("dbm_store", 1, "db"); // DBM *
	ADD_PARAM_NAME("dbm_store", 2, "key"); // datum
	ADD_PARAM_NAME("dbm_store", 3, "content"); // datum
	ADD_PARAM_NAME("dbm_store", 4, "store_mode"); // int

	//
	// net/if.h
	//
	ADD_PARAM_NAME("if_freenameindex", 1, "if_indexes"); // struct if_nameindex *
	ADD_PARAM_NAME("if_indextoname", 1, "if_index"); // unsigned int
	ADD_PARAM_NAME("if_indextoname", 2, "if_name"); // char *
	ADD_PARAM_NAME("if_nametoindex", 1, "if_name"); // const char *

	//
	// netdb.h
	//
	ADD_PARAM_NAME("gethostbyaddr", 1, "addr"); // const void *
	ADD_PARAM_NAME("gethostbyaddr", 2, "length"); // socklen_t
	ADD_PARAM_NAME("gethostbyaddr", 3, "type"); // int
	ADD_PARAM_NAME("gethostbyaddr_r", 1, "addr"); // const void *
	ADD_PARAM_NAME("gethostbyaddr_r", 2, "length"); // socklen_t
	ADD_PARAM_NAME("gethostbyaddr_r", 3, "type"); // int
	ADD_PARAM_NAME("gethostbyaddr_r", 4, "ret"); // struct hostent *
	ADD_PARAM_NAME("gethostbyaddr_r", 5, "buf"); // char *
	ADD_PARAM_NAME("gethostbyaddr_r", 6, "buf_len"); // size_t
	ADD_PARAM_NAME("gethostbyaddr_r", 7, "host"); // struct hostent **
	ADD_PARAM_NAME("gethostbyaddr_r", 8, "h_errnop"); // int *
	ADD_PARAM_NAME("gethostbyname", 1, "name"); // const char *
	ADD_PARAM_NAME("gethostbyname2", 1, "name"); // const char *
	ADD_PARAM_NAME("gethostbyname2", 2, "address_family"); // int
	ADD_PARAM_NAME("gethostbyname2_r", 1, "name"); // const char *
	ADD_PARAM_NAME("gethostbyname2_r", 2, "address_family"); // int
	ADD_PARAM_NAME("gethostbyname2_r", 3, "ret"); // struct hostent *
	ADD_PARAM_NAME("gethostbyname2_r", 4, "buf"); // char *
	ADD_PARAM_NAME("gethostbyname2_r", 5, "buf_len"); // size_t
	ADD_PARAM_NAME("gethostbyname2_r", 6, "host"); // struct hostent **
	ADD_PARAM_NAME("gethostbyname2_r", 7, "h_errnop"); // int *
	ADD_PARAM_NAME("gethostbyname_r", 1, "name"); // const char *
	ADD_PARAM_NAME("gethostbyname_r", 2, "ret"); // struct hostent *
	ADD_PARAM_NAME("gethostbyname_r", 3, "buf"); // char *
	ADD_PARAM_NAME("gethostbyname_r", 4, "buf_len"); // size_t
	ADD_PARAM_NAME("gethostbyname_r", 5, "host"); // struct hostent **
	ADD_PARAM_NAME("gethostbyname_r", 6, "h_errnop"); // int *
	ADD_PARAM_NAME("gethostent_r", 1, "ret"); // struct hostent *
	ADD_PARAM_NAME("gethostent_r", 1, "buf"); // char *
	ADD_PARAM_NAME("gethostent_r", 1, "buf_len"); // size_t
	ADD_PARAM_NAME("gethostent_r", 1, "host"); // struct hostent **
	ADD_PARAM_NAME("gethostent_r", 1, "h_errnop"); // int *
	ADD_PARAM_NAME("getnetbyaddr", 1, "net"); // uint32_t
	ADD_PARAM_NAME("getnetbyaddr", 2, "type"); // int
	ADD_PARAM_NAME("getnetbyaddr_r", 1, "net"); // uint32_t
	ADD_PARAM_NAME("getnetbyaddr_r", 2, "type"); // int
	ADD_PARAM_NAME("getnetbyaddr_r", 3, "network_buf"); // struct netent *
	ADD_PARAM_NAME("getnetbyaddr_r", 4, "buf"); // char *
	ADD_PARAM_NAME("getnetbyaddr_r", 5, "buf_len"); // size_t
	ADD_PARAM_NAME("getnetbyaddr_r", 6, "network"); // struct netent **
	ADD_PARAM_NAME("getnetbyaddr_r", 7, "h_errnop"); // int *
	ADD_PARAM_NAME("getnetbyname", 1, "name"); // const char *
	ADD_PARAM_NAME("getnetbyname_r", 1, "name"); // const char *
	ADD_PARAM_NAME("getnetbyname_r", 2, "network_buf"); // struct netent *
	ADD_PARAM_NAME("getnetbyname_r", 3, "buf"); // char *
	ADD_PARAM_NAME("getnetbyname_r", 4, "buf_len"); // size_t
	ADD_PARAM_NAME("getnetbyname_r", 5, "network"); // struct netent **
	ADD_PARAM_NAME("getnetbyname_r", 6, "h_errnop"); // int *
	ADD_PARAM_NAME("getnetent_r", 1, "network_buf"); // struct netent *
	ADD_PARAM_NAME("getnetent_r", 2, "buf"); // char *
	ADD_PARAM_NAME("getnetent_r", 3, "buf_len"); // size_t
	ADD_PARAM_NAME("getnetent_r", 4, "network"); // struct netent **
	ADD_PARAM_NAME("getnetent_r", 5, "h_errnop"); // int *
	ADD_PARAM_NAME("getnetgrent", 1, "host"); // char **
	ADD_PARAM_NAME("getnetgrent", 2, "user"); // char **
	ADD_PARAM_NAME("getnetgrent", 3, "domain"); // char **
	ADD_PARAM_NAME("getnetgrent_r", 1, "host"); // char **
	ADD_PARAM_NAME("getnetgrent_r", 2, "user"); // char **
	ADD_PARAM_NAME("getnetgrent_r", 3, "domain"); // char **
	ADD_PARAM_NAME("getnetgrent_r", 4, "buf"); // char *
	ADD_PARAM_NAME("getnetgrent_r", 5, "buf_len"); // int
	ADD_PARAM_NAME("getprotobyname", 1, "name"); // const char *
	ADD_PARAM_NAME("getprotobyname_r", 1, "name"); // const char *
	ADD_PARAM_NAME("getprotobyname_r", 2, "protocol_buf"); // struct protoent *
	ADD_PARAM_NAME("getprotobyname_r", 3, "buf"); // char *
	ADD_PARAM_NAME("getprotobyname_r", 4, "buf_len"); // size_t
	ADD_PARAM_NAME("getprotobyname_r", 5, "protocol"); // struct protoent **
	ADD_PARAM_NAME("getprotobynumber", 1, "protocol"); // int
	ADD_PARAM_NAME("getprotobynumber_r", 1, "protocol"); // int
	ADD_PARAM_NAME("getprotobynumber_r", 2, "protocol_buf"); // struct protoent *
	ADD_PARAM_NAME("getprotobynumber_r", 3, "buf"); // char *
	ADD_PARAM_NAME("getprotobynumber_r", 4, "buf_len"); // size_t
	ADD_PARAM_NAME("getprotobynumber_r", 5, "protocol"); // struct protoent **
	ADD_PARAM_NAME("getprotoent_r", 1, "protocol_buf"); // struct protoent *
	ADD_PARAM_NAME("getprotoent_r", 2, "buf"); // char *
	ADD_PARAM_NAME("getprotoent_r", 3, "buf_len"); // size_t
	ADD_PARAM_NAME("getprotoent_r", 4, "protocol"); // struct protoent **
	ADD_PARAM_NAME("getrpcbyname", 1, "name"); // char *
	ADD_PARAM_NAME("getrpcbyname_r", 1, "name"); // const char *
	ADD_PARAM_NAME("getrpcbyname_r", 2, "rpc_buf"); // struct rpcent *
	ADD_PARAM_NAME("getrpcbyname_r", 3, "buf"); // char *
	ADD_PARAM_NAME("getrpcbyname_r", 4, "buf_len"); // size_t
	ADD_PARAM_NAME("getrpcbyname_r", 5, "rpc"); // struct rpcent **
	ADD_PARAM_NAME("getrpcbynumber", 1, "number"); // int
	ADD_PARAM_NAME("getrpcbynumber_r", 1, "number"); // int
	ADD_PARAM_NAME("getrpcbynumber_r", 2, "rpc_buf"); // struct rpcent *
	ADD_PARAM_NAME("getrpcbynumber_r", 3, "buf"); // char *
	ADD_PARAM_NAME("getrpcbynumber_r", 4, "buf_len"); // size_t
	ADD_PARAM_NAME("getrpcbynumber_r", 5, "rpc"); // struct rpcent **
	ADD_PARAM_NAME("getrpcent_r", 1, "rpc_buf"); // struct rpcent *
	ADD_PARAM_NAME("getrpcent_r", 2, "buf"); // char *
	ADD_PARAM_NAME("getrpcent_r", 3, "buf_len"); // size_t
	ADD_PARAM_NAME("getrpcent_r", 4, "rpc"); // struct rpcent **
	ADD_PARAM_NAME("getservbyname", 1, "name"); // const char *
	ADD_PARAM_NAME("getservbyname", 2, "protocol"); // const char *
	ADD_PARAM_NAME("getservbyname_r", 1, "name"); // const char *
	ADD_PARAM_NAME("getservbyname_r", 2, "protocol"); // const char *
	ADD_PARAM_NAME("getservbyname_r", 3, "serv_buf"); // struct servent *
	ADD_PARAM_NAME("getservbyname_r", 4, "buf"); // char *
	ADD_PARAM_NAME("getservbyname_r", 5, "buf_len"); // size_t
	ADD_PARAM_NAME("getservbyname_r", 6, "serv"); // struct servent **
	ADD_PARAM_NAME("getservbyport", 1, "port"); // int
	ADD_PARAM_NAME("getservbyport", 2, "protocol"); // const char *
	ADD_PARAM_NAME("getservbyport_r", 1, "port"); // int
	ADD_PARAM_NAME("getservbyport_r", 2, "protocol"); // const char *
	ADD_PARAM_NAME("getservbyport_r", 3, "serv_buf"); // struct servent *
	ADD_PARAM_NAME("getservbyport_r", 4, "buf"); // char *
	ADD_PARAM_NAME("getservbyport_r", 5, "buf_len"); // size_t
	ADD_PARAM_NAME("getservbyport_r", 6, "serv"); // struct servent **
	ADD_PARAM_NAME("getservent_r", 1, "serv_buf"); // struct servent *
	ADD_PARAM_NAME("getservent_r", 2, "buf"); // char *
	ADD_PARAM_NAME("getservent_r", 3, "buf_len"); // size_t
	ADD_PARAM_NAME("getservent_r", 4, "serv"); // struct servent **
	ADD_PARAM_NAME("herror", 1, "str"); // const char *
	ADD_PARAM_NAME("hstrerror", 1, "err_num"); // int
	ADD_PARAM_NAME("innetgr", 1, "netgroup"); // const char *
	ADD_PARAM_NAME("innetgr", 2, "host"); // const char *
	ADD_PARAM_NAME("innetgr", 3, "user"); // const char *
	ADD_PARAM_NAME("innetgr", 4, "domain"); // const char *
	ADD_PARAM_NAME("iruserok", 1, "raddr"); // uint32_t
	ADD_PARAM_NAME("iruserok", 2, "superuser"); // int
	ADD_PARAM_NAME("iruserok", 3, "ruser"); // const char *
	ADD_PARAM_NAME("iruserok", 4, "luser"); // const char *
	ADD_PARAM_NAME("iruserok_af", 1, "raddr"); // uint32_t
	ADD_PARAM_NAME("iruserok_af", 2, "superuser"); // int
	ADD_PARAM_NAME("iruserok_af", 3, "ruser"); // const char *
	ADD_PARAM_NAME("iruserok_af", 4, "luser"); // const char *
	ADD_PARAM_NAME("iruserok_af", 5, "address_family"); // sa_family_t
	ADD_PARAM_NAME("rcmd", 1, "ahost"); // char **
	ADD_PARAM_NAME("rcmd", 2, "inport"); // int
	ADD_PARAM_NAME("rcmd", 3, "locuser"); // const char *
	ADD_PARAM_NAME("rcmd", 4, "remuser"); // const char *
	ADD_PARAM_NAME("rcmd", 5, "cmd"); // const char *
	ADD_PARAM_NAME("rcmd", 6, "fd2p"); // int *
	ADD_PARAM_NAME("rcmd_af", 1, "ahost"); // char **
	ADD_PARAM_NAME("rcmd_af", 2, "inport"); // int
	ADD_PARAM_NAME("rcmd_af", 3, "locuser"); // const char *
	ADD_PARAM_NAME("rcmd_af", 4, "remuser"); // const char *
	ADD_PARAM_NAME("rcmd_af", 5, "cmd"); // const char *
	ADD_PARAM_NAME("rcmd_af", 6, "fd2p"); // int *
	ADD_PARAM_NAME("rcmd_af", 7, "address_family"); // sa_family_t
	ADD_PARAM_NAME("rexec", 1, "ahost"); // char **
	ADD_PARAM_NAME("rexec", 2, "inport"); // int
	ADD_PARAM_NAME("rexec", 3, "user"); // char *
	ADD_PARAM_NAME("rexec", 4, "passwd"); // char *
	ADD_PARAM_NAME("rexec", 5, "cmd"); // char *
	ADD_PARAM_NAME("rexec", 6, "fd2p"); // int *
	ADD_PARAM_NAME("rexec_af", 1, "ahost"); // char **
	ADD_PARAM_NAME("rexec_af", 2, "inport"); // int
	ADD_PARAM_NAME("rexec_af", 3, "user"); // char *
	ADD_PARAM_NAME("rexec_af", 4, "passwd"); // char *
	ADD_PARAM_NAME("rexec_af", 5, "cmd"); // char *
	ADD_PARAM_NAME("rexec_af", 6, "fd2p"); // int *
	ADD_PARAM_NAME("rexec_af", 7, "address_family"); // sa_family_t
	ADD_PARAM_NAME("rresvport", 1, "port"); // int *
	ADD_PARAM_NAME("rresvport_af", 1, "port"); // int *
	ADD_PARAM_NAME("rresvport_af", 2, "address_family"); // sa_family_t
	ADD_PARAM_NAME("ruserok", 1, "rhost"); // const char *
	ADD_PARAM_NAME("ruserok", 2, "superuser"); // int
	ADD_PARAM_NAME("ruserok", 3, "ruser"); // const char *
	ADD_PARAM_NAME("ruserok", 4, "luser"); // const char *
	ADD_PARAM_NAME("ruserok_af", 1, "rhost"); // const char *
	ADD_PARAM_NAME("ruserok_af", 2, "superuser"); // int
	ADD_PARAM_NAME("ruserok_af", 3, "ruser"); // const char *
	ADD_PARAM_NAME("ruserok_af", 4, "luser"); // const char *
	ADD_PARAM_NAME("ruserok_af", 5, "address_family"); // sa_family_t
	ADD_PARAM_NAME("sethostent", 1, "stayopen"); // int
	ADD_PARAM_NAME("setnetent", 1, "stayopen"); // int
	ADD_PARAM_NAME("setnetgrent", 1, "netgroup"); // const char *
	ADD_PARAM_NAME("setprotoent", 1, "stayopen"); // int
	ADD_PARAM_NAME("setrpcent", 1, "stayopen"); // int
	ADD_PARAM_NAME("setservent", 1, "stayopen"); // int

	//
	// nl_types.h
	//
	ADD_PARAM_NAME("catclose", 1, "catalog"); // nl_catd
	ADD_PARAM_NAME("catgets", 1, "catalog"); // nl_catd
	ADD_PARAM_NAME("catgets", 2, "set_number"); // int
	ADD_PARAM_NAME("catgets", 3, "message_number"); // int
	ADD_PARAM_NAME("catgets", 4, "message"); // const char *
	ADD_PARAM_NAME("catopen", 1, "name"); // const char *
	ADD_PARAM_NAME("catopen", 2, "flag"); // int

	//
	// poll.h
	//
	ADD_PARAM_NAME("poll", 1, "fds"); // struct pollfd []
	ADD_PARAM_NAME("poll", 2, "nfds"); // nfds_t
	ADD_PARAM_NAME("poll", 3, "timeout"); // int

	//
	// pthread.h
	//
	ADD_PARAM_NAME("pthread_attr_destroy", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_getdetachstate", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_getdetachstate", 2, "detachstate"); // int *
	ADD_PARAM_NAME("pthread_attr_getguardsize", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_getguardsize", 2, "guardsize"); // size_t *
	ADD_PARAM_NAME("pthread_attr_getinheritsched", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_getinheritsched", 2, "inheritsched"); // int *
	ADD_PARAM_NAME("pthread_attr_getschedparam", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_getschedparam", 2, "param"); // struct sched_param *
	ADD_PARAM_NAME("pthread_attr_getschedpolicy", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_getschedpolicy", 2, "sched_policy"); // int *
	ADD_PARAM_NAME("pthread_attr_getscope", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_getscope", 2, "scope"); // int *
	ADD_PARAM_NAME("pthread_attr_getstack", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_getstack", 2, "stackaddr"); // void **
	ADD_PARAM_NAME("pthread_attr_getstack", 3, "stacksize"); // size_t *
	ADD_PARAM_NAME("pthread_attr_getstackaddr", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_getstackaddr", 2, "stackaddr"); // void **
	ADD_PARAM_NAME("pthread_attr_getstacksize", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_getstacksize", 2, "stacksize"); // size_t *
	ADD_PARAM_NAME("pthread_attr_init", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_setdetachstate", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_setdetachstate", 2, "detachstate"); // int
	ADD_PARAM_NAME("pthread_attr_setguardsize", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_setguardsize", 2, "guardsize"); // size_t
	ADD_PARAM_NAME("pthread_attr_setinheritsched", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_setinheritsched", 2, "inheritsched"); // int
	ADD_PARAM_NAME("pthread_attr_setschedparam", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_setschedparam", 2, "param"); // const struct sched_param *
	ADD_PARAM_NAME("pthread_attr_setschedpolicy", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_setschedpolicy", 2, "sched_policy"); // int
	ADD_PARAM_NAME("pthread_attr_setscope", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_setscope", 2, "scope"); // int
	ADD_PARAM_NAME("pthread_attr_setstack", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_setstack", 2, "stackaddr"); // void *
	ADD_PARAM_NAME("pthread_attr_setstack", 3, "stacksize"); // size_t
	ADD_PARAM_NAME("pthread_attr_setstackaddr", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_setstackaddr", 2, "stackaddr"); // void *
	ADD_PARAM_NAME("pthread_attr_setstacksize", 1, "attr"); // pthread_attr_t *
	ADD_PARAM_NAME("pthread_attr_setstacksize", 2, "stacksize"); // size_t
	ADD_PARAM_NAME("pthread_barrier_destroy", 1, "barrier"); // pthread_barrier_t *
	ADD_PARAM_NAME("pthread_barrier_init", 1, "barrier"); // pthread_barrier_t * restrict
	ADD_PARAM_NAME("pthread_barrier_init", 2, "attr"); // const pthread_barrierattr_t * restrict
	ADD_PARAM_NAME("pthread_barrier_init", 3, "count"); // unsigned
	ADD_PARAM_NAME("pthread_barrier_wait", 1, "barrier"); // pthread_barrier_t *
	ADD_PARAM_NAME("pthread_barrierattr_destroy", 1, "attr"); // pthread_barrierattr_t *
	ADD_PARAM_NAME("pthread_barrierattr_getpshared", 1, "attr"); // const pthread_barrierattr_t * restrict
	ADD_PARAM_NAME("pthread_barrierattr_getpshared", 3, "pshared"); // int * restrict
	ADD_PARAM_NAME("pthread_barrierattr_init", 1, "attr"); // pthread_barrierattr_t *
	ADD_PARAM_NAME("pthread_barrierattr_setpshared", 1, "attr"); // pthread_barrierattr_t *
	ADD_PARAM_NAME("pthread_barrierattr_setpshared", 2, "pshared"); // int
	ADD_PARAM_NAME("pthread_cancel", 1, "thread"); // pthread_t
	ADD_PARAM_NAME("pthread_cond_broadcast", 1, "cond"); // pthread_cond_t *
	ADD_PARAM_NAME("pthread_cond_destroy", 1, "cond"); // pthread_cond_t *
	ADD_PARAM_NAME("pthread_cond_init", 1, "cond"); // pthread_cond_t * restrict
	ADD_PARAM_NAME("pthread_cond_init", 2, "attr"); // const pthread_condattr_t * restrict
	ADD_PARAM_NAME("pthread_cond_signal", 1, "cond"); // pthread_cond_t *
	ADD_PARAM_NAME("pthread_cond_timedwait", 1, "cond"); // pthread_cond_t * restrict
	ADD_PARAM_NAME("pthread_cond_timedwait", 2, "mutex"); // pthread_mutex_t * restrict
	ADD_PARAM_NAME("pthread_cond_timedwait", 3, "abstime"); // const struct timespec * restrict
	ADD_PARAM_NAME("pthread_cond_wait", 1, "cond"); // pthread_cond_t * restrict
	ADD_PARAM_NAME("pthread_cond_wait", 2, "mutex"); // pthread_mutex_t * restrict
	ADD_PARAM_NAME("pthread_condattr_destroy", 1, "attr"); // pthread_condattr_t *
	ADD_PARAM_NAME("pthread_condattr_getclock", 1, "attr"); // const pthread_condattr_t * restrict
	ADD_PARAM_NAME("pthread_condattr_getclock", 2, "clock_id"); // clockid_t * restrict
	ADD_PARAM_NAME("pthread_condattr_getpshared", 1, "attr"); // const pthread_condattr_t * restrict
	ADD_PARAM_NAME("pthread_condattr_getpshared", 2, "pshared"); // int * restrict
	ADD_PARAM_NAME("pthread_condattr_init", 1, "attr"); // pthread_condattr_t *
	ADD_PARAM_NAME("pthread_condattr_setclock", 1, "attr"); // pthread_condattr_t *
	ADD_PARAM_NAME("pthread_condattr_setclock", 2, "clock_id"); // clockid_t
	ADD_PARAM_NAME("pthread_condattr_setpshared", 1, "attr"); // pthread_condattr_t *
	ADD_PARAM_NAME("pthread_condattr_setpshared", 2, "pshared"); // int
	ADD_PARAM_NAME("pthread_create", 1, "thread"); // pthread_t *
	ADD_PARAM_NAME("pthread_create", 2, "attr"); // const pthread_attr_t *
	ADD_PARAM_NAME("pthread_create", 3, "thread_func"); // void *(*)(void *)
	ADD_PARAM_NAME("pthread_create", 4, "thread_func_arg"); // void *
	ADD_PARAM_NAME("pthread_detach", 1, "thread"); // pthread_t
	ADD_PARAM_NAME("pthread_equal", 1, "t1"); // pthread_t
	ADD_PARAM_NAME("pthread_equal", 2, "t2"); // pthread_t
	ADD_PARAM_NAME("pthread_getcpuclockid", 1, "thread"); // pthread_t
	ADD_PARAM_NAME("pthread_getcpuclockid", 2, "clock_id"); // clockid_t *
	ADD_PARAM_NAME("pthread_getschedparam", 1, "thread"); // pthread_t
	ADD_PARAM_NAME("pthread_getschedparam", 2, "sched_policy"); // int *
	ADD_PARAM_NAME("pthread_getschedparam", 3, "param"); // struct sched_param *
	ADD_PARAM_NAME("pthread_getspecific", 1, "key"); // pthread_key_t
	ADD_PARAM_NAME("pthread_join", 1, "thread"); // pthread_t
	ADD_PARAM_NAME("pthread_join", 2, "retval"); // void **
	ADD_PARAM_NAME("pthread_key_delete", 1, "key"); // pthread_key_t
	ADD_PARAM_NAME("pthread_mutex_consistent", 1, "mutex"); // pthread_mutex_t *
	ADD_PARAM_NAME("pthread_mutex_destroy", 1, "mutex"); // pthread_mutex_t *
	ADD_PARAM_NAME("pthread_mutex_getprioceiling", 1, "mutex"); // const pthread_mutex_t * restrict
	ADD_PARAM_NAME("pthread_mutex_getprioceiling", 2, "prioceiling"); // int * restrict
	ADD_PARAM_NAME("pthread_mutex_init", 1, "mutex"); // pthread_mutex_t * restrict
	ADD_PARAM_NAME("pthread_mutex_init", 2, "attr"); // const pthread_mutexattr_t * restrict
	ADD_PARAM_NAME("pthread_mutex_lock", 1, "mutex"); // pthread_mutex_t *
	ADD_PARAM_NAME("pthread_mutex_setprioceiling", 1, "mutex"); // pthread_mutex_t * restrict
	ADD_PARAM_NAME("pthread_mutex_setprioceiling", 2, "prioceiling"); // int
	ADD_PARAM_NAME("pthread_mutex_setprioceiling", 3, "ceiling"); // int * restrict
	ADD_PARAM_NAME("pthread_mutex_timedlock", 1, "mutex"); // pthread_mutex_t * restrict
	ADD_PARAM_NAME("pthread_mutex_timedlock", 2, "abstime"); // const struct timespec * restrict
	ADD_PARAM_NAME("pthread_mutex_trylock", 1, "mutex"); // pthread_mutex_t *
	ADD_PARAM_NAME("pthread_mutex_unlock", 1, "mutex"); // pthread_mutex_t *
	ADD_PARAM_NAME("pthread_mutexattr_destroy", 1, "attr"); // pthread_mutexattr_t *
	ADD_PARAM_NAME("pthread_mutexattr_getprioceiling", 1, "attr"); // const pthread_mutexattr_t *
	ADD_PARAM_NAME("pthread_mutexattr_getprioceiling", 2, "prioceiling"); // int * restrict
	ADD_PARAM_NAME("pthread_mutexattr_getprotocol", 1, "attr"); // const pthread_mutexattr_t * restrict
	ADD_PARAM_NAME("pthread_mutexattr_getprotocol", 2, "protocol"); // int * restrict
	ADD_PARAM_NAME("pthread_mutexattr_getpshared", 1, "attr"); // const pthread_mutexattr_t * restrict
	ADD_PARAM_NAME("pthread_mutexattr_getpshared", 2, "pshared"); // int * restrict
	ADD_PARAM_NAME("pthread_mutexattr_getrobust", 1, "attr"); // const pthread_mutexattr_t * restrict
	ADD_PARAM_NAME("pthread_mutexattr_getrobust", 2, "robust"); // int * restrict
	ADD_PARAM_NAME("pthread_mutexattr_gettype", 1, "attr"); // const pthread_mutexattr_t * restrict
	ADD_PARAM_NAME("pthread_mutexattr_gettype", 2, "type"); // int * restrict
	ADD_PARAM_NAME("pthread_mutexattr_init", 1, "attr"); // pthread_mutexattr_t *
	ADD_PARAM_NAME("pthread_mutexattr_setprioceiling", 1, "attr"); // pthread_mutexattr_t *
	ADD_PARAM_NAME("pthread_mutexattr_setprioceiling", 2, "prioceiling"); // int
	ADD_PARAM_NAME("pthread_mutexattr_setprotocol", 1, "attr"); // pthread_mutexattr_t *
	ADD_PARAM_NAME("pthread_mutexattr_setprotocol", 2, "protocol"); // int
	ADD_PARAM_NAME("pthread_mutexattr_setpshared", 1, "attr"); // pthread_mutexattr_t *
	ADD_PARAM_NAME("pthread_mutexattr_setpshared", 2, "pshared"); // int
	ADD_PARAM_NAME("pthread_mutexattr_setrobust", 1, "attr"); // pthread_mutexattr_t *
	ADD_PARAM_NAME("pthread_mutexattr_setrobust", 2, "robust"); // int
	ADD_PARAM_NAME("pthread_mutexattr_settype", 1, "attr"); // pthread_mutexattr_t *
	ADD_PARAM_NAME("pthread_mutexattr_settype", 2, "type"); // int
	ADD_PARAM_NAME("pthread_rwlock_destroy", 1, "rwlock"); // pthread_rwlock_t *
	ADD_PARAM_NAME("pthread_rwlock_init", 1, "rwlock"); // pthread_rwlock_t * restrict
	ADD_PARAM_NAME("pthread_rwlock_init", 2, "attr"); // const pthread_rwlockattr_t * restrict
	ADD_PARAM_NAME("pthread_rwlock_rdlock", 1, "rwlock"); // pthread_rwlock_t *
	ADD_PARAM_NAME("pthread_rwlock_timedrdlock", 1, "rwlock"); // pthread_rwlock_t * restrict
	ADD_PARAM_NAME("pthread_rwlock_timedrdlock", 2, "abstime"); // const struct timespec * restrict
	ADD_PARAM_NAME("pthread_rwlock_timedwrlock", 1, "rwlock"); // pthread_rwlock_t * restrict
	ADD_PARAM_NAME("pthread_rwlock_timedwrlock", 2, "abstime"); // const struct timespec * restrict
	ADD_PARAM_NAME("pthread_rwlock_tryrdlock", 1, "rwlock"); // pthread_rwlock_t *
	ADD_PARAM_NAME("pthread_rwlock_trywrlock", 1, "rwlock"); // pthread_rwlock_t *
	ADD_PARAM_NAME("pthread_rwlock_unlock", 1, "rwlock"); // pthread_rwlock_t *
	ADD_PARAM_NAME("pthread_rwlock_wrlock", 1, "rwlock"); // pthread_rwlock_t *
	ADD_PARAM_NAME("pthread_rwlockattr_destroy", 1, "attr"); // pthread_rwlockattr_t *
	ADD_PARAM_NAME("pthread_rwlockattr_getpshared", 1, "attr"); // const pthread_rwlockattr_t * restrict
	ADD_PARAM_NAME("pthread_rwlockattr_getpshared", 2, "pshared"); // int * restrict
	ADD_PARAM_NAME("pthread_rwlockattr_init", 1, "attr"); // pthread_rwlockattr_t *
	ADD_PARAM_NAME("pthread_rwlockattr_setpshared", 1, "attr"); // pthread_rwlockattr_t *
	ADD_PARAM_NAME("pthread_rwlockattr_setpshared", 2, "pshared"); // int
	ADD_PARAM_NAME("pthread_rwlockattr_getkind_np", 1, "attr"); // const pthread_rwlockattr_t *
	ADD_PARAM_NAME("pthread_rwlockattr_getkind_np", 2, "pref"); // int *
	ADD_PARAM_NAME("pthread_rwlockattr_setkind_np", 1, "attr"); // pthread_rwlockattr_t *
	ADD_PARAM_NAME("pthread_rwlockattr_setkind_np", 2, "pref"); // int *
	ADD_PARAM_NAME("pthread_setcancelstate", 1, "state"); // int
	ADD_PARAM_NAME("pthread_setcancelstate", 2, "state"); // int *
	ADD_PARAM_NAME("pthread_setcanceltype", 1, "type"); // int
	ADD_PARAM_NAME("pthread_setcanceltype", 2, "type"); // int *
	ADD_PARAM_NAME("pthread_setschedparam", 1, "thread"); // pthread_t
	ADD_PARAM_NAME("pthread_setschedparam", 2, "sched_policy"); // int
	ADD_PARAM_NAME("pthread_setschedparam", 3, "param"); // const struct sched_param *
	ADD_PARAM_NAME("pthread_setschedprio", 1, "thread"); // pthread_t
	ADD_PARAM_NAME("pthread_setschedprio", 2, "prio"); // int
	ADD_PARAM_NAME("pthread_setspecific", 1, "key"); // pthread_key_t
	ADD_PARAM_NAME("pthread_setspecific", 2, "value"); // const void *
	ADD_PARAM_NAME("pthread_spin_destroy", 1, "lock"); // pthread_spinlock_t *
	ADD_PARAM_NAME("pthread_spin_init", 1, "lock"); // pthread_spinlock_t *
	ADD_PARAM_NAME("pthread_spin_init", 2, "pshared"); // int
	ADD_PARAM_NAME("pthread_spin_lock", 1, "lock"); // pthread_spinlock_t *
	ADD_PARAM_NAME("pthread_spin_trylock", 1, "lock"); // pthread_spinlock_t *
	ADD_PARAM_NAME("pthread_spin_unlock", 1, "lock"); // pthread_spinlock_t *

	//
	// pwd.h
	//
	ADD_PARAM_NAME("fgetpwent_r", 1, "file"); // FILE *
	ADD_PARAM_NAME("fgetpwent_r", 2, "pwbuf"); // struct passwd *
	ADD_PARAM_NAME("fgetpwent_r", 3, "buf"); // char *
	ADD_PARAM_NAME("fgetpwent_r", 4, "buf_len"); // size_t
	ADD_PARAM_NAME("fgetpwent_r", 5, "pwbufp"); // struct passwd **
	ADD_PARAM_NAME("getpwent_r", 1, "pwbuf"); // struct passwd *
	ADD_PARAM_NAME("getpwent_r", 2, "buf"); // char *
	ADD_PARAM_NAME("getpwent_r", 3, "buf_len"); // size_t
	ADD_PARAM_NAME("getpwent_r", 4, "pwbufp"); // struct passwd **

	//
	// sched.h
	//
	ADD_PARAM_NAME("posix_spawnattr_setschedparam", 1, "attr"); // posix_spawnattr_t * restrict
	ADD_PARAM_NAME("posix_spawnattr_setschedparam", 2, "schedparam"); // const struct sched_param * restrict
	ADD_PARAM_NAME("posix_spawnattr_setschedpolicy", 1, "attr"); // posix_spawnattr_t *
	ADD_PARAM_NAME("posix_spawnattr_setschedpolicy", 2, "sched_policy"); // int
	ADD_PARAM_NAME("sched_get_priority_max", 1, "sched_policy"); // int
	ADD_PARAM_NAME("sched_get_priority_min", 1, "sched_policy"); // int
	ADD_PARAM_NAME("sched_getparam", 1, "pid"); // pid_t
	ADD_PARAM_NAME("sched_getparam", 2, "param"); // struct sched_param *
	ADD_PARAM_NAME("sched_getscheduler", 1, "pid"); // pid_t
	ADD_PARAM_NAME("sched_rr_get_interval", 1, "pid"); // pid_t
	ADD_PARAM_NAME("sched_rr_get_interval", 2, "interval"); // struct timespec *
	ADD_PARAM_NAME("sched_setparam", 1, "pid"); // pid_t
	ADD_PARAM_NAME("sched_setparam", 2, "param"); // const struct sched_param *
	ADD_PARAM_NAME("sched_setscheduler", 1, "pid"); // pid_t
	ADD_PARAM_NAME("sched_setscheduler", 2, "sched_policy"); // int
	ADD_PARAM_NAME("sched_setscheduler", 3, "param"); // const struct sched_param *

	//
	// search.h
	//
	ADD_PARAM_NAME("hcreate", 1, "nel"); // size_t
	ADD_PARAM_NAME("hsearch", 1, "item"); // ENTRY
	ADD_PARAM_NAME("hsearch", 2, "action"); // ACTION
	ADD_PARAM_NAME("lfind", 1, "key"); // const void *
	ADD_PARAM_NAME("lfind", 2, "base"); // const void *
	ADD_PARAM_NAME("lfind", 3, "nmemb"); // size_t *
	ADD_PARAM_NAME("lfind", 4, "size"); // size_t
	ADD_PARAM_NAME("lfind", 5, "cmp_func"); // int (*)(const void *, const void *)
	ADD_PARAM_NAME("lsearch", 1, "key"); // const void *
	ADD_PARAM_NAME("lsearch", 2, "base"); // const void *
	ADD_PARAM_NAME("lsearch", 3, "nmemb"); // size_t *
	ADD_PARAM_NAME("lsearch", 4, "size"); // size_t
	ADD_PARAM_NAME("lsearch", 5, "cmp_func"); // int (*)(const void *, const void *)
	ADD_PARAM_NAME("tdelete", 1, "key"); // const void **
	ADD_PARAM_NAME("tdelete", 2, "rootp"); // void **
	ADD_PARAM_NAME("tdelete", 3, "cmp_func"); // int (*)(const void *, const void *)
	ADD_PARAM_NAME("tfind", 1, "key"); // const void **
	ADD_PARAM_NAME("tfind", 2, "rootp"); // void **
	ADD_PARAM_NAME("tfind", 3, "cmp_func"); // int (*)(const void *, const void *)
	ADD_PARAM_NAME("tsearch", 1, "key"); // const void **
	ADD_PARAM_NAME("tsearch", 2, "rootp"); // void **
	ADD_PARAM_NAME("tsearch", 3, "cmp_func"); // int (*)(const void *, const void *)
	ADD_PARAM_NAME("twalk", 1, "root"); // const void *
	ADD_PARAM_NAME("twalk", 2, "action_func"); // void (*)(const void *, const VISIT, const int)

	//
	// semaphore.h
	//
	ADD_PARAM_NAME("sem_close", 1, "sem"); // sem_t *
	ADD_PARAM_NAME("sem_destroy", 1, "sem"); // sem_t *
	ADD_PARAM_NAME("sem_getvalue", 1, "sem"); // sem_t *
	ADD_PARAM_NAME("sem_getvalue", 2, "sval"); // int *
	ADD_PARAM_NAME("sem_init", 1, "sem"); // sem_t *
	ADD_PARAM_NAME("sem_init", 2, "pshared"); // int
	ADD_PARAM_NAME("sem_init", 3, "value"); // unsigned int
	ADD_PARAM_NAME("sem_post", 1, "sem"); // sem_t *
	ADD_PARAM_NAME("sem_timedwait", 1, "sem"); // sem_t *
	ADD_PARAM_NAME("sem_timedwait", 2, "abs_timeout"); // const struct timespec *
	ADD_PARAM_NAME("sem_trywait", 1, "sem"); // sem_t *
	ADD_PARAM_NAME("sem_unlink", 1, "name"); // const char *
	ADD_PARAM_NAME("sem_wait", 1, "sem"); // sem_t *

	//
	// setjmp.h
	//
	ADD_PARAM_NAME("_longjmp", 1, "env"); // jmp_buf
	ADD_PARAM_NAME("_longjmp", 2, "val"); // int
	ADD_PARAM_NAME("_setjmp", 1, "env"); // jmp_buf
	ADD_PARAM_NAME("siglongjmp", 1, "env"); // sigjmp_buf
	ADD_PARAM_NAME("siglongjmp", 2, "val"); // int

	//
	// signal.h
	//
	ADD_PARAM_NAME("gsignal", 1, "sig_num"); // int
	ADD_PARAM_NAME("kill", 1, "pid"); // pid_t
	ADD_PARAM_NAME("kill", 2, "sig_num"); // int
	ADD_PARAM_NAME("killpg", 1, "pgrp"); // pid_t
	ADD_PARAM_NAME("killpg", 2, "sig_num"); // int
	ADD_PARAM_NAME("posix_spawnattr_getsigdefault", 1, "attr"); // const posix_spawnattr_t * restrict
	ADD_PARAM_NAME("posix_spawnattr_getsigdefault", 2, "sigdefault"); // sigset_t * restrict
	ADD_PARAM_NAME("posix_spawnattr_getsigmask", 1, "attr"); // const posix_spawnattr_t * restrict
	ADD_PARAM_NAME("posix_spawnattr_getsigmask", 2, "sigmask"); // sigset_t * restrict
	ADD_PARAM_NAME("posix_spawnattr_setsigdefault", 1, "attr"); // posix_spawnattr_t * restrict
	ADD_PARAM_NAME("posix_spawnattr_setsigdefault", 2, "sigdefault"); // const sigset_t * restrict
	ADD_PARAM_NAME("posix_spawnattr_setsigmask", 1, "attr"); // posix_spawnattr_t * restrict
	ADD_PARAM_NAME("posix_spawnattr_setsigmask", 2, "sigmask"); // const sigset_t * restrict
	ADD_PARAM_NAME("psiginfo", 1, "pinfo"); // const siginfo_t *
	ADD_PARAM_NAME("psiginfo", 2, "str"); // const char *
	ADD_PARAM_NAME("psignal", 1, "sig_num"); // int
	ADD_PARAM_NAME("psignal", 2, "str"); // const char *
	ADD_PARAM_NAME("pthread_kill", 1, "thread"); // pthread_t
	ADD_PARAM_NAME("pthread_kill", 2, "sig_num"); // int
	ADD_PARAM_NAME("pthread_sigmask", 1, "how"); // int
	ADD_PARAM_NAME("pthread_sigmask", 2, "set"); // const sigset_t *
	ADD_PARAM_NAME("pthread_sigmask", 3, "set"); // sigset_t *
	ADD_PARAM_NAME("sigaction", 1, "sig_num"); // int
	ADD_PARAM_NAME("sigaction", 2, "act"); // const struct sigaction * restrict
	ADD_PARAM_NAME("sigaction", 3, "oact"); // struct sigaction * restrict
	ADD_PARAM_NAME("sigaddset", 1, "set"); // sigset_t *
	ADD_PARAM_NAME("sigaddset", 2, "sig_num"); // int
	ADD_PARAM_NAME("sigaltstack", 1, "ss"); // const stack_t * restrict
	ADD_PARAM_NAME("sigaltstack", 2, "oss"); // stack_t * restrict
	ADD_PARAM_NAME("sigblock", 1, "mask"); // int
	ADD_PARAM_NAME("sigdelset", 1, "set"); // sigset_t *
	ADD_PARAM_NAME("sigdelset", 2, "sig_num"); // int
	ADD_PARAM_NAME("sigemptyset", 1, "set"); // sigset_t *
	ADD_PARAM_NAME("sigfillset", 1, "set"); // sigset_t *
	ADD_PARAM_NAME("siginterrupt", 1, "sig_num"); // int
	ADD_PARAM_NAME("siginterrupt", 2, "flag"); // int
	ADD_PARAM_NAME("sigismember", 1, "set"); // const sigset_t *
	ADD_PARAM_NAME("sigismember", 2, "sig_num"); // int
	ADD_PARAM_NAME("sigpending", 1, "set"); // sigset_t *
	ADD_PARAM_NAME("sigprocmask", 1, "how"); // int
	ADD_PARAM_NAME("sigprocmask", 2, "set"); // const sigset_t * restrict
	ADD_PARAM_NAME("sigprocmask", 3, "oset"); // sigset_t * restrict
	ADD_PARAM_NAME("sigqueue", 1, "pid"); // pid_t
	ADD_PARAM_NAME("sigqueue", 2, "sig_num"); // int
	ADD_PARAM_NAME("sigqueue", 3, "value"); // const union sigval
	ADD_PARAM_NAME("sigsetmask", 1, "mask"); // int
	ADD_PARAM_NAME("sigstack", 1, "ss"); // struct sigstack *
	ADD_PARAM_NAME("sigstack", 2, "ss"); // struct sigstack *
	ADD_PARAM_NAME("sigsuspend", 1, "sigmask"); // const sigset_t *
	ADD_PARAM_NAME("sigtimedwait", 1, "set"); // const sigset_t * restrict
	ADD_PARAM_NAME("sigtimedwait", 2, "info"); // siginfo_t * restrict
	ADD_PARAM_NAME("sigtimedwait", 3, "timeout"); // const struct timespec * restrict
	ADD_PARAM_NAME("sigvec", 1, "sig_num"); // int
	ADD_PARAM_NAME("sigvec", 2, "vec"); // struct sigvec *
	ADD_PARAM_NAME("sigvec", 3, "ovec"); // struct sigvec *
	ADD_PARAM_NAME("sigwait", 1, "set"); // const sigset_t *
	ADD_PARAM_NAME("sigwait", 2, "sig_num"); // int *
	ADD_PARAM_NAME("sigwaitinfo", 1, "set"); // const sigset_t * restrict
	ADD_PARAM_NAME("sigwaitinfo", 2, "info"); // siginfo_t * restrict
	ADD_PARAM_NAME("ssignal", 1, "sig_num"); // int
	ADD_PARAM_NAME("ssignal", 2, "action"); // sighandler_t
	ADD_PARAM_NAME("timer_create", 1, "clockid"); // clockid_t
	ADD_PARAM_NAME("timer_create", 2, "evp"); // struct sigevent * restrict
	ADD_PARAM_NAME("timer_create", 3, "timerid"); // timer_t * restrict

	//
	// spawn.h
	//
	ADD_PARAM_NAME("posix_spawn", 1, "pid"); // pid_t * restrict
	ADD_PARAM_NAME("posix_spawn", 2, "path"); // const char * restrict
	ADD_PARAM_NAME("posix_spawn", 3, "file_actions"); // const posix_spawn_file_actions_t *
	ADD_PARAM_NAME("posix_spawn", 4, "attrp"); // const posix_spawnattr_t *restrict
	ADD_PARAM_NAME("posix_spawn", 5, "argv"); // char * const [restrict]
	ADD_PARAM_NAME("posix_spawn", 6, "envp"); // char * const [restrict]
	ADD_PARAM_NAME("posix_spawn_file_actions_addclose", 1, "file_actions"); // posix_spawn_file_actions_t *restrict
	ADD_PARAM_NAME("posix_spawn_file_actions_addclose", 2, "fd"); // int
	ADD_PARAM_NAME("posix_spawn_file_actions_adddup2", 1, "file_actions"); // posix_spawn_file_actions_t *
	ADD_PARAM_NAME("posix_spawn_file_actions_adddup2", 2, "fd"); // int
	ADD_PARAM_NAME("posix_spawn_file_actions_adddup2", 3, "fd"); // int
	ADD_PARAM_NAME("posix_spawn_file_actions_addopen", 1, "file_actions"); // posix_spawn_file_actions_t *restrict
	ADD_PARAM_NAME("posix_spawn_file_actions_addopen", 2, "fd"); // int
	ADD_PARAM_NAME("posix_spawn_file_actions_addopen", 3, "path"); // const char *restrict
	ADD_PARAM_NAME("posix_spawn_file_actions_addopen", 4, "oflag"); // int
	ADD_PARAM_NAME("posix_spawn_file_actions_addopen", 5, "mode"); // mode_t
	ADD_PARAM_NAME("posix_spawn_file_actions_destroy", 1, "file_actions"); // posix_spawn_file_actions_t *
	ADD_PARAM_NAME("posix_spawn_file_actions_init", 1, "file_actions"); // posix_spawn_file_actions_t *
	ADD_PARAM_NAME("posix_spawnattr_destroy", 1, "attr"); // posix_spawnattr_t *
	ADD_PARAM_NAME("posix_spawnattr_getflags", 1, "attr"); // const posix_spawnattr_t * restrict
	ADD_PARAM_NAME("posix_spawnattr_getflags", 2, "flags"); // short * restrict
	ADD_PARAM_NAME("posix_spawnattr_getpgroup", 1, "attr"); // const posix_spawnattr_t * restrict
	ADD_PARAM_NAME("posix_spawnattr_getpgroup", 2, "pgroup"); // pid_t * restrict
	ADD_PARAM_NAME("posix_spawnattr_getschedparam", 1, "attr"); // const posix_spawnattr_t * restrict
	ADD_PARAM_NAME("posix_spawnattr_getschedparam", 2, "sched_param"); // struct sched_param *restrict
	ADD_PARAM_NAME("posix_spawnattr_getschedpolicy", 1, "attr"); // const posix_spawnattr_t * restrict
	ADD_PARAM_NAME("posix_spawnattr_getschedpolicy", 2, "sched_policy"); // int *
	ADD_PARAM_NAME("posix_spawnattr_init", 1, "attr"); // posix_spawnattr_t *
	ADD_PARAM_NAME("posix_spawnattr_setflags", 1, "attr"); // posix_spawnattr_t *
	ADD_PARAM_NAME("posix_spawnattr_setflags", 2, "flags"); // short
	ADD_PARAM_NAME("posix_spawnattr_setpgroup", 1, "attr"); // posix_spawnattr_t *
	ADD_PARAM_NAME("posix_spawnattr_setpgroup", 2, "pgroup"); // pid_t
	ADD_PARAM_NAME("posix_spawnp", 1, "pid"); // pid_t * restrict
	ADD_PARAM_NAME("posix_spawnp", 2, "path"); // const char * restrict
	ADD_PARAM_NAME("posix_spawnp", 3, "file_actions"); // const posix_spawn_file_actions_t *
	ADD_PARAM_NAME("posix_spawnp", 4, "attrp"); // const posix_spawnattr_t *restrict
	ADD_PARAM_NAME("posix_spawnp", 5, "argv"); // char * const [restrict]
	ADD_PARAM_NAME("posix_spawnp", 6, "envp"); // char * const [restrict]

	//
	// stddef.h
	//
	ADD_PARAM_NAME("wcstoimax", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcstoimax", 2, "endptr"); // wchar_t **
	ADD_PARAM_NAME("wcstoimax", 3, "base"); // int
	ADD_PARAM_NAME("wcstoumax", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcstoumax", 2, "endptr"); // wchar_t **
	ADD_PARAM_NAME("wcstoumax", 3, "base"); // int

	//
	// stdio.h
	//
	ADD_PARAM_NAME("clearerr_unlocked", 1, "stream"); // FILE *
	ADD_PARAM_NAME("ctermid", 1, "str"); // char *
	ADD_PARAM_NAME("dprintf", 1, "fd"); // int
	ADD_PARAM_NAME("dprintf", 2, "format"); // const char *
	ADD_PARAM_NAME("fdopen", 1, "fd"); // int
	ADD_PARAM_NAME("fdopen", 2, "mode"); // const char *
	ADD_PARAM_NAME("feof_unlocked", 1, "stream"); // FILE *
	ADD_PARAM_NAME("ferror_unlocked", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fflush_unlocked", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fgetc_unlocked", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fgetgrent", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fgetpwent", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fileno", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fileno_unlocked", 1, "stream"); // FILE *
	ADD_PARAM_NAME("flockfile", 1, "file"); // FILE *
	ADD_PARAM_NAME("fputc_unlocked", 1, "c"); // int
	ADD_PARAM_NAME("fputc_unlocked", 2, "stream"); // FILE *
	ADD_PARAM_NAME("fseeko", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fseeko", 2, "offset"); // off_t
	ADD_PARAM_NAME("fseeko", 3, "whence"); // int
	ADD_PARAM_NAME("ftello", 1, "stream"); // FILE *
	ADD_PARAM_NAME("ftrylockfile", 1, "file"); // FILE *
	ADD_PARAM_NAME("funlockfile", 1, "file"); // FILE *
	ADD_PARAM_NAME("fwrite_unlocked", 1, "data"); // const void *
	ADD_PARAM_NAME("fwrite_unlocked", 2, "size"); // size_t
	ADD_PARAM_NAME("fwrite_unlocked", 3, "n"); // size_t
	ADD_PARAM_NAME("fwrite_unlocked", 4, "stream"); // FILE *
	ADD_PARAM_NAME("getc_unlocked", 1, "stream"); // FILE *
	ADD_PARAM_NAME("getdelim", 1, "lineptr"); // char **
	ADD_PARAM_NAME("getdelim", 2, "n"); // size_t *
	ADD_PARAM_NAME("getdelim", 3, "delim"); // int
	ADD_PARAM_NAME("getdelim", 4, "stream"); // FILE *
	ADD_PARAM_NAME("getline", 1, "lineptr"); // char **
	ADD_PARAM_NAME("getline", 2, "n"); // size_t *
	ADD_PARAM_NAME("getline", 3, "stream"); // FILE *
	ADD_PARAM_NAME("getw", 1, "stream"); // FILE *
	ADD_PARAM_NAME("open_memstream", 1, "data"); // char **
	ADD_PARAM_NAME("open_memstream", 2, "sizeloc"); // size_t *
	ADD_PARAM_NAME("open_wmemstream", 1, "data"); // wchar_t **
	ADD_PARAM_NAME("open_wmemstream", 2, "sizeloc"); // size_t *
	ADD_PARAM_NAME("pclose", 1, "stream"); // FILE *
	ADD_PARAM_NAME("popen", 1, "command"); // const char *
	ADD_PARAM_NAME("popen", 2, "type"); // const char *
	ADD_PARAM_NAME("putc_unlocked", 1, "c"); // int
	ADD_PARAM_NAME("putc_unlocked", 2, "stream"); // FILE *
	ADD_PARAM_NAME("putchar_unlocked", 1, "c"); // int
	ADD_PARAM_NAME("putpwent", 1, "p"); // const struct passwd *
	ADD_PARAM_NAME("putpwent", 2, "stream"); // FILE *
	ADD_PARAM_NAME("putw", 1, "w"); // int
	ADD_PARAM_NAME("putw", 2, "stream"); // FILE *
	ADD_PARAM_NAME("renameat", 1, "fd"); // int
	ADD_PARAM_NAME("renameat", 2, "path"); // const char *
	ADD_PARAM_NAME("renameat", 3, "fd"); // int
	ADD_PARAM_NAME("renameat", 4, "path"); // const char *
	ADD_PARAM_NAME("setbuffer", 1, "stream"); // FILE *
	ADD_PARAM_NAME("setbuffer", 2, "buf"); // char *
	ADD_PARAM_NAME("setbuffer", 3, "size"); // size_t
	ADD_PARAM_NAME("setlinebuf", 1, "stream"); // FILE *
	ADD_PARAM_NAME("tempnam", 1, "dir"); // const char *
	ADD_PARAM_NAME("tempnam", 2, "pfx"); // const char *
	ADD_PARAM_NAME("tmpnam_r", 1, "file_name"); // char *s
	ADD_PARAM_NAME("vdprintf", 1, "fd"); // int
	ADD_PARAM_NAME("vdprintf", 2, "format"); // const char *
	ADD_PARAM_NAME("vdprintf", 3, "ap"); // va_list

	//
	// stdlib.h
	//
	ADD_PARAM_NAME("_exit", 1, "status"); // int
	ADD_PARAM_NAME("a64l", 1, "str64"); // char *
	ADD_PARAM_NAME("drand48_r", 1, "buf"); // struct drand48_data *
	// ADD_PARAM_NAME("drand48_r", 2, "result"); // double *
	ADD_PARAM_NAME("ecvt", 1, "number"); // double
	ADD_PARAM_NAME("ecvt", 2, "ndigits"); // int
	ADD_PARAM_NAME("ecvt", 3, "decpt"); // int *
	ADD_PARAM_NAME("ecvt", 4, "sign"); // int *
	ADD_PARAM_NAME("ecvt_r", 1, "number"); // double
	ADD_PARAM_NAME("ecvt_r", 2, "ndigits"); // int
	ADD_PARAM_NAME("ecvt_r", 3, "decpt"); // int *
	ADD_PARAM_NAME("ecvt_r", 4, "sign"); // int *
	ADD_PARAM_NAME("ecvt_r", 5, "buf"); // char *
	ADD_PARAM_NAME("ecvt_r", 6, "length"); // size_t
	ADD_PARAM_NAME("erand48", 1, "xsubi"); // unsigned short [3]
	ADD_PARAM_NAME("erand48_r", 1, "xsubi"); // unsigned short [3]
	ADD_PARAM_NAME("erand48_r", 2, "buf"); // struct drand48_data *
	// ADD_PARAM_NAME("erand48_r", 3, "result"); // double *
	ADD_PARAM_NAME("fcvt", 1, "number"); // double
	ADD_PARAM_NAME("fcvt", 2, "ndigits"); // int
	ADD_PARAM_NAME("fcvt", 3, "decpt"); // int *
	ADD_PARAM_NAME("fcvt", 4, "sign"); // int *
	ADD_PARAM_NAME("fcvt_r", 1, "number"); // double
	ADD_PARAM_NAME("fcvt_r", 2, "ndigits"); // int
	ADD_PARAM_NAME("fcvt_r", 3, "decpt"); // int *
	ADD_PARAM_NAME("fcvt_r", 4, "sign"); // int *
	ADD_PARAM_NAME("fcvt_r", 5, "buf"); // char *
	ADD_PARAM_NAME("fcvt_r", 6, "length"); // size_t
	ADD_PARAM_NAME("gcvt", 1, "number"); // double
	ADD_PARAM_NAME("gcvt", 2, "ndigit"); // size_t
	ADD_PARAM_NAME("gcvt", 3, "buf"); // char *
	ADD_PARAM_NAME("getloadavg", 1, "loadavg"); // double []
	ADD_PARAM_NAME("getloadavg", 2, "nelem"); // int
	ADD_PARAM_NAME("getsubopt", 1, "optionp"); // char **
	ADD_PARAM_NAME("getsubopt", 2, "tokens"); // char * const *
	ADD_PARAM_NAME("getsubopt", 3, "valuep"); // char **
	ADD_PARAM_NAME("imaxabs", 1, "j"); // intmax_t
	ADD_PARAM_NAME("imaxdiv", 1, "numerator"); // intmax_t
	ADD_PARAM_NAME("imaxdiv", 2, "denominator"); // intmax_t
	ADD_PARAM_NAME("initstate", 1, "seed"); // unsigned int
	ADD_PARAM_NAME("initstate", 2, "state"); // char *
	ADD_PARAM_NAME("initstate", 3, "n"); // size_t
	ADD_PARAM_NAME("initstate_r", 1, "seed"); // unsigned int
	ADD_PARAM_NAME("initstate_r", 2, "statebuf"); // char *
	ADD_PARAM_NAME("initstate_r", 3, "statelen"); // size_t
	ADD_PARAM_NAME("initstate_r", 4, "buf"); // struct random_data *
	ADD_PARAM_NAME("jrand48", 1, "xsubi"); // unsigned short [3]
	ADD_PARAM_NAME("jrand48_r", 1, "xsubi"); // unsigned short int [3]
	ADD_PARAM_NAME("jrand48_r", 2, "buf"); // struct drand48_data *
	// ADD_PARAM_NAME("jrand48_r", 3, "result"); // long int *
	ADD_PARAM_NAME("l64a", 1, "value"); // long
	ADD_PARAM_NAME("lcong48", 1, "param"); // unsigned short [7]
	ADD_PARAM_NAME("lcong48_r", 1, "param"); // unsigned short int [7]
	ADD_PARAM_NAME("lcong48_r", 2, "buf"); // struct drand48_data *
	ADD_PARAM_NAME("lrand48_r", 1, "buf"); // struct drand48_data *
	// ADD_PARAM_NAME("lrand48_r", 2, "result"); // long int *
	ADD_PARAM_NAME("mblen", 1, "str"); // const char *
	ADD_PARAM_NAME("mblen", 2, "n"); // size_t
	ADD_PARAM_NAME("mbstowcs", 1, "dest"); // wchar_t *
	ADD_PARAM_NAME("mbstowcs", 2, "src"); // const char *
	ADD_PARAM_NAME("mbstowcs", 3, "n"); // size_t
	ADD_PARAM_NAME("mbtowc", 1, "pwc"); // wchar_t *
	ADD_PARAM_NAME("mbtowc", 2, "str"); // const char *
	ADD_PARAM_NAME("mbtowc", 3, "n"); // size_t
	ADD_PARAM_NAME("mkdtemp", 1, "template"); // char *
	ADD_PARAM_NAME("mkstemp", 1, "template"); // char *
	ADD_PARAM_NAME("mkstemps", 1, "template"); // char *
	ADD_PARAM_NAME("mkstemps", 2, "suffix_len"); // int
	ADD_PARAM_NAME("mktemp", 1, "template"); // char *
	ADD_PARAM_NAME("mrand48_r", 1, "buf"); // struct drand48_data *
	// ADD_PARAM_NAME("mrand48_r", 2, "result"); // long int *
	ADD_PARAM_NAME("nrand48", 1, "xsubi"); // unsigned short [3]
	ADD_PARAM_NAME("nrand48_r", 1, "xsubi"); // unsigned short int [3]
	ADD_PARAM_NAME("nrand48_r", 2, "buf"); // struct drand48_data *
	// ADD_PARAM_NAME("nrand48_r", 3, "result"); // long int *
	ADD_PARAM_NAME("putenv", 1, "str"); // char *
	ADD_PARAM_NAME("qecvt", 1, "number"); // long double
	ADD_PARAM_NAME("qecvt", 2, "ndigits"); // int
	ADD_PARAM_NAME("qecvt", 3, "decpt"); // int *
	ADD_PARAM_NAME("qecvt", 4, "sign"); // int *
	ADD_PARAM_NAME("qecvt_r", 1, "number"); // long double
	ADD_PARAM_NAME("qecvt_r", 2, "ndigits"); // int
	ADD_PARAM_NAME("qecvt_r", 3, "decpt"); // int *
	ADD_PARAM_NAME("qecvt_r", 4, "sign"); // int *
	ADD_PARAM_NAME("qecvt_r", 5, "buf"); // char *
	ADD_PARAM_NAME("qecvt_r", 6, "length"); // size_t
	ADD_PARAM_NAME("qfcvt", 1, "number"); // long double
	ADD_PARAM_NAME("qfcvt", 2, "ndigits"); // int
	ADD_PARAM_NAME("qfcvt", 3, "decpt"); // int *
	ADD_PARAM_NAME("qfcvt", 4, "sign"); // int *
	ADD_PARAM_NAME("qfcvt_r", 1, "number"); // long double
	ADD_PARAM_NAME("qfcvt_r", 2, "ndigits"); // int
	ADD_PARAM_NAME("qfcvt_r", 3, "decpt"); // int *
	ADD_PARAM_NAME("qfcvt_r", 4, "sign"); // int *
	ADD_PARAM_NAME("qfcvt_r", 5, "buf"); // char *
	ADD_PARAM_NAME("qfcvt_r", 6, "length"); // size_t
	ADD_PARAM_NAME("qgcvt", 1, "number"); // long double
	ADD_PARAM_NAME("qgcvt", 2, "ndigit"); // int
	ADD_PARAM_NAME("qgcvt", 3, "buf"); // char *
	ADD_PARAM_NAME("rand_r", 1, "seedp"); // unsigned int *
	ADD_PARAM_NAME("random_r", 1, "buf"); // struct random_data *
	// ADD_PARAM_NAME("random_r", 2, "result"); // int32_t *
	ADD_PARAM_NAME("rpmatch", 1, "response"); // const char *
	ADD_PARAM_NAME("seed48", 1, "seed16v"); // unsigned short [3]
	ADD_PARAM_NAME("seed48_r", 1, "seed16v"); // unsigned short int [3]
	ADD_PARAM_NAME("seed48_r", 2, "buf"); // struct drand48_data *
	ADD_PARAM_NAME("setenv", 1, "name"); // const char *
	ADD_PARAM_NAME("setenv", 2, "value"); // const char *
	ADD_PARAM_NAME("setenv", 3, "overwrite"); // int
	ADD_PARAM_NAME("setstate", 1, "state"); // char *
	ADD_PARAM_NAME("setstate_r", 1, "statebuf"); // char *
	ADD_PARAM_NAME("setstate_r", 2, "buf"); // struct random_data *
	ADD_PARAM_NAME("srand48", 1, "seedval"); // long int
	ADD_PARAM_NAME("srand48_r", 1, "seedval"); // long int
	ADD_PARAM_NAME("srand48_r", 2, "buf"); // struct drand48_data *
	ADD_PARAM_NAME("srandom", 1, "seed"); // unsigned int
	ADD_PARAM_NAME("srandom_r", 1, "seed"); // unsigned int
	ADD_PARAM_NAME("srandom_r", 2, "buf"); // struct random_data *
	ADD_PARAM_NAME("strtoq", 1, "str"); // const char *
	ADD_PARAM_NAME("strtoq", 2, "endptr"); // char * *
	ADD_PARAM_NAME("strtoq", 3, "base"); // int
	ADD_PARAM_NAME("strtouq", 1, "str"); // const char *
	ADD_PARAM_NAME("strtouq", 2, "endptr"); // char * *
	ADD_PARAM_NAME("strtouq", 3, "base"); // int
	ADD_PARAM_NAME("unsetenv", 1, "name"); // const char *
	ADD_PARAM_NAME("valloc", 1, "size"); // size_t
	ADD_PARAM_NAME("wcstombs", 1, "dest"); // char *
	ADD_PARAM_NAME("wcstombs", 2, "src"); // const wchar_t *
	ADD_PARAM_NAME("wcstombs", 3, "n"); // size_t
	ADD_PARAM_NAME("wctomb", 1, "str"); // char *
	ADD_PARAM_NAME("wctomb", 2, "wc"); // wchar_t

	//
	// string.h
	//
	ADD_PARAM_NAME("stpcpy", 1, "str"); // char *
	ADD_PARAM_NAME("stpcpy", 2, "str"); // const char *
	ADD_PARAM_NAME("stpncpy", 1, "str"); // char *
	ADD_PARAM_NAME("stpncpy", 2, "str"); // const char *
	ADD_PARAM_NAME("stpncpy", 3, "n"); // size_t
	ADD_PARAM_NAME("strcoll_l", 1, "str"); // const char *
	ADD_PARAM_NAME("strcoll_l", 2, "str"); // const char *
	ADD_PARAM_NAME("strcoll_l", 3, "locale"); // locale_t
	ADD_PARAM_NAME("strdup", 1, "str"); // const char *
	ADD_PARAM_NAME("strerror_l", 1, "err_num"); // int
	ADD_PARAM_NAME("strerror_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("strerror_r", 1, "err_num"); // int
	ADD_PARAM_NAME("strerror_r", 2, "buf"); // char *
	ADD_PARAM_NAME("strerror_r", 3, "buf_len"); // size_t
	ADD_PARAM_NAME("strndup", 1, "str"); // const char *
	ADD_PARAM_NAME("strndup", 2, "n"); // size_t
	ADD_PARAM_NAME("strnlen", 1, "str"); // const char *
	ADD_PARAM_NAME("strnlen", 2, "max_len"); // size_t
	ADD_PARAM_NAME("strsep", 1, "strp"); // char **
	ADD_PARAM_NAME("strsep", 2, "delim"); // const char *
	ADD_PARAM_NAME("strsignal", 1, "sig_num"); // int
	ADD_PARAM_NAME("strtok_r", 1, "str"); // char *
	ADD_PARAM_NAME("strtok_r", 2, "delim"); // const char *
	ADD_PARAM_NAME("strtok_r", 3, "saveptr"); // char **
	ADD_PARAM_NAME("strxfrm_l", 1, "str"); // char * restrict
	ADD_PARAM_NAME("strxfrm_l", 2, "str"); // const char * restrict
	ADD_PARAM_NAME("strxfrm_l", 3, "n"); // size_t
	ADD_PARAM_NAME("strxfrm_l", 4, "locale"); // locale_t

	//
	// strings.h
	//
	ADD_PARAM_NAME("bcmp", 1, "data"); // const void *
	ADD_PARAM_NAME("bcmp", 2, "data"); // const void *
	ADD_PARAM_NAME("bcmp", 3, "n"); // size_t
	ADD_PARAM_NAME("bcopy", 1, "str"); // const void *
	ADD_PARAM_NAME("bcopy", 2, "data"); // void *
	ADD_PARAM_NAME("bcopy", 3, "n"); // size_t
	ADD_PARAM_NAME("ffs", 1, "i"); // int
	ADD_PARAM_NAME("index", 1, "str"); // const char *
	ADD_PARAM_NAME("index", 2, "c"); // int
	ADD_PARAM_NAME("rindex", 1, "str"); // const char *
	ADD_PARAM_NAME("rindex", 2, "c"); // int
	ADD_PARAM_NAME("strcasecmp", 1, "str"); // const char *
	ADD_PARAM_NAME("strcasecmp", 2, "str"); // const char *
	ADD_PARAM_NAME("strncasecmp", 1, "str"); // const char *
	ADD_PARAM_NAME("strncasecmp", 2, "str"); // const char *
	ADD_PARAM_NAME("strncasecmp", 3, "n"); // size_t

	//
	// stropts.h
	//
	ADD_PARAM_NAME("fattach", 1, "fd"); // int
	ADD_PARAM_NAME("fattach", 2, "path"); // const char *
	ADD_PARAM_NAME("fdetach", 1, "path"); // const char *
	ADD_PARAM_NAME("getmsg", 1, "fd"); // int
	ADD_PARAM_NAME("getmsg", 2, "ctlptr"); // struct strbuf * restrict
	ADD_PARAM_NAME("getmsg", 3, "dataptr"); // struct strbuf * restrict
	ADD_PARAM_NAME("getmsg", 4, "flagsp"); // int * restrict
	ADD_PARAM_NAME("getpmsg", 1, "fd"); // int
	ADD_PARAM_NAME("getpmsg", 2, "ctlptr"); // struct strbuf * restrict
	ADD_PARAM_NAME("getpmsg", 3, "dataptr"); // struct strbuf * restrict
	ADD_PARAM_NAME("getpmsg", 4, "bandp"); // int * restrict
	ADD_PARAM_NAME("getpmsg", 5, "flagsp"); // int * restrict
	ADD_PARAM_NAME("ioctl", 1, "fd"); // int
	ADD_PARAM_NAME("ioctl", 2, "request"); // int
	ADD_PARAM_NAME("isastream", 1, "fd"); // int
	ADD_PARAM_NAME("putmsg", 1, "fd"); // int
	ADD_PARAM_NAME("putmsg", 2, "ctlptr"); // const struct strbuf *
	ADD_PARAM_NAME("putmsg", 3, "dataptr"); // const struct strbuf *
	ADD_PARAM_NAME("putmsg", 4, "flags"); // int
	ADD_PARAM_NAME("putpmsg", 1, "fd"); // int
	ADD_PARAM_NAME("putpmsg", 2, "ctlptr"); // const struct strbuf *
	ADD_PARAM_NAME("putpmsg", 3, "dataptr"); // const struct strbuf *
	ADD_PARAM_NAME("putpmsg", 4, "band"); // int
	ADD_PARAM_NAME("putpmsg", 5, "flags"); // int

	//
	// sys/file.h
	//
	ADD_PARAM_NAME("flock", 1, "fd"); // int
	ADD_PARAM_NAME("flock", 2, "operation"); // int

	//
	// sys/mman.h
	//
	ADD_PARAM_NAME("mlock", 1, "addr"); // const void *
	ADD_PARAM_NAME("mlock", 2, "length"); // size_t
	ADD_PARAM_NAME("mlockall", 1, "flags"); // int
	ADD_PARAM_NAME("munlock", 1, "addr"); // const void *
	ADD_PARAM_NAME("munlock", 2, "length"); // size_t
	ADD_PARAM_NAME("shm_open", 1, "name"); // const char *
	ADD_PARAM_NAME("shm_open", 2, "oflag"); // int
	ADD_PARAM_NAME("shm_open", 3, "mode"); // mode_t
	ADD_PARAM_NAME("shm_unlink", 1, "name"); // const char *

	//
	// sys/msg.h
	//
	ADD_PARAM_NAME("msgctl", 1, "msqid"); // int
	ADD_PARAM_NAME("msgctl", 2, "cmd"); // int
	ADD_PARAM_NAME("msgctl", 3, "buf"); // struct msqid_ds *
	ADD_PARAM_NAME("msgget", 1, "key"); // key_t
	ADD_PARAM_NAME("msgget", 2, "msgflg"); // int
	ADD_PARAM_NAME("msgrcv", 1, "msqid"); // int
	ADD_PARAM_NAME("msgrcv", 2, "msgp"); // void *
	ADD_PARAM_NAME("msgrcv", 3, "msgsz"); // size_t
	ADD_PARAM_NAME("msgrcv", 4, "msgtyp"); // long
	ADD_PARAM_NAME("msgrcv", 5, "msgflg"); // int
	ADD_PARAM_NAME("msgsnd", 1, "msqid"); // int
	ADD_PARAM_NAME("msgsnd", 2, "msgp"); // const void *
	ADD_PARAM_NAME("msgsnd", 3, "msgsz"); // size_t
	ADD_PARAM_NAME("msgsnd", 4, "msgflg"); // int

	//
	// sys/prctl.h
	//
	ADD_PARAM_NAME("prctl", 1, "option"); // int
	// ADD_PARAM_NAME("prctl", 2, "arg2"); // unsigned long
	// ADD_PARAM_NAME("prctl", 3, "arg3"); // unsigned long
	// ADD_PARAM_NAME("prctl", 4, "arg4"); // unsigned long
	// ADD_PARAM_NAME("prctl", 5, "arg5"); // unsigned long

	//
	// sys/resource.h
	//
	ADD_PARAM_NAME("getpriority", 1, "which"); // int
	ADD_PARAM_NAME("getpriority", 2, "who"); // id_t
	ADD_PARAM_NAME("getrlimit", 1, "resource"); // int
	ADD_PARAM_NAME("getrlimit", 2, "rlp"); // struct rlimit *
	ADD_PARAM_NAME("getrusage", 1, "who"); // int
	ADD_PARAM_NAME("getrusage", 2, "r_usage"); // struct rusage *
	ADD_PARAM_NAME("setpriority", 1, "which"); // int
	ADD_PARAM_NAME("setpriority", 2, "who"); // id_t
	ADD_PARAM_NAME("setpriority", 3, "nice"); // int
	ADD_PARAM_NAME("setrlimit", 1, "resource"); // int
	ADD_PARAM_NAME("setrlimit", 2, "rlp"); // const struct rlimit *

	//
	// sys/select.h
	//
	ADD_PARAM_NAME("pselect", 1, "nfds"); // int
	ADD_PARAM_NAME("pselect", 2, "readfds"); // fd_set * restrict
	ADD_PARAM_NAME("pselect", 3, "writefds"); // fd_set * restrict
	ADD_PARAM_NAME("pselect", 4, "errorfds"); // fd_set * restrict
	ADD_PARAM_NAME("pselect", 5, "timeout"); // const struct timespec * restrict
	ADD_PARAM_NAME("pselect", 6, "sigmask"); // const sigset_t * restrict
	ADD_PARAM_NAME("select", 1, "nfds"); // int
	ADD_PARAM_NAME("select", 2, "readfds"); // fd_set * restrict
	ADD_PARAM_NAME("select", 3, "writefds"); // fd_set * restrict
	ADD_PARAM_NAME("select", 4, "errorfds"); // fd_set * restrict
	ADD_PARAM_NAME("select", 5, "timeout"); // struct timeval * restrict

	//
	// sys/sem.h
	//
	ADD_PARAM_NAME("semctl", 1, "semid"); // int
	ADD_PARAM_NAME("semctl", 2, "semnum"); // int
	ADD_PARAM_NAME("semctl", 3, "cmd"); // int
	ADD_PARAM_NAME("semget", 1, "key"); // key_t
	ADD_PARAM_NAME("semget", 2, "nsems"); // int
	ADD_PARAM_NAME("semget", 3, "semflg"); // int
	ADD_PARAM_NAME("semop", 1, "semid"); // int
	ADD_PARAM_NAME("semop", 2, "sops"); // struct sembuf *
	ADD_PARAM_NAME("semop", 3, "nsops"); // size_t

	//
	// sys/shm.h
	//
	ADD_PARAM_NAME("shmat", 1, "shmid"); // int
	ADD_PARAM_NAME("shmat", 2, "shmaddr"); // const void *
	ADD_PARAM_NAME("shmat", 3, "shmflg"); // int
	ADD_PARAM_NAME("shmctl", 1, "shmid"); // int
	ADD_PARAM_NAME("shmctl", 2, "cmd"); // int
	ADD_PARAM_NAME("shmctl", 3, "buf"); // struct shmid_ds *
	ADD_PARAM_NAME("shmdt", 1, "shmaddr"); // const void *
	ADD_PARAM_NAME("shmget", 1, "key"); // key_t
	ADD_PARAM_NAME("shmget", 2, "size"); // size_t
	ADD_PARAM_NAME("shmget", 3, "shmflg"); // int

	//
	// sys/socket.h
	//
	ADD_PARAM_NAME("accept", 1, "sock"); // int
	ADD_PARAM_NAME("accept", 2, "addr"); // struct sockaddr * restrict
	ADD_PARAM_NAME("accept", 3, "addr_len"); // socklen_t * restrict
	ADD_PARAM_NAME("bind", 1, "sock"); // int
	ADD_PARAM_NAME("bind", 2, "addr"); // const struct sockaddr *
	ADD_PARAM_NAME("bind", 3, "addr_len"); // socklen_t
	ADD_PARAM_NAME("connect", 1, "sock"); // int
	ADD_PARAM_NAME("connect", 2, "addr"); // const struct sockaddr *
	ADD_PARAM_NAME("connect", 3, "addr_len"); // socklen_t
	ADD_PARAM_NAME("getnameinfo", 1, "sa"); // const struct sockaddr *
	ADD_PARAM_NAME("getnameinfo", 2, "salen"); // socklen_t
	ADD_PARAM_NAME("getnameinfo", 3, "host"); // char *
	ADD_PARAM_NAME("getnameinfo", 4, "hostlen"); // size_t
	ADD_PARAM_NAME("getnameinfo", 5, "serv"); // char *
	ADD_PARAM_NAME("getnameinfo", 6, "servlen"); // size_t
	ADD_PARAM_NAME("getnameinfo", 7, "flags"); // int
	ADD_PARAM_NAME("getpeername", 1, "sock"); // int
	ADD_PARAM_NAME("getpeername", 2, "addr"); // struct sockaddr * restrict
	ADD_PARAM_NAME("getpeername", 3, "addr_len"); // socklen_t * restrict
	ADD_PARAM_NAME("getsockname", 1, "sock"); // int
	ADD_PARAM_NAME("getsockname", 2, "addr"); // struct sockaddr * restrict
	ADD_PARAM_NAME("getsockname", 3, "addr_len"); // socklen_t * restrict
	ADD_PARAM_NAME("getsockopt", 1, "sock"); // int
	ADD_PARAM_NAME("getsockopt", 2, "level"); // int
	ADD_PARAM_NAME("getsockopt", 3, "option_name"); // int
	ADD_PARAM_NAME("getsockopt", 4, "option_value"); // void * restrict
	ADD_PARAM_NAME("getsockopt", 5, "option_len"); // socklen_t * restrict
	ADD_PARAM_NAME("inet_addr", 1, "cp"); // const char *
	ADD_PARAM_NAME("inet_aton", 1, "cp"); // const char *
	ADD_PARAM_NAME("inet_aton", 2, "inp"); // struct in_addr *
	ADD_PARAM_NAME("inet_lnaof", 1, "in"); // struct in_addr
	ADD_PARAM_NAME("inet_makeaddr", 1, "net"); // int
	ADD_PARAM_NAME("inet_makeaddr", 2, "host"); // int
	ADD_PARAM_NAME("inet_netof", 1, "in"); // struct in_addr
	ADD_PARAM_NAME("inet_network", 1, "cp"); // const char *
	ADD_PARAM_NAME("inet_ntoa", 1, "in"); // struct in_addr
	ADD_PARAM_NAME("listen", 1, "sock"); // int
	ADD_PARAM_NAME("listen", 2, "backlog"); // int
	ADD_PARAM_NAME("recv", 1, "sock"); // int
	ADD_PARAM_NAME("recv", 2, "buf"); // void *
	ADD_PARAM_NAME("recv", 3, "length"); // size_t
	ADD_PARAM_NAME("recv", 4, "flags"); // int
	ADD_PARAM_NAME("recvfrom", 1, "sock"); // int
	ADD_PARAM_NAME("recvfrom", 2, "buf"); // void * restrict
	ADD_PARAM_NAME("recvfrom", 3, "length"); // size_t
	ADD_PARAM_NAME("recvfrom", 4, "flags"); // int
	ADD_PARAM_NAME("recvfrom", 5, "addr"); // struct sockaddr * restrict
	ADD_PARAM_NAME("recvfrom", 6, "addr_len"); // socklen_t * restrict
	ADD_PARAM_NAME("recvmsg", 1, "sock"); // int
	ADD_PARAM_NAME("recvmsg", 2, "message"); // struct msghdr *
	ADD_PARAM_NAME("recvmsg", 3, "flags"); // int
	ADD_PARAM_NAME("send", 1, "sock"); // int
	ADD_PARAM_NAME("send", 2, "buf"); // const void *
	ADD_PARAM_NAME("send", 3, "length"); // size_t
	ADD_PARAM_NAME("send", 4, "flags"); // int
	ADD_PARAM_NAME("sendmsg", 1, "sock"); // int
	ADD_PARAM_NAME("sendmsg", 2, "message"); // const struct msghdr *
	ADD_PARAM_NAME("sendmsg", 3, "flags"); // int
	ADD_PARAM_NAME("sendto", 1, "sock"); // int
	ADD_PARAM_NAME("sendto", 2, "message"); // const void *
	ADD_PARAM_NAME("sendto", 3, "length"); // size_t
	ADD_PARAM_NAME("sendto", 4, "flags"); // int
	ADD_PARAM_NAME("sendto", 5, "dest_addr"); // const struct sockaddr *
	ADD_PARAM_NAME("sendto", 6, "dest_len"); // socklen_t
	ADD_PARAM_NAME("setsockopt", 1, "sock"); // int
	ADD_PARAM_NAME("setsockopt", 2, "level"); // int
	ADD_PARAM_NAME("setsockopt", 3, "option_name"); // int
	ADD_PARAM_NAME("setsockopt", 4, "option_value"); // const void *
	ADD_PARAM_NAME("setsockopt", 5, "option_len"); // socklen_t
	ADD_PARAM_NAME("shutdown", 1, "sock"); // int
	ADD_PARAM_NAME("shutdown", 2, "how"); // int
	ADD_PARAM_NAME("sockatmark", 1, "sock"); // int
	ADD_PARAM_NAME("socket", 1, "domain"); // int
	ADD_PARAM_NAME("socket", 2, "type"); // int
	ADD_PARAM_NAME("socket", 3, "protocol"); // int
	ADD_PARAM_NAME("socketpair", 1, "domain"); // int
	ADD_PARAM_NAME("socketpair", 2, "type"); // int
	ADD_PARAM_NAME("socketpair", 3, "protocol"); // int
	ADD_PARAM_NAME("socketpair", 4, "socket_vector"); // int [2]

	//
	// sys/stat.h
	//
	ADD_PARAM_NAME("chmod", 1, "path"); // const char *
	ADD_PARAM_NAME("chmod", 2, "mode"); // mode_t
	ADD_PARAM_NAME("creat", 1, "path"); // const char *
	ADD_PARAM_NAME("creat", 2, "mode"); // mode_t
	ADD_PARAM_NAME("fchmod", 1, "fd"); // int
	ADD_PARAM_NAME("fchmod", 2, "mode"); // mode_t
	ADD_PARAM_NAME("fchmodat", 1, "fd"); // int
	ADD_PARAM_NAME("fchmodat", 2, "path"); // const char *
	ADD_PARAM_NAME("fchmodat", 3, "mode"); // mode_t
	ADD_PARAM_NAME("fchmodat", 4, "flag"); // int
	ADD_PARAM_NAME("fstat", 1, "fd"); // int
	ADD_PARAM_NAME("fstat", 2, "buf"); // struct stat *
	ADD_PARAM_NAME("fstatat", 1, "fd"); // int
	ADD_PARAM_NAME("fstatat", 2, "path"); // const char * restrict
	ADD_PARAM_NAME("fstatat", 3, "buf"); // struct stat * restrict
	ADD_PARAM_NAME("fstatat", 4, "flag"); // int
	ADD_PARAM_NAME("isfdtype", 1, "filedes"); // int
	ADD_PARAM_NAME("isfdtype", 2, "fdtype"); // int
	ADD_PARAM_NAME("lchmod", 1, "path"); // const char *
	ADD_PARAM_NAME("lchmod", 2, "mode"); // mode_t
	ADD_PARAM_NAME("lstat", 1, "path"); // const char * restrict
	ADD_PARAM_NAME("lstat", 2, "buf"); // struct stat * restrict
	ADD_PARAM_NAME("mkdir", 1, "path"); // const char *
	ADD_PARAM_NAME("mkdir", 2, "mode"); // mode_t
	ADD_PARAM_NAME("mkdirat", 1, "fd"); // int
	ADD_PARAM_NAME("mkdirat", 2, "path"); // const char *
	ADD_PARAM_NAME("mkdirat", 3, "mode"); // mode_t
	ADD_PARAM_NAME("mknod", 1, "path"); // const char *
	ADD_PARAM_NAME("mknod", 2, "mode"); // mode_t
	ADD_PARAM_NAME("mknod", 3, "dev"); // dev_t
	ADD_PARAM_NAME("mknodat", 1, "fd"); // int
	ADD_PARAM_NAME("mknodat", 2, "path"); // const char *
	ADD_PARAM_NAME("mknodat", 3, "mode"); // mode_t
	ADD_PARAM_NAME("mknodat", 4, "dev"); // dev_t
	ADD_PARAM_NAME("open", 1, "path"); // const char *
	ADD_PARAM_NAME("open", 2, "oflag"); // int
	ADD_PARAM_NAME("stat", 1, "path"); // const char * restrict
	ADD_PARAM_NAME("stat", 2, "buf"); // struct stat * restrict
	ADD_PARAM_NAME("umask", 1, "cmask"); // mode_t
	ADD_PARAM_NAME("utimensat", 1, "fd"); // int
	ADD_PARAM_NAME("utimensat", 2, "path"); // const char *
	ADD_PARAM_NAME("utimensat", 3, "times"); // const struct timespec [2]
	ADD_PARAM_NAME("utimensat", 4, "flag"); // int
	ADD_PARAM_NAME("utimes", 1, "path"); // const char *
	ADD_PARAM_NAME("utimes", 2, "times"); // const struct timeval [2]

	//
	// sys/statvfs.h
	//
	ADD_PARAM_NAME("fstatvfs", 1, "fd"); // int
	ADD_PARAM_NAME("fstatvfs", 2, "buf"); // struct statvfs *
	ADD_PARAM_NAME("statvfs", 1, "path"); // const char *
	ADD_PARAM_NAME("statvfs", 2, "buf"); // struct statvfs *

	//
	// sys/time.h
	//
	ADD_PARAM_NAME("adjtime", 1, "delta"); // const struct timeval *
	ADD_PARAM_NAME("adjtime", 2, "delta"); // struct timeval *
	ADD_PARAM_NAME("futimes", 1, "fd"); // int
	ADD_PARAM_NAME("futimes", 2, "tv"); // const struct timeval [2]
	ADD_PARAM_NAME("getitimer", 1, "which"); // int
	ADD_PARAM_NAME("getitimer", 2, "value"); // struct itimerval *
	ADD_PARAM_NAME("gettimeofday", 1, "tp"); // struct timeval * restrict
	ADD_PARAM_NAME("gettimeofday", 2, "tzp"); // void * restrict
	ADD_PARAM_NAME("lutimes", 1, "file_name"); // const char *
	ADD_PARAM_NAME("lutimes", 2, "tv"); // const struct timeval [2]
	ADD_PARAM_NAME("setitimer", 1, "which"); // int
	ADD_PARAM_NAME("setitimer", 2, "value"); // const struct itimerval * restrict
	ADD_PARAM_NAME("setitimer", 3, "ovalue"); // struct itimerval * restrict
	ADD_PARAM_NAME("settimeofday", 1, "tv"); // const struct timeval *
	ADD_PARAM_NAME("settimeofday", 2, "tz"); // const struct timezone *

	//
	// sys/times.h
	//
	ADD_PARAM_NAME("times", 1, "buf"); // struct tms *

	//
	// sys/types.h
	//
	ADD_PARAM_NAME("bindresvport", 1, "sock"); // int
	ADD_PARAM_NAME("bindresvport", 2, "sin"); // struct sockaddr_in *
	ADD_PARAM_NAME("closedir", 1, "dirp"); // DIR *
	ADD_PARAM_NAME("dirfd", 1, "dirp"); // DIR *
	ADD_PARAM_NAME("fdopendir", 1, "fd"); // int
	ADD_PARAM_NAME("freeaddrinfo", 1, "addr_info"); // struct addrinfo *
	ADD_PARAM_NAME("ftok", 1, "pathname"); // const char *
	ADD_PARAM_NAME("ftok", 2, "proj_id"); // int
	ADD_PARAM_NAME("gai_strerror", 1, "errcode"); // int
	ADD_PARAM_NAME("getaddrinfo", 1, "node"); // const char *
	ADD_PARAM_NAME("getaddrinfo", 2, "service"); // const char *
	ADD_PARAM_NAME("getaddrinfo", 3, "hints"); // const struct addrinfo *
	ADD_PARAM_NAME("getaddrinfo", 4, "addr_info"); // struct addrinfo **
	ADD_PARAM_NAME("getgrgid", 1, "gid"); // gid_t
	ADD_PARAM_NAME("getgrgid_r", 1, "gid"); // gid_t
	ADD_PARAM_NAME("getgrgid_r", 2, "grp"); // struct group *
	ADD_PARAM_NAME("getgrgid_r", 3, "buf"); // char *
	ADD_PARAM_NAME("getgrgid_r", 4, "buf_len"); // size_t
	ADD_PARAM_NAME("getgrgid_r", 5, "grp"); // struct group **
	ADD_PARAM_NAME("getgrnam", 1, "name"); // const char *
	ADD_PARAM_NAME("getgrnam_r", 1, "name"); // const char *
	ADD_PARAM_NAME("getgrnam_r", 2, "grp"); // struct group *
	ADD_PARAM_NAME("getgrnam_r", 3, "buf"); // char *
	ADD_PARAM_NAME("getgrnam_r", 4, "buf_len"); // size_t
	ADD_PARAM_NAME("getgrnam_r", 5, "grp"); // struct group **
	ADD_PARAM_NAME("getpwnam", 1, "name"); // const char *
	ADD_PARAM_NAME("getpwnam_r", 1, "name"); // const char *
	ADD_PARAM_NAME("getpwnam_r", 2, "passwd"); // struct passwd *
	ADD_PARAM_NAME("getpwnam_r", 3, "buf"); // char *
	ADD_PARAM_NAME("getpwnam_r", 4, "buf_len"); // size_t
	ADD_PARAM_NAME("getpwnam_r", 5, "passwd"); // struct passwd **
	ADD_PARAM_NAME("getpwuid", 1, "uid"); // uid_t
	ADD_PARAM_NAME("getpwuid_r", 1, "uid"); // uid_t
	ADD_PARAM_NAME("getpwuid_r", 2, "passwd"); // struct passwd *
	ADD_PARAM_NAME("getpwuid_r", 3, "buf"); // char *
	ADD_PARAM_NAME("getpwuid_r", 4, "buf_len"); // size_t
	ADD_PARAM_NAME("getpwuid_r", 5, "passwd"); // struct passwd **
	ADD_PARAM_NAME("initgroups", 1, "user"); // const char *
	ADD_PARAM_NAME("initgroups", 2, "group"); // gid_t
	ADD_PARAM_NAME("mkfifo", 1, "pathname"); // const char *
	ADD_PARAM_NAME("mkfifo", 2, "mode"); // mode_t
	ADD_PARAM_NAME("mkfifoat", 1, "dirfd"); // int
	ADD_PARAM_NAME("mkfifoat", 2, "pathname"); // const char *
	ADD_PARAM_NAME("mkfifoat", 3, "mode"); // mode_t
	ADD_PARAM_NAME("opendir", 1, "name"); // const char *
	ADD_PARAM_NAME("regcomp", 1, "preg"); // regex_t *
	ADD_PARAM_NAME("regcomp", 2, "regex"); // const char *
	ADD_PARAM_NAME("regcomp", 3, "cflags"); // int
	ADD_PARAM_NAME("regerror", 1, "errcode"); // int
	ADD_PARAM_NAME("regerror", 2, "preg"); // const regex_t *
	ADD_PARAM_NAME("regerror", 3, "errbuf"); // char *
	ADD_PARAM_NAME("regerror", 4, "errbuf_size"); // size_t
	ADD_PARAM_NAME("regexec", 1, "preg"); // const regex_t *
	ADD_PARAM_NAME("regexec", 2, "str"); // const char *
	ADD_PARAM_NAME("regexec", 3, "nmatch"); // size_t
	ADD_PARAM_NAME("regexec", 4, "pmatch"); // regmatch_t []
	ADD_PARAM_NAME("regexec", 5, "eflags"); // int
	ADD_PARAM_NAME("regfree", 1, "preg"); // regex_t *
	ADD_PARAM_NAME("rewinddir", 1, "dirp"); // DIR *
	ADD_PARAM_NAME("setgroups", 1, "size"); // size_t
	ADD_PARAM_NAME("setgroups", 2, "list"); // const gid_t *
	ADD_PARAM_NAME("wait3", 1, "status"); // int *
	ADD_PARAM_NAME("wait3", 2, "options"); // int
	ADD_PARAM_NAME("wait3", 3, "rusage"); // struct rusage *
	ADD_PARAM_NAME("wait4", 1, "pid"); // pid_t
	ADD_PARAM_NAME("wait4", 2, "status"); // int *
	ADD_PARAM_NAME("wait4", 3, "options"); // int
	ADD_PARAM_NAME("wait4", 4, "rusage"); // struct rusage *

	//
	// sys/uio.h
	//
	ADD_PARAM_NAME("preadv", 1, "fd"); // int
	ADD_PARAM_NAME("preadv", 2, "iov"); // const struct iovec *
	ADD_PARAM_NAME("preadv", 3, "iovcnt"); // int
	ADD_PARAM_NAME("preadv", 4, "offset"); // off_t
	ADD_PARAM_NAME("pwritev", 1, "fd"); // int
	ADD_PARAM_NAME("pwritev", 2, "iov"); // const struct iovec *
	ADD_PARAM_NAME("pwritev", 3, "iovcnt"); // int
	ADD_PARAM_NAME("pwritev", 4, "offset"); // off_t
	ADD_PARAM_NAME("readv", 1, "fd"); // int
	ADD_PARAM_NAME("readv", 2, "iov"); // const struct iovec *
	ADD_PARAM_NAME("readv", 3, "iovcnt"); // int
	ADD_PARAM_NAME("writev", 1, "fd"); // int
	ADD_PARAM_NAME("writev", 2, "iov"); // const struct iovec *
	ADD_PARAM_NAME("writev", 3, "iovcnt"); // int

	//
	// sys/utsname.h
	//
	ADD_PARAM_NAME("uname", 1, "name"); // struct utsname *

	//
	// sys/wait.h
	//
	ADD_PARAM_NAME("wait", 1, "stat_loc"); // int *
	ADD_PARAM_NAME("waitid", 1, "idtype"); // idtype_t
	ADD_PARAM_NAME("waitid", 2, "id"); // id_t
	ADD_PARAM_NAME("waitid", 3, "infop"); // siginfo_t *
	ADD_PARAM_NAME("waitid", 4, "options"); // int
	ADD_PARAM_NAME("waitpid", 1, "pid"); // pid_t
	ADD_PARAM_NAME("waitpid", 2, "stat_loc"); // int *
	ADD_PARAM_NAME("waitpid", 3, "options"); // int

	//
	// syslog.h
	//
	ADD_PARAM_NAME("openlog", 1, "ident"); // const char *
	ADD_PARAM_NAME("openlog", 2, "option"); // int
	ADD_PARAM_NAME("openlog", 3, "facility"); // int
	ADD_PARAM_NAME("setlogmask", 1, "mask"); // int
	ADD_PARAM_NAME("syslog", 1, "priority"); // int
	ADD_PARAM_NAME("syslog", 2, "format"); // const char *
	ADD_PARAM_NAME("vsyslog", 1, "priority"); // int
	ADD_PARAM_NAME("vsyslog", 2, "format"); // const char *
	ADD_PARAM_NAME("vsyslog", 3, "ap"); // va_list

	//
	// termios.h
	//
	ADD_PARAM_NAME("cfgetispeed", 1, "termios_p"); // const struct termios *
	ADD_PARAM_NAME("cfgetospeed", 1, "termios_p"); // const struct termios *
	ADD_PARAM_NAME("cfmakeraw", 1, "termios_p"); // struct termios *
	ADD_PARAM_NAME("cfsetispeed", 1, "termios_p"); // struct termios *
	ADD_PARAM_NAME("cfsetispeed", 2, "speed"); // speed_t
	ADD_PARAM_NAME("cfsetospeed", 1, "termios_p"); // struct termios *
	ADD_PARAM_NAME("cfsetospeed", 2, "speed"); // speed_t
	ADD_PARAM_NAME("cfsetspeed", 1, "termios_p"); // struct termios *
	ADD_PARAM_NAME("cfsetspeed", 2, "speed"); // speed_t
	ADD_PARAM_NAME("tcdrain", 1, "fd"); // int
	ADD_PARAM_NAME("tcflow", 1, "fd"); // int
	ADD_PARAM_NAME("tcflow", 2, "action"); // int
	ADD_PARAM_NAME("tcflush", 1, "fd"); // int
	ADD_PARAM_NAME("tcflush", 2, "queue_selector"); // int
	ADD_PARAM_NAME("tcgetattr", 1, "fd"); // int
	ADD_PARAM_NAME("tcgetattr", 2, "termios_p"); // struct termios *
	ADD_PARAM_NAME("tcgetsid", 1, "fd"); // int
	ADD_PARAM_NAME("tcsendbreak", 1, "fd"); // int
	ADD_PARAM_NAME("tcsendbreak", 2, "duration"); // int
	ADD_PARAM_NAME("tcsetattr", 1, "fd"); // int
	ADD_PARAM_NAME("tcsetattr", 2, "optional_actions"); // int
	ADD_PARAM_NAME("tcsetattr", 3, "termios_p"); // const struct termios *

	//
	// time.h
	//
	ADD_PARAM_NAME("asctime_r", 1, "tm"); // const struct tm *
	ADD_PARAM_NAME("asctime_r", 2, "buf"); // char *
	ADD_PARAM_NAME("clock_getcpuclockid", 1, "pid"); // pid_t
	ADD_PARAM_NAME("clock_getcpuclockid", 2, "clock_id"); // clockid_t *
	ADD_PARAM_NAME("clock_getres", 1, "clk_id"); // clockid_t
	ADD_PARAM_NAME("clock_getres", 2, "res"); // struct timespec *
	ADD_PARAM_NAME("clock_gettime", 1, "clk_id"); // clockid_t
	ADD_PARAM_NAME("clock_gettime", 2, "tp"); // struct timespec *
	ADD_PARAM_NAME("clock_nanosleep", 1, "clock_id"); // clockid_t
	ADD_PARAM_NAME("clock_nanosleep", 2, "flags"); // int
	ADD_PARAM_NAME("clock_nanosleep", 3, "rqtp"); // const struct timespec *
	ADD_PARAM_NAME("clock_nanosleep", 4, "rmtp"); // struct timespec *
	ADD_PARAM_NAME("clock_settime", 1, "clk_id"); // clockid_t
	ADD_PARAM_NAME("clock_settime", 2, "tp"); // const struct timespec *
	ADD_PARAM_NAME("ctime_r", 1, "timep"); // const time_t *
	ADD_PARAM_NAME("ctime_r", 2, "buf"); // char *
	ADD_PARAM_NAME("dysize", 1, "year"); // int
	ADD_PARAM_NAME("gmtime_r", 1, "timep"); // const time_t *
	ADD_PARAM_NAME("gmtime_r", 2, "time"); // struct tm *
	ADD_PARAM_NAME("localtime_r", 1, "timep"); // const time_t *
	ADD_PARAM_NAME("localtime_r", 2, "time"); // struct tm *
	ADD_PARAM_NAME("nanosleep", 1, "rqtp"); // const struct timespec *
	ADD_PARAM_NAME("nanosleep", 2, "rmtp"); // struct timespec *
	ADD_PARAM_NAME("stime", 1, "t"); // time_t *
	ADD_PARAM_NAME("strftime_l", 1, "str"); // char * restrict
	ADD_PARAM_NAME("strftime_l", 2, "max_size"); // size_t
	ADD_PARAM_NAME("strftime_l", 3, "format"); // const char * restrict
	ADD_PARAM_NAME("strftime_l", 4, "timeptr"); // const struct tm * restrict
	ADD_PARAM_NAME("strftime_l", 5, "locale"); // locale_t
	ADD_PARAM_NAME("timegm", 1, "tm"); // struct tm *
	ADD_PARAM_NAME("timelocal", 1, "tm"); // struct tm *
	ADD_PARAM_NAME("timer_delete", 1, "timerid"); // timer_t
	ADD_PARAM_NAME("timer_getoverrun", 1, "timerid"); // timer_t
	ADD_PARAM_NAME("timer_gettime", 1, "timerid"); // timer_t
	ADD_PARAM_NAME("timer_gettime", 2, "value"); // struct itimerspec *
	ADD_PARAM_NAME("timer_settime", 1, "timerid"); // timer_t
	ADD_PARAM_NAME("timer_settime", 2, "flags"); // int
	ADD_PARAM_NAME("timer_settime", 3, "value"); // const struct itimerspec * restrict
	ADD_PARAM_NAME("timer_settime", 4, "ovalue"); // struct itimerspec * restrict

	//
	// ulimit.h
	//
	ADD_PARAM_NAME("ulimit", 1, "cmd"); // int
	ADD_PARAM_NAME("ulimit", 2, "limit"); // long

	//
	// unistd.h
	//
	ADD_PARAM_NAME("access", 1, "path"); // const char *
	ADD_PARAM_NAME("access", 2, "amode"); // int
	ADD_PARAM_NAME("acct", 1, "file_name"); // const char *
	ADD_PARAM_NAME("alarm", 1, "seconds"); // unsigned
	ADD_PARAM_NAME("chdir", 1, "path"); // const char *
	ADD_PARAM_NAME("chown", 1, "path"); // const char *
	ADD_PARAM_NAME("chown", 2, "owner"); // uid_t
	ADD_PARAM_NAME("chown", 3, "group"); // gid_t
	ADD_PARAM_NAME("chroot", 1, "path"); // const char *
	ADD_PARAM_NAME("close", 1, "fd"); // int
	ADD_PARAM_NAME("confstr", 1, "name"); // int
	ADD_PARAM_NAME("confstr", 2, "buf"); // char *
	ADD_PARAM_NAME("confstr", 3, "length"); // size_t
	ADD_PARAM_NAME("daemon", 1, "nochdir"); // int
	ADD_PARAM_NAME("daemon", 2, "noclose"); // int
	ADD_PARAM_NAME("dup", 1, "fd"); // int
	ADD_PARAM_NAME("dup2", 1, "fd"); // int
	ADD_PARAM_NAME("dup2", 2, "fd"); // int
	ADD_PARAM_NAME("execl", 1, "path"); // const char *
	ADD_PARAM_NAME("execl", 2, "exec_arg"); // const char *
	ADD_PARAM_NAME("execle", 1, "path"); // const char *
	ADD_PARAM_NAME("execle", 2, "exec_arg"); // const char *
	ADD_PARAM_NAME("execlp", 1, "file"); // const char *
	ADD_PARAM_NAME("execlp", 2, "exec_arg"); // const char *
	ADD_PARAM_NAME("execv", 1, "path"); // const char *
	ADD_PARAM_NAME("execv", 2, "exec_argv"); // char * const []
	ADD_PARAM_NAME("execve", 1, "path"); // const char *
	ADD_PARAM_NAME("execve", 2, "exec_argv"); // char * const []
	ADD_PARAM_NAME("execve", 3, "envp"); // char * const []
	ADD_PARAM_NAME("execvp", 1, "file"); // const char *
	ADD_PARAM_NAME("execvp", 2, "exec_argv"); // char * const []
	ADD_PARAM_NAME("faccessat", 1, "fd"); // int
	ADD_PARAM_NAME("faccessat", 2, "path"); // const char *
	ADD_PARAM_NAME("faccessat", 3, "amode"); // int
	ADD_PARAM_NAME("faccessat", 4, "flag"); // int
	ADD_PARAM_NAME("fchdir", 1, "fd"); // int
	ADD_PARAM_NAME("fchown", 1, "fd"); // int
	ADD_PARAM_NAME("fchown", 2, "owner"); // uid_t
	ADD_PARAM_NAME("fchown", 3, "group"); // gid_t
	ADD_PARAM_NAME("fchownat", 1, "fd"); // int
	ADD_PARAM_NAME("fchownat", 2, "path"); // const char *
	ADD_PARAM_NAME("fchownat", 3, "owner"); // uid_t
	ADD_PARAM_NAME("fchownat", 4, "group"); // gid_t
	ADD_PARAM_NAME("fchownat", 5, "flag"); // int
	ADD_PARAM_NAME("fdatasync", 1, "fd"); // int
	ADD_PARAM_NAME("fexecve", 1, "fd"); // int
	ADD_PARAM_NAME("fexecve", 2, "exec_argv"); // char * const []
	ADD_PARAM_NAME("fexecve", 3, "envp"); // char * const []
	ADD_PARAM_NAME("fpathconf", 1, "fd"); // int
	ADD_PARAM_NAME("fpathconf", 2, "name"); // int
	ADD_PARAM_NAME("fsync", 1, "fd"); // int
	ADD_PARAM_NAME("ftruncate", 1, "fd"); // int
	ADD_PARAM_NAME("ftruncate", 2, "length"); // off_t
	ADD_PARAM_NAME("getcwd", 1, "buf"); // char *
	ADD_PARAM_NAME("getcwd", 2, "size"); // size_t
	ADD_PARAM_NAME("getdomainname", 1, "name"); // char *
	ADD_PARAM_NAME("getdomainname", 2, "length"); // size_t
	ADD_PARAM_NAME("getgroups", 1, "gidsetsize"); // int
	ADD_PARAM_NAME("getgroups", 2, "grouplist"); // gid_t []
	ADD_PARAM_NAME("gethostname", 1, "name"); // char *
	ADD_PARAM_NAME("gethostname", 2, "namelen"); // size_t
	ADD_PARAM_NAME("getlogin_r", 1, "buf"); // char *
	ADD_PARAM_NAME("getlogin_r", 2, "buf_size"); // size_t
	ADD_PARAM_NAME("getopt", 1, "argc"); // int
	ADD_PARAM_NAME("getopt", 2, "argv"); // char * const []
	ADD_PARAM_NAME("getopt", 3, "optstring"); // const char *
	ADD_PARAM_NAME("getpass", 1, "prompt"); // const char *
	ADD_PARAM_NAME("getpgid", 1, "pid"); // pid_t
	ADD_PARAM_NAME("getsid", 1, "pid"); // pid_t
	ADD_PARAM_NAME("getwd", 1, "buf"); // char *
	ADD_PARAM_NAME("isatty", 1, "fd"); // int
	ADD_PARAM_NAME("lchown", 1, "path"); // const char *
	ADD_PARAM_NAME("lchown", 2, "owner"); // uid_t
	ADD_PARAM_NAME("lchown", 3, "group"); // gid_t
	ADD_PARAM_NAME("link", 1, "path1"); // const char *
	ADD_PARAM_NAME("link", 2, "path2"); // const char *
	ADD_PARAM_NAME("linkat", 1, "fd"); // int
	ADD_PARAM_NAME("linkat", 2, "path1"); // const char *
	ADD_PARAM_NAME("linkat", 3, "fd"); // int
	ADD_PARAM_NAME("linkat", 4, "path2"); // const char *
	ADD_PARAM_NAME("linkat", 5, "flag"); // int
	ADD_PARAM_NAME("lockf", 1, "fd"); // int
	ADD_PARAM_NAME("lockf", 2, "cmd"); // int
	ADD_PARAM_NAME("lockf", 3, "length"); // off_t
	ADD_PARAM_NAME("lseek", 1, "fd"); // int
	ADD_PARAM_NAME("lseek", 2, "offset"); // off_t
	ADD_PARAM_NAME("lseek", 3, "whence"); // int
	ADD_PARAM_NAME("nice", 1, "incr"); // int
	ADD_PARAM_NAME("pathconf", 1, "path"); // char *
	ADD_PARAM_NAME("pathconf", 2, "name"); // int
	ADD_PARAM_NAME("pipe", 1, "fds"); // int [2]
	ADD_PARAM_NAME("pread", 1, "fd"); // int
	ADD_PARAM_NAME("pread", 2, "buf"); // void *
	ADD_PARAM_NAME("pread", 3, "nbyte"); // size_t
	ADD_PARAM_NAME("pread", 4, "offset"); // off_t
	ADD_PARAM_NAME("profil", 1, "buf"); // unsigned short *
	ADD_PARAM_NAME("profil", 2, "bufsiz"); // size_t
	ADD_PARAM_NAME("profil", 3, "offset"); // size_t
	ADD_PARAM_NAME("profil", 4, "scale"); // unsigned int
	ADD_PARAM_NAME("pwrite", 1, "fd"); // int
	ADD_PARAM_NAME("pwrite", 2, "buf"); // const void *
	ADD_PARAM_NAME("pwrite", 3, "nbyte"); // size_t
	ADD_PARAM_NAME("pwrite", 4, "offset"); // off_t
	ADD_PARAM_NAME("read", 1, "fd"); // int
	ADD_PARAM_NAME("read", 2, "buf"); // void *
	ADD_PARAM_NAME("read", 3, "nbyte"); // size_t
	ADD_PARAM_NAME("readlink", 1, "path"); // const char * restrict
	ADD_PARAM_NAME("readlink", 2, "buf"); // char * restrict
	ADD_PARAM_NAME("readlink", 3, "buf_size"); // size_t
	ADD_PARAM_NAME("readlinkat", 1, "fd"); // int
	ADD_PARAM_NAME("readlinkat", 2, "path"); // const char * restrict
	ADD_PARAM_NAME("readlinkat", 3, "buf"); // char * restrict
	ADD_PARAM_NAME("readlinkat", 4, "buf_size"); // size_t
	ADD_PARAM_NAME("revoke", 1, "path"); // const char *
	ADD_PARAM_NAME("rmdir", 1, "path"); // const char *
	ADD_PARAM_NAME("sbrk", 1, "increment"); // intptr_t
	ADD_PARAM_NAME("setdomainname", 1, "name"); // const char *
	ADD_PARAM_NAME("setdomainname", 2, "length"); // size_t
	ADD_PARAM_NAME("setegid", 1, "gid"); // gid_t
	ADD_PARAM_NAME("seteuid", 1, "uid"); // uid_t
	ADD_PARAM_NAME("setgid", 1, "gid"); // gid_t
	ADD_PARAM_NAME("sethostid", 1, "hostid"); // long
	ADD_PARAM_NAME("sethostname", 1, "name"); // const char *
	ADD_PARAM_NAME("sethostname", 2, "length"); // size_t
	ADD_PARAM_NAME("setlogin", 1, "name"); // const char *
	ADD_PARAM_NAME("setpgid", 1, "pid"); // pid_t
	ADD_PARAM_NAME("setpgid", 2, "pgid"); // pid_t
	ADD_PARAM_NAME("setregid", 1, "rgid"); // gid_t
	ADD_PARAM_NAME("setregid", 2, "egid"); // gid_t
	ADD_PARAM_NAME("setreuid", 1, "ruid"); // uid_t
	ADD_PARAM_NAME("setreuid", 2, "euid"); // uid_t
	ADD_PARAM_NAME("setuid", 1, "uid"); // uid_t
	ADD_PARAM_NAME("sleep", 1, "seconds"); // unsigned int
	ADD_PARAM_NAME("symlink", 1, "path1"); // const char *
	ADD_PARAM_NAME("symlink", 2, "path2"); // const char *
	ADD_PARAM_NAME("symlinkat", 1, "path1"); // const char *
	ADD_PARAM_NAME("symlinkat", 2, "fd"); // int
	ADD_PARAM_NAME("symlinkat", 3, "path2"); // const char *
	ADD_PARAM_NAME("syscall", 1, "syscall_number"); // int
	ADD_PARAM_NAME("sysconf", 1, "name"); // int
	ADD_PARAM_NAME("tcgetpgrp", 1, "fd"); // int
	ADD_PARAM_NAME("tcsetpgrp", 1, "fd"); // int
	ADD_PARAM_NAME("tcsetpgrp", 2, "pgrp"); // pid_t
	ADD_PARAM_NAME("truncate", 1, "path"); // const char *
	ADD_PARAM_NAME("truncate", 2, "length"); // off_t
	ADD_PARAM_NAME("ttyname", 1, "fd"); // int
	ADD_PARAM_NAME("ttyname_r", 1, "fd"); // int
	ADD_PARAM_NAME("ttyname_r", 2, "buf"); // char *
	ADD_PARAM_NAME("ttyname_r", 3, "buf_len"); // size_t
	ADD_PARAM_NAME("ualarm", 1, "usecs"); // useconds_t
	ADD_PARAM_NAME("ualarm", 2, "interval"); // useconds_t
	ADD_PARAM_NAME("unlink", 1, "path"); // const char *
	ADD_PARAM_NAME("unlinkat", 1, "fd"); // int
	ADD_PARAM_NAME("unlinkat", 2, "path"); // const char *
	ADD_PARAM_NAME("unlinkat", 3, "flag"); // int
	ADD_PARAM_NAME("usleep", 1, "usec"); // useconds_t
	ADD_PARAM_NAME("write", 1, "fd"); // int
	ADD_PARAM_NAME("write", 2, "buf"); // const void *
	ADD_PARAM_NAME("write", 3, "nbyte"); // size_t

	//
	// utime.h
	//
	ADD_PARAM_NAME("utime", 1, "path"); // const char *
	ADD_PARAM_NAME("utime", 2, "times"); // const struct utimbuf *

	//
	// utmp.h
	//
	ADD_PARAM_NAME("getutid", 1, "ut"); // struct utmp *
	ADD_PARAM_NAME("getutline", 1, "ut"); // struct utmp *
	ADD_PARAM_NAME("pututline", 1, "ut"); // struct utmp *
	ADD_PARAM_NAME("utmpname", 1, "file_path"); // const char *

	//
	// wchar.h
	//
	ADD_PARAM_NAME("mbsnrtowcs", 1, "wstr"); // wchar_t *
	ADD_PARAM_NAME("mbsnrtowcs", 2, "wstr"); // const char **
	ADD_PARAM_NAME("mbsnrtowcs", 3, "nms"); // size_t
	ADD_PARAM_NAME("mbsnrtowcs", 4, "length"); // size_t
	ADD_PARAM_NAME("mbsnrtowcs", 5, "ps"); // mbstate_t *
	ADD_PARAM_NAME("wcpcpy", 1, "wstr"); // wchar_t *
	ADD_PARAM_NAME("wcpcpy", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcpncpy", 1, "wstr"); // wchar_t *
	ADD_PARAM_NAME("wcpncpy", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcpncpy", 3, "n"); // size_t
	ADD_PARAM_NAME("wcscasecmp", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcscasecmp", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcscasecmp_l", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcscasecmp_l", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcscasecmp_l", 3, "locale"); // locale_t
	ADD_PARAM_NAME("wcscoll_l", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcscoll_l", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcscoll_l", 3, "locale"); // locale_t
	ADD_PARAM_NAME("wcsdup", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcsncasecmp", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcsncasecmp", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcsncasecmp", 3, "n"); // size_t
	ADD_PARAM_NAME("wcsncasecmp_l", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcsncasecmp_l", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcsncasecmp_l", 3, "n"); // size_t
	ADD_PARAM_NAME("wcsncasecmp_l", 4, "locale"); // locale_t
	ADD_PARAM_NAME("wcsnlen", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcsnlen", 2, "max_len"); // size_t
	ADD_PARAM_NAME("wcsnrtombs", 1, "wstr"); // char *
	ADD_PARAM_NAME("wcsnrtombs", 2, "wstr"); // const wchar_t **
	ADD_PARAM_NAME("wcsnrtombs", 3, "nwc"); // size_t
	ADD_PARAM_NAME("wcsnrtombs", 4, "length"); // size_t
	ADD_PARAM_NAME("wcsnrtombs", 5, "ps"); // mbstate_t *
	ADD_PARAM_NAME("wcsxfrm_l", 1, "wstr"); // wchar_t * restrict
	ADD_PARAM_NAME("wcsxfrm_l", 2, "wstr"); // const wchar_t * restrict
	ADD_PARAM_NAME("wcsxfrm_l", 3, "n"); // size_t
	ADD_PARAM_NAME("wcsxfrm_l", 4, "locale"); // locale_t

	//
	// wctype.h
	//
	ADD_PARAM_NAME("iswalnum_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswalnum_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("iswalpha_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswalpha_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("iswblank_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswblank_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("iswcntrl_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswcntrl_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("iswctype_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswctype_l", 2, "charclass"); // wctype_t
	ADD_PARAM_NAME("iswctype_l", 3, "locale"); // locale_t
	ADD_PARAM_NAME("iswdigit_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswdigit_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("iswgraph_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswgraph_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("iswlower_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswlower_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("iswprint_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswprint_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("iswpunct_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswpunct_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("iswspace_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswspace_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("iswupper_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswupper_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("iswxdigit_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswxdigit_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("towctrans_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("towctrans_l", 2, "desc"); // wctrans_t
	ADD_PARAM_NAME("towctrans_l", 3, "locale"); // locale_t
	ADD_PARAM_NAME("towlower_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("towlower_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("towupper_l", 1, "wc"); // wint_t
	ADD_PARAM_NAME("towupper_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("wctrans_l", 1, "charclass"); // const char *
	ADD_PARAM_NAME("wctrans_l", 2, "locale"); // locale_t
	ADD_PARAM_NAME("wctype_l", 1, "property"); // const char *
	ADD_PARAM_NAME("wctype_l", 2, "locale"); // locale_t

	//
	// wordexp.h
	//
	ADD_PARAM_NAME("wordexp", 1, "str"); // const char *
	ADD_PARAM_NAME("wordexp", 2, "p"); // wordexp_t *
	ADD_PARAM_NAME("wordexp", 3, "flags"); // int
	ADD_PARAM_NAME("wordfree", 1, "p"); // wordexp_t *

	return funcParamNamesMap;
}

/// Mapping of function parameter positions into the names of parameters.
const FuncParamNamesMap static FUNC_PARAM_NAMES_MAP(initFuncParamNamesMap());

} // anonymous namespace

/**
* @brief Implements getNameOfParam() for GCCGeneralSemantics.
*
* See its description for more details.
*/
Maybe<std::string> getNameOfParam(const std::string &funcName,
		unsigned paramPos) {
	return getNameOfParamFromMap(funcName, paramPos, FUNC_PARAM_NAMES_MAP);
}

} // namespace gcc_general
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
