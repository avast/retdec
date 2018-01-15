/**
* @file src/llvmir2hll/semantics/semantics/libc_semantics/get_name_of_var_storing_result.cpp
* @brief Implementation of semantics::libc::getNameOfVarStoringResult() for
*        LibcSemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/impl_support/get_name_of_var_storing_result.h"
#include "retdec/llvmir2hll/semantics/semantics/libc_semantics/get_name_of_var_storing_result.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace libc {

namespace {

/**
* @brief This function is used to initialize FUNC_VAR_NAME_MAP later in the
*        file.
*/
const StringStringUMap &initFuncVarNameMap() {
	static StringStringUMap m;

	// The following list is based on
	//
	//     - http://en.wikipedia.org/wiki/C_standard_library
	//     - http://www.cplusplus.com/reference/clibrary/
	//
	// and contains functions from C89, C99, and C11. It is by all means not
	// complete, but most of the functions should be there. If you find a
	// function that is missing, please, add it.

	//
	// assert.h
	//
	// m["assert"] = ""; // void

	//
	// complex.h
	//
	// m["cabs"] = "";
	// m["carg"] = "";
	// m["cimag"] = "";
	// m["creal"] = "";
	// m["conj"] = "";
	// m["cproj"] = "";
	// m["cexp"] = "";
	// m["clog"] = "";
	// m["csqrt"] = "";
	// m["cpow"] = "";
	// m["csin"] = "";
	// m["ccos"] = "";
	// m["ctan"] = "";
	// m["casin"] = "";
	// m["cacos"] = "";
	// m["catan"] = "";
	// m["csinh"] = "";
	// m["ccosh"] = "";
	// m["ctanh"] = "";
	// m["casinh"] = "";
	// m["cacosh"] = "";
	// m["catanh"] = "";

	//
	// ctype.h
	//
	// m["isalnum"] = "";
	// m["isalpha"] = "";
	// m["isblank"] = "";
	// m["iscntrl"] = "";
	// m["isdigit"] = "";
	// m["isgraph"] = "";
	// m["islower"] = "";
	// m["isprint"] = "";
	// m["ispunct"] = "";
	// m["isspace"] = "";
	// m["isupper"] = "";
	// m["isxdigit"] = "";
	// m["tolower"] = "";
	// m["toupper"] = "";

	//
	// errno.h
	//
	// -

	//
	// fenv.h
	//
	// m["feclearexcept"] = "";
	// m["fegetenv"] = "";
	// m["fegetexceptflag"] = "";
	// m["fegetround "] = "";
	// m["feholdexcept"] = "";
	// m["feraiseexcept"] = "";
	// m["fesetenv"] = "";
	// m["fesetexceptflag"] = "";
	// m["fesetround "] = "";
	// m["fetestexcept"] = "";
	// m["feupdateenv "] = "";

	//
	// float.h
	//
	// -

	//
	// inttypes.h
	//
	// -

	//
	// iso646.h
	//
	// -

	//
	// limits.h
	//
	// -

	//
	// locale.h
	//
	m["localeconv"] = "locale_info";
	m["setlocale"] = "locale";

	//
	// math.h
	//
	// m["abs"] = "";
	// m["labs"] = "";
	// m["llabs"] = "";
	// m["fabs"] = "";
	// m["div"] = "";
	// m["ldiv"] = "";
	// m["lldiv"] = "";
	// m["fmod"] = "";
	// m["remainder"] = "";
	// m["remquo"] = "";
	// m["fma"] = "";
	// m["fmax"] = "";
	// m["fmin"] = "";
	// m["fdim"] = "";
	// m["nan"] = "";
	// m["nanf"] = "";
	// m["nanl"] = "";
	// m["exp"] = "";
	// m["exp2"] = "";
	// m["expm1"] = "";
	// m["log"] = "";
	// m["log2"] = "";
	// m["log10"] = "";
	// m["log1p"] = "";
	// m["ilogb"] = "";
	// m["logb"] = "";
	// m["sqrt"] = "";
	// m["cbrt"] = "";
	// m["hypot"] = "";
	// m["pow"] = "";
	// m["sin"] = "";
	// m["cos"] = "";
	// m["tan"] = "";
	// m["asin"] = "";
	// m["acos"] = "";
	// m["atan"] = "";
	// m["atan2"] = "";
	// m["sinh"] = "";
	// m["cosh"] = "";
	// m["tanh"] = "";
	// m["asinh"] = "";
	// m["acosh"] = "";
	// m["atanh"] = "";
	// m["erf"] = "";
	// m["erfc"] = "";
	// m["lgamma"] = "";
	// m["tgamma"] = "";
	// m["ceil"] = "";
	// m["floor"] = "";
	// m["trunc"] = "";
	// m["round"] = "";
	// m["lround"] = "";
	// m["llround"] = "";
	// m["nearbyint"] = "";
	// m["rint"] = "";
	// m["lrint"] = "";
	// m["llrint"] = "";
	// m["frexp"] = "";
	// m["ldexp"] = "";
	// m["modf"] = "";
	// m["scalbn"] = "";
	// m["scalbln"] = "";
	// m["nextafter"] = "";
	// m["nexttoward"] = "";
	// m["copysign"] = "";
	// m["fpclassify"] = "";
	// m["isfinite"] = "";
	// m["isinf"] = "";
	// m["isnan"] = "";
	// m["isnormal"] = "";
	// m["signbit"] = "";

	//
	// setjmp.h
	//
	m["setjmp"] = "val";
	// m["longjmp"] = ""; // void

	//
	// signal.h
	//
	m["signal"] = "prev_sig_handler";
	m["raise"] = "raise_rc";

	//
	// stdalign.h
	//
	// -

	//
	// stdarg.h
	//
	// m["va_start"] = ""; // void
	// m["va_arg"] = "";
	// m["va_end"] = ""; // void
	// m["va_copy"] = ""; // void

	//
	// stdatomic.h
	//
	// -

	//
	// stdbool.h
	//
	// -

	//
	// stddef.h
	//
	// m["offsetof"] = "";

	//
	// stdint.h
	//
	// -

	//
	// stdio.h
	//
	// m["clearerr"] = ""; // void
	// m["fclose"] = ""; // void
	m["feof"] = "is_feof";
	m["ferror"] = "is_ferror";
	m["fflush"] = "fflush_rc";
	m["fgetc"] = "c";
	m["fgetpos"] = "fgetpos_rc";
	m["fgets"] = "str";
	m["fopen"] = "file";
	m["fprintf"] = "chars_printed";
	m["fputc"] = "fputc_rc";
	m["fputs"] = "fputs_rc";
	m["fread"] = "items_read";
	m["freopen"] = "file";
	m["fscanf"] = "items_assigned";
	m["fseek"] = "fseek_rc";
	m["fsetpos"] = "fsetpos_rc";
	m["ftell"] = "curr_file_offset";
	m["fwrite"] = "items_written";
	m["getc"] = "c";
	m["getchar"] = "c";
	m["gets"] = "str";
	// m["perror"] = ""; // void
	m["printf"] = "chars_printed";
	m["putc"] = "putc_rc";
	m["putchar"] = "putchar_rc";
	m["puts"] = "puts_rc";
	m["remove"] = "remove_rc";
	m["rename"] = "rename_rc";
	// m["rewind"] = ""; // void
	m["scanf"] = "items_assigned";
	// m["setbuf"] = ""; // void
	m["setvbuf"] = "setvbuf_rc";
	m["snprintf"] = "chars_printed";
	m["sprintf"] = "chars_printed";
	m["sscanf"] = "items_assigned";
	m["tmpfile"] = "tmp_file";
	m["tmpnam"] = "tmp_file_name";
	m["ungetc"] = "ungetc_rc";
	m["vfprintf"] = "chars_printed";
	m["vfscanf"] = "items_assigned";
	m["vprintf"] = "chars_printed";
	m["vscanf"] = "items_assigned";
	m["vsnprintf"] = "chars_printed";
	m["vsprintf"] = "chars_printed";
	m["vsscanf"] = "items_assigned";

	//
	// stdlib.h
	//
	m["atof"] = "str_as_f";
	m["atoi"] = "str_as_i";
	m["atol"] = "str_as_l";
	m["atoll"] = "str_as_ll";
	m["strtof"] = "str_as_f";
	m["strtod"] = "str_as_d";
	m["strtold"] = "str_as_ld";
	m["strtol"] = "str_as_l";
	m["strtoll"] = "str_as_ll";
	m["strtoul"] = "str_as_ul";
	m["strtoull"] = "str_as_ull";
	m["calloc"] = "mem";
	m["malloc"] = "mem";
	m["realloc"] = "mem";
	// m["free"] = ""; // void
	// m["abort"] = ""; // void
	// m["exit"] = ""; // void
	m["atexit"] = "atexit_rc";
	// m["quick_exit"] = ""; // void
	m["at_quick_exit"] = "at_quick_exit_rc";
	m["system"] = "system_rc";
	m["getenv"] = "env_val";
	m["bsearch"] = "found_elem";
	// m["qsort"] = ""; // void
	// m["rand"] = "";
	// m["srand"] = ""; // void
	// m["_Exit"] = ""; // void

	//
	// stdnoreturn.h
	//
	// -

	//
	// string.h
	//
	m["memchr"] = "found_byte_pos";
	m["memcmp"] = "memcmp_rc";
	m["memcpy"] = "dest_mem";
	m["memmove"] = "dest_mem";
	m["memset"] = "set_mem";
	m["strcat"] = "dest_str";
	m["strchr"] = "found_char_pos";
	m["strcmp"] = "strcmp_rc";
	m["strcoll"] = "strcoll_rc";
	m["strcpy"] = "dest_str";
	m["strcspn"] = "ini_seg_bytes";
	m["strerror"] = "err_str";
	m["strlen"] = "len";
	m["strncat"] = "dest_str";
	m["strncmp"] = "strncmp_rc";
	m["strncpy"] = "dest_str";
	m["strpbrk"] = "found_byte_pos";
	m["strrchr"] = "found_char_pos";
	m["strspn"] = "ini_seg_bytes";
	m["strstr"] = "substr_pos";
	m["strtok"] = "next_token";
	m["strxfrm"] = "req_bytes";

	//
	// tgmath.h
	//
	// -

	//
	// threads.h
	//
	// -

	//
	// time.h
	//
	m["difftime"] = "time_diff";
	m["time"] = "time_val";
	m["clock"] = "proc_time";
	m["asctime"] = "time_str";
	m["ctime"] = "time_str";
	m["strftime"] = "copied_chars";
	m["gmtime"] = "time_info";
	m["localtime"] = "time_info";
	m["mktime"] = "time_info";

	//
	// wchar.h
	//
	// m["btowc"] = "";
	// m["fgetwc"] = "";
	// m["fgetws"] = "";
	// m["fputwc"] = "";
	// m["fputws"] = "";
	// m["fwide"] = "";
	// m["fwprintf"] = "";
	// m["fwscanf"] = "";
	// m["getwc"] = "";
	// m["getwchar"] = "";
	// m["mbrlen"] = "";
	// m["mbrtowc"] = "";
	// m["mbsinit"] = "";
	// m["mbsrtowcs"] = "";
	// m["putwc"] = "";
	// m["putwchar"] = "";
	// m["swprintf"] = "";
	// m["swscanf"] = "";
	// m["ungetwc"] = "";
	// m["vfwprintf"] = "";
	// m["vfwscanf"] = "";
	// m["vswprintf"] = "";
	// m["vswscanf"] = "";
	// m["vwprintf"] = "";
	// m["vwscanf"] = "";
	// m["wcrtomb"] = "";
	// m["wcscat"] = "";
	// m["wcschr"] = "";
	// m["wcscmp"] = "";
	// m["wcscoll"] = "";
	// m["wcscpy"] = "";
	// m["wcscspn"] = "";
	// m["wcsftime"] = "";
	// m["wcslen"] = "";
	// m["wcsncat"] = "";
	// m["wcsncmp"] = "";
	// m["wcsncpy"] = "";
	// m["wcspbrk"] = "";
	// m["wcsrchr"] = "";
	// m["wcsrtombs"] = "";
	// m["wcsspn"] = "";
	// m["wcsstr"] = "";
	// m["wcstod"] = "";
	// m["wcstof"] = "";
	// m["wcstok"] = "";
	// m["wcstol"] = "";
	// m["wcstold"] = "";
	// m["wcstoll"] = "";
	// m["wcstoul"] = "";
	// m["wcstoull"] = "";
	// m["wcsxfrm"] = "";
	// m["wctob"] = "";
	// m["wmemchr"] = "";
	// m["wmemcmp"] = "";
	// m["wmemcpy"] = "";
	// m["wmemmove"] = "";
	// m["wmemset"] = "";
	// m["wprintf"] = "";
	// m["wscanf"] = "";

	//
	// wctype.h
	//
	// m["iswalnum"] = "";
	// m["iswalpha"] = "";
	// m["iswblank"] = "";
	// m["iswcntrl"] = "";
	// m["iswctype"] = "";
	// m["iswdigit"] = "";
	// m["iswgraph"] = "";
	// m["iswlower"] = "";
	// m["iswprint"] = "";
	// m["iswpunct"] = "";
	// m["iswspace"] = "";
	// m["iswupper"] = "";
	// m["iswxdigit"] = "";
	// m["towctrans"] = "";
	// m["towlower"] = "";
	// m["towupper"] = "";
	// m["wctrans"] = "";
	// m["wctype"] = "";

	return m;
}

/// Mapping of function names to their corresponding names of variables.
const StringStringUMap &FUNC_VAR_NAME_MAP(initFuncVarNameMap());

} // anonymous namespace

/**
* @brief Implements getNameOfVarStoringResult() for LibcSemantics.
*
* See its description for more details.
*/
Maybe<std::string> getNameOfVarStoringResult(const std::string &funcName) {
	return getNameOfVarStoringResultFromMap(funcName, FUNC_VAR_NAME_MAP);
}

} // namespace libc
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
