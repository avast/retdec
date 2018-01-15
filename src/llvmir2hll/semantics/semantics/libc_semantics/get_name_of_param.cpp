/**
* @file src/llvmir2hll/semantics/semantics/libc_semantics/get_name_of_param.cpp
* @brief Implementation of semantics::libc::getNameOfParam() for
*        LibcSemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/impl_support/get_name_of_param.h"
#include "retdec/llvmir2hll/semantics/semantics/libc_semantics/get_name_of_param.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace libc {

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
	// script over the functions in LibcSemantics/getCHeaderFileForFunc.cpp.
	// The resulting semantics has been updated manually. Useless mappings have
	// been commented out.
	//

	//
	// assert.h
	//
	// ADD_PARAM_NAME("assert", 1, "expression"); // scalar

	//
	// complex.h
	//
	// ADD_PARAM_NAME("cabs", 1, "z"); // double complex
	// ADD_PARAM_NAME("cabsf", 1, "z"); // float complex
	// ADD_PARAM_NAME("cabsl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("cacos", 1, "z"); // double complex
	// ADD_PARAM_NAME("cacosf", 1, "z"); // float complex
	// ADD_PARAM_NAME("cacosh", 1, "z"); // double complex
	// ADD_PARAM_NAME("cacoshf", 1, "z"); // float complex
	// ADD_PARAM_NAME("cacoshl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("cacosl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("carg", 1, "z"); // double complex
	// ADD_PARAM_NAME("cargf", 1, "z"); // float complex
	// ADD_PARAM_NAME("cargl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("casin", 1, "z"); // double complex
	// ADD_PARAM_NAME("casinf", 1, "z"); // float complex
	// ADD_PARAM_NAME("casinh", 1, "z"); // double complex
	// ADD_PARAM_NAME("casinhf", 1, "z"); // float complex
	// ADD_PARAM_NAME("casinhl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("casinl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("catan", 1, "z"); // double complex
	// ADD_PARAM_NAME("catanf", 1, "z"); // float complex
	// ADD_PARAM_NAME("catanh", 1, "z"); // double complex
	// ADD_PARAM_NAME("catanhf", 1, "z"); // float complex
	// ADD_PARAM_NAME("catanhl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("catanl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("ccos", 1, "z"); // double complex
	// ADD_PARAM_NAME("ccosf", 1, "z"); // float complex
	// ADD_PARAM_NAME("ccosh", 1, "z"); // double complex
	// ADD_PARAM_NAME("ccoshf", 1, "z"); // float complex
	// ADD_PARAM_NAME("ccoshl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("ccosl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("cexp", 1, "z"); // double complex
	// ADD_PARAM_NAME("cexpf", 1, "z"); // float complex
	// ADD_PARAM_NAME("cexpl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("cimag", 1, "z"); // double complex
	// ADD_PARAM_NAME("cimagf", 1, "z"); // float complex
	// ADD_PARAM_NAME("cimagl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("clog", 1, "z"); // double complex
	// ADD_PARAM_NAME("clogf", 1, "z"); // float complex
	// ADD_PARAM_NAME("clogl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("conj", 1, "z"); // double complex
	// ADD_PARAM_NAME("conjf", 1, "z"); // float complex
	// ADD_PARAM_NAME("conjl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("cpow", 1, "x"); // double complex
	// ADD_PARAM_NAME("cpow", 2, "z"); // complex double
	// ADD_PARAM_NAME("cpowf", 1, "x"); // float complex
	// ADD_PARAM_NAME("cpowf", 2, "z"); // complex float
	// ADD_PARAM_NAME("cpowl", 1, "x"); // long double complex
	// ADD_PARAM_NAME("cpowl", 2, "z"); // complex long double
	// ADD_PARAM_NAME("cproj", 1, "z"); // double complex
	// ADD_PARAM_NAME("cprojf", 1, "z"); // float complex
	// ADD_PARAM_NAME("cprojl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("creal", 1, "z"); // double complex
	// ADD_PARAM_NAME("crealf", 1, "z"); // float complex
	// ADD_PARAM_NAME("creall", 1, "z"); // long double complex
	// ADD_PARAM_NAME("csin", 1, "z"); // double complex
	// ADD_PARAM_NAME("csinf", 1, "z"); // float complex
	// ADD_PARAM_NAME("csinh", 1, "z"); // double complex
	// ADD_PARAM_NAME("csinhf", 1, "z"); // float complex
	// ADD_PARAM_NAME("csinhl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("csinl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("csqrt", 1, "z"); // double complex
	// ADD_PARAM_NAME("csqrtf", 1, "z"); // float complex
	// ADD_PARAM_NAME("csqrtl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("ctan", 1, "z"); // double complex
	// ADD_PARAM_NAME("ctanf", 1, "z"); // float complex
	// ADD_PARAM_NAME("ctanh", 1, "z"); // double complex
	// ADD_PARAM_NAME("ctanhf", 1, "z"); // float complex
	// ADD_PARAM_NAME("ctanhl", 1, "z"); // long double complex
	// ADD_PARAM_NAME("ctanl", 1, "z"); // long double complex

	//
	// ctype.h
	//
	ADD_PARAM_NAME("isalnum", 1, "c"); // int
	ADD_PARAM_NAME("isalpha", 1, "c"); // int
	ADD_PARAM_NAME("isblank", 1, "c"); // int
	ADD_PARAM_NAME("iscntrl", 1, "c"); // int
	ADD_PARAM_NAME("isdigit", 1, "c"); // int
	ADD_PARAM_NAME("isgraph", 1, "c"); // int
	ADD_PARAM_NAME("islower", 1, "c"); // int
	ADD_PARAM_NAME("isprint", 1, "c"); // int
	ADD_PARAM_NAME("ispunct", 1, "c"); // int
	ADD_PARAM_NAME("isspace", 1, "c"); // int
	ADD_PARAM_NAME("isupper", 1, "c"); // int
	ADD_PARAM_NAME("isxdigit", 1, "c"); // int
	ADD_PARAM_NAME("tolower", 1, "c"); // int
	ADD_PARAM_NAME("toupper", 1, "c"); // int

	//
	// fenv.h
	//
	ADD_PARAM_NAME("feclearexcept", 1, "excepts"); // int
	ADD_PARAM_NAME("fegetenv", 1, "envp"); // fenv_t *
	ADD_PARAM_NAME("fegetexceptflag", 1, "flagp"); // fexcept_t *
	ADD_PARAM_NAME("fegetexceptflag", 2, "excepts"); // int
	ADD_PARAM_NAME("feholdexcept", 1, "envp"); // fenv_t *
	ADD_PARAM_NAME("feraiseexcept", 1, "excepts"); // int
	ADD_PARAM_NAME("fesetenv", 1, "envp"); // const fenv_t *
	ADD_PARAM_NAME("fesetexceptflag", 1, "flagp"); // const fexcept_t *
	ADD_PARAM_NAME("fesetexceptflag", 2, "excepts"); // int
	ADD_PARAM_NAME("fesetround", 1, "rounding_mode"); // int
	ADD_PARAM_NAME("fetestexcept", 1, "excepts"); // int
	ADD_PARAM_NAME("feupdateenv", 1, "envp"); // const fenv_t *

	//
	// locale.h
	//
	ADD_PARAM_NAME("setlocale", 1, "locale_category"); // int
	ADD_PARAM_NAME("setlocale", 2, "locale"); // const char *

	//
	// math.h
	//
	// ADD_PARAM_NAME("acos", 1, "x"); // double
	// ADD_PARAM_NAME("acosh", 1, "x"); // double
	// ADD_PARAM_NAME("asin", 1, "x"); // double
	// ADD_PARAM_NAME("asinh", 1, "x"); // double
	// ADD_PARAM_NAME("atan", 1, "x"); // double
	// ADD_PARAM_NAME("atan2", 1, "y"); // double
	// ADD_PARAM_NAME("atan2", 2, "x"); // double
	// ADD_PARAM_NAME("atanh", 1, "x"); // double
	// ADD_PARAM_NAME("cbrt", 1, "x"); // double
	// ADD_PARAM_NAME("ceil", 1, "x"); // double
	// ADD_PARAM_NAME("copysign", 1, "x"); // double
	// ADD_PARAM_NAME("copysign", 2, "y"); // double
	// ADD_PARAM_NAME("cos", 1, "x"); // double
	// ADD_PARAM_NAME("cosh", 1, "x"); // double
	// ADD_PARAM_NAME("erf", 1, "x"); // double
	// ADD_PARAM_NAME("erfc", 1, "x"); // double
	// ADD_PARAM_NAME("exp", 1, "x"); // double
	// ADD_PARAM_NAME("exp2", 1, "x"); // double
	// ADD_PARAM_NAME("expm1", 1, "x"); // double
	// ADD_PARAM_NAME("fabs", 1, "x"); // double
	// ADD_PARAM_NAME("fdim", 1, "x"); // double
	// ADD_PARAM_NAME("fdim", 2, "y"); // double
	// ADD_PARAM_NAME("floor", 1, "x"); // double
	// ADD_PARAM_NAME("fma", 1, "x"); // double
	// ADD_PARAM_NAME("fma", 2, "y"); // double
	// ADD_PARAM_NAME("fma", 3, "z"); // double
	// ADD_PARAM_NAME("fmax", 1, "x"); // double
	// ADD_PARAM_NAME("fmax", 2, "y"); // double
	// ADD_PARAM_NAME("fmin", 1, "x"); // double
	// ADD_PARAM_NAME("fmin", 2, "y"); // double
	// ADD_PARAM_NAME("fmod", 1, "x"); // double
	// ADD_PARAM_NAME("fmod", 2, "y"); // double
	// ADD_PARAM_NAME("fpclassify", 1, "x"); // ?
	// ADD_PARAM_NAME("frexp", 1, "x"); // double
	// ADD_PARAM_NAME("frexp", 2, "exp"); // int *
	// ADD_PARAM_NAME("hypot", 1, "x"); // double
	// ADD_PARAM_NAME("hypot", 2, "y"); // double
	// ADD_PARAM_NAME("ilogb", 1, "x"); // double
	// ADD_PARAM_NAME("isfinite", 1, "x"); // ?
	// ADD_PARAM_NAME("isinf", 1, "x"); // ?
	// ADD_PARAM_NAME("isnan", 1, "x"); // ?
	// ADD_PARAM_NAME("isnormal", 1, "x"); // ?
	// ADD_PARAM_NAME("ldexp", 1, "x"); // double
	// ADD_PARAM_NAME("ldexp", 2, "exp"); // int
	// ADD_PARAM_NAME("lgamma", 1, "x"); // double
	// ADD_PARAM_NAME("llrint", 1, "x"); // double
	// ADD_PARAM_NAME("llround", 1, "x"); // double
	// ADD_PARAM_NAME("log", 1, "x"); // double
	// ADD_PARAM_NAME("log10", 1, "x"); // double
	// ADD_PARAM_NAME("log1p", 1, "x"); // double
	// ADD_PARAM_NAME("log2", 1, "x"); // double
	// ADD_PARAM_NAME("logb", 1, "x"); // double
	// ADD_PARAM_NAME("lrint", 1, "x"); // double
	// ADD_PARAM_NAME("lround", 1, "x"); // double
	// ADD_PARAM_NAME("modf", 1, "x"); // double
	// ADD_PARAM_NAME("modf", 2, "iptr"); // double *
	// ADD_PARAM_NAME("nan", 1, "tagp"); // const char *
	// ADD_PARAM_NAME("nanf", 1, "tagp"); // const char *
	// ADD_PARAM_NAME("nanl", 1, "tagp"); // const char *
	// ADD_PARAM_NAME("nearbyint", 1, "x"); // double
	// ADD_PARAM_NAME("nextafter", 1, "x"); // double
	// ADD_PARAM_NAME("nextafter", 2, "y"); // double
	// ADD_PARAM_NAME("nexttoward", 1, "x"); // double
	// ADD_PARAM_NAME("nexttoward", 2, "y"); // long double
	// ADD_PARAM_NAME("pow", 1, "x"); // double
	// ADD_PARAM_NAME("pow", 2, "y"); // double
	// ADD_PARAM_NAME("remainder", 1, "x"); // double
	// ADD_PARAM_NAME("remainder", 2, "y"); // double
	// ADD_PARAM_NAME("remquo", 1, "x"); // double
	// ADD_PARAM_NAME("remquo", 2, "y"); // double
	// ADD_PARAM_NAME("remquo", 3, "quo"); // int *
	// ADD_PARAM_NAME("rint", 1, "x"); // double
	// ADD_PARAM_NAME("round", 1, "x"); // double
	// ADD_PARAM_NAME("scalbln", 1, "x"); // double
	// ADD_PARAM_NAME("scalbln", 2, "exp"); // long int
	// ADD_PARAM_NAME("scalbn", 1, "x"); // double
	// ADD_PARAM_NAME("scalbn", 2, "exp"); // int
	// ADD_PARAM_NAME("signbit", 1, "x"); // ?
	// ADD_PARAM_NAME("sin", 1, "x"); // double
	// ADD_PARAM_NAME("sinh", 1, "x"); // double
	// ADD_PARAM_NAME("sqrt", 1, "x"); // double
	// ADD_PARAM_NAME("tan", 1, "x"); // double
	// ADD_PARAM_NAME("tanh", 1, "x"); // double
	// ADD_PARAM_NAME("tgamma", 1, "x"); // double
	// ADD_PARAM_NAME("trunc", 1, "x"); // double

	//
	// setjmp.h
	//
	ADD_PARAM_NAME("longjmp", 1, "env"); // jmp_buf
	ADD_PARAM_NAME("longjmp", 2, "val"); // int
	ADD_PARAM_NAME("setjmp", 1, "env"); // jmp_buf

	//
	// signal.h
	//
	ADD_PARAM_NAME("raise", 1, "sig_num"); // int
	ADD_PARAM_NAME("signal", 1, "sig_num"); // int
	ADD_PARAM_NAME("signal", 1, "sig_handler"); // void (*)(int)

	//
	// stdarg.h
	//
	// ADD_PARAM_NAME("va_arg", 1, "ap"); // va_list
	// ADD_PARAM_NAME("va_arg", 2, "type"); // ?
	// ADD_PARAM_NAME("va_copy", 1, "dest"); // va_list
	// ADD_PARAM_NAME("va_copy", 2, "src"); // va_list
	// ADD_PARAM_NAME("va_end", 1, "ap"); // va_list
	// ADD_PARAM_NAME("va_start", 1, "ap"); // va_list
	// ADD_PARAM_NAME("va_start", 2, "last"); // ?
	ADD_PARAM_NAME("vfwscanf", 1, "stream"); // FILE * restrict
	ADD_PARAM_NAME("vfwscanf", 2, "format"); // const wchar_t * restrict
	ADD_PARAM_NAME("vswscanf", 1, "wstr"); // const wchar_t * restrict
	ADD_PARAM_NAME("vswscanf", 2, "format"); // const wchar_t * restrict
	ADD_PARAM_NAME("vwscanf", 1, "format"); // const wchar_t * restrict

	//
	// stddef.h
	//
	// ADD_PARAM_NAME("offsetof", 1, "type"); // ?
	// ADD_PARAM_NAME("offsetof", 2, "member"); // ?

	//
	// stdio.h
	//
	ADD_PARAM_NAME("clearerr", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fclose", 1, "file"); // FILE *
	ADD_PARAM_NAME("feof", 1, "stream"); // FILE *
	ADD_PARAM_NAME("ferror", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fflush", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fgetc", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fgetpos", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fgetpos", 2, "pos"); // fpos_t *
	ADD_PARAM_NAME("fgets", 1, "str"); // char *
	ADD_PARAM_NAME("fgets", 2, "size"); // int
	ADD_PARAM_NAME("fgets", 3, "stream"); // FILE *
	ADD_PARAM_NAME("fgetwc", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fopen", 1, "file_path"); // const char *
	ADD_PARAM_NAME("fopen", 2, "mode"); // const char *
	ADD_PARAM_NAME("fprintf", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fprintf", 2, "format"); // const char *
	ADD_PARAM_NAME("fputc", 1, "c"); // int
	ADD_PARAM_NAME("fputc", 2, "stream"); // FILE *
	ADD_PARAM_NAME("fputs", 1, "str"); // const char *
	ADD_PARAM_NAME("fputs", 2, "stream"); // FILE *
	ADD_PARAM_NAME("fputwc", 1, "wc"); // wchar_t
	ADD_PARAM_NAME("fputwc", 2, "stream"); // FILE *
	ADD_PARAM_NAME("fread", 1, "data"); // void *
	ADD_PARAM_NAME("fread", 2, "size"); // size_t
	ADD_PARAM_NAME("fread", 3, "nmemb"); // size_t
	ADD_PARAM_NAME("fread", 4, "stream"); // FILE *
	ADD_PARAM_NAME("freopen", 1, "file_path"); // const char *
	ADD_PARAM_NAME("freopen", 2, "mode"); // const char *
	ADD_PARAM_NAME("freopen", 3, "stream"); // FILE *
	ADD_PARAM_NAME("fscanf", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fscanf", 2, "format"); // const char *
	ADD_PARAM_NAME("fseek", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fseek", 2, "offset"); // long
	ADD_PARAM_NAME("fseek", 3, "whence"); // int
	ADD_PARAM_NAME("fsetpos", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fsetpos", 2, "pos"); // fpos_t *
	ADD_PARAM_NAME("ftell", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fwprintf", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fwprintf", 2, "format"); // const wchar_t *
	ADD_PARAM_NAME("fwrite", 1, "data"); // const void *
	ADD_PARAM_NAME("fwrite", 2, "size"); // size_t
	ADD_PARAM_NAME("fwrite", 3, "nmemb"); // size_t
	ADD_PARAM_NAME("fwrite", 4, "stream"); // FILE *
	ADD_PARAM_NAME("fwscanf", 1, "stream"); // FILE * restrict
	ADD_PARAM_NAME("fwscanf", 2, "format"); // const wchar_t * restrict
	ADD_PARAM_NAME("getc", 1, "stream"); // FILE *
	ADD_PARAM_NAME("gets", 1, "str"); // char *
	ADD_PARAM_NAME("getwc", 1, "stream"); // FILE *
	ADD_PARAM_NAME("perror", 1, "str"); // const char *
	ADD_PARAM_NAME("printf", 1, "format"); // const char *
	ADD_PARAM_NAME("putc", 1, "c"); // int
	ADD_PARAM_NAME("putc", 2, "stream"); // FILE *
	ADD_PARAM_NAME("putchar", 1, "c"); // int
	ADD_PARAM_NAME("puts", 1, "str"); // const char *
	ADD_PARAM_NAME("putwc", 1, "wc"); // wchar_t
	ADD_PARAM_NAME("putwc", 2, "stream"); // FILE *
	ADD_PARAM_NAME("remove", 1, "file_path"); // const char *
	ADD_PARAM_NAME("rename", 1, "file_path"); // const char *
	ADD_PARAM_NAME("rename", 2, "file_path"); // const char *
	ADD_PARAM_NAME("rewind", 1, "stream"); // FILE *
	ADD_PARAM_NAME("scanf", 1, "format"); // const char *
	ADD_PARAM_NAME("setbuf", 1, "stream"); // FILE *
	ADD_PARAM_NAME("setbuf", 2, "buf"); // char *
	ADD_PARAM_NAME("setvbuf", 1, "stream"); // FILE *
	ADD_PARAM_NAME("setvbuf", 2, "buf"); // char *
	ADD_PARAM_NAME("setvbuf", 3, "mode"); // int
	ADD_PARAM_NAME("setvbuf", 4, "size"); // size_t
	ADD_PARAM_NAME("snprintf", 1, "str"); // char *
	ADD_PARAM_NAME("snprintf", 2, "size"); // size_t
	ADD_PARAM_NAME("snprintf", 3, "format"); // const char *
	ADD_PARAM_NAME("sprintf", 1, "str"); // char *
	ADD_PARAM_NAME("sprintf", 2, "format"); // const char *
	ADD_PARAM_NAME("sscanf", 1, "str"); // const char *
	ADD_PARAM_NAME("sscanf", 2, "format"); // const char *
	ADD_PARAM_NAME("swprintf", 1, "wstr"); // wchar_t *
	ADD_PARAM_NAME("swprintf", 2, "max_length"); // size_t
	ADD_PARAM_NAME("swprintf", 3, "format"); // const wchar_t *
	ADD_PARAM_NAME("swscanf", 1, "wstr"); // const wchar_t * restrict
	ADD_PARAM_NAME("swscanf", 2, "format"); // const wchar_t * restrict
	ADD_PARAM_NAME("tmpnam", 1, "tmp_file_name"); // char *
	ADD_PARAM_NAME("ungetc", 1, "c"); // int
	ADD_PARAM_NAME("ungetc", 2, "stream"); // FILE *
	ADD_PARAM_NAME("vfprintf", 1, "stream"); // FILE *
	ADD_PARAM_NAME("vfprintf", 2, "format"); // const char *
	ADD_PARAM_NAME("vfscanf", 2, "format"); // const char *
	ADD_PARAM_NAME("vfwprintf", 1, "stream"); // FILE *
	ADD_PARAM_NAME("vfwprintf", 2, "format"); // const wchar_t *
	ADD_PARAM_NAME("vprintf", 1, "format"); // const char *
	ADD_PARAM_NAME("vscanf", 1, "format"); // const char *
	ADD_PARAM_NAME("vsnprintf", 1, "str"); // char *
	ADD_PARAM_NAME("vsnprintf", 2, "size"); // size_t
	ADD_PARAM_NAME("vsnprintf", 3, "format"); // const char *
	ADD_PARAM_NAME("vsprintf", 1, "str"); // char *
	ADD_PARAM_NAME("vsprintf", 2, "format"); // const char *
	ADD_PARAM_NAME("vsscanf", 1, "str"); // const char *
	ADD_PARAM_NAME("vsscanf", 2, "format"); // const char *
	ADD_PARAM_NAME("vswprintf", 1, "wstr"); // wchar_t *
	ADD_PARAM_NAME("vswprintf", 2, "maxlen"); // size_t
	ADD_PARAM_NAME("vswprintf", 3, "format"); // const wchar_t *
	ADD_PARAM_NAME("vwprintf", 1, "format"); // const wchar_t *
	ADD_PARAM_NAME("wprintf", 1, "format"); // const wchar_t *
	ADD_PARAM_NAME("wscanf", 1, "format"); // const wchar_t * restrict

	//
	// stdlib.h
	//
	ADD_PARAM_NAME("_Exit", 1, "status"); // int
	// ADD_PARAM_NAME("abs", 1, "j"); // int
	ADD_PARAM_NAME("at_quick_exit", 1, "at_quick_exit_func"); // void (*)(void)
	ADD_PARAM_NAME("atexit", 1, "atexit_func"); // void (*)(void)
	ADD_PARAM_NAME("atof", 1, "str"); // const char *
	ADD_PARAM_NAME("atoi", 1, "str"); // const char *
	ADD_PARAM_NAME("atol", 1, "str"); // const char *
	ADD_PARAM_NAME("atoll", 1, "str"); // const char *
	ADD_PARAM_NAME("bsearch", 1, "key"); // const void *
	ADD_PARAM_NAME("bsearch", 2, "base"); // const void *
	ADD_PARAM_NAME("bsearch", 3, "nmemb"); // size_t
	ADD_PARAM_NAME("bsearch", 4, "size"); // size_t
	ADD_PARAM_NAME("bsearch", 5, "cmp_func"); // int (*)(const void *, const void *)
	ADD_PARAM_NAME("calloc", 1, "nmemb"); // size_t
	ADD_PARAM_NAME("calloc", 2, "size"); // size_t
	// ADD_PARAM_NAME("div", 1, "numerator"); // int
	// ADD_PARAM_NAME("div", 2, "denominator"); // int
	ADD_PARAM_NAME("exit", 1, "status"); // int
	ADD_PARAM_NAME("getenv", 1, "name"); // const char *
	// ADD_PARAM_NAME("labs", 1, "j"); // long int
	// ADD_PARAM_NAME("ldiv", 1, "numerator"); // long
	// ADD_PARAM_NAME("ldiv", 2, "denominator"); // long
	// ADD_PARAM_NAME("llabs", 1, "j"); // long long int
	// ADD_PARAM_NAME("lldiv", 1, "numerator"); // long long
	// ADD_PARAM_NAME("lldiv", 2, "denominator"); // long long
	ADD_PARAM_NAME("malloc", 1, "size"); // size_t
	ADD_PARAM_NAME("qsort", 1, "base"); //
	ADD_PARAM_NAME("qsort", 2, "nmemb"); //
	ADD_PARAM_NAME("qsort", 3, "size"); //
	ADD_PARAM_NAME("bsearch", 4, "cmp_func"); // int (*)(const void *, const void *)
	ADD_PARAM_NAME("quick_exit", 1, "status"); // int
	ADD_PARAM_NAME("srand", 1, "seed"); // unsigned int
	ADD_PARAM_NAME("strtod", 1, "str"); // const char *
	ADD_PARAM_NAME("strtod", 2, "endptr"); // char * *
	ADD_PARAM_NAME("strtof", 1, "str"); // const char *
	ADD_PARAM_NAME("strtof", 2, "endptr"); // char * *
	ADD_PARAM_NAME("strtol", 1, "str"); // const char *
	ADD_PARAM_NAME("strtol", 2, "endptr"); // char * *
	ADD_PARAM_NAME("strtol", 3, "base"); // int
	ADD_PARAM_NAME("strtold", 1, "str"); // const char *
	ADD_PARAM_NAME("strtold", 2, "endptr"); // char * *
	ADD_PARAM_NAME("strtoll", 1, "str"); // const char *
	ADD_PARAM_NAME("strtoll", 2, "endptr"); // char * *
	ADD_PARAM_NAME("strtoll", 3, "base"); // int
	ADD_PARAM_NAME("strtoul", 1, "str"); // const char *
	ADD_PARAM_NAME("strtoul", 2, "endptr"); // char * *
	ADD_PARAM_NAME("strtoul", 3, "base"); // int
	ADD_PARAM_NAME("strtoull", 1, "str"); // const char *
	ADD_PARAM_NAME("strtoull", 2, "endptr"); // char * *
	ADD_PARAM_NAME("strtoull", 3, "base"); // int
	ADD_PARAM_NAME("system", 1, "command"); // const char *

	//
	// string.h
	//
	ADD_PARAM_NAME("memchr", 1, "str"); // const void *
	ADD_PARAM_NAME("memchr", 2, "c"); // int
	ADD_PARAM_NAME("memchr", 3, "n"); // size_t
	ADD_PARAM_NAME("memcmp", 1, "str"); // const void *
	ADD_PARAM_NAME("memcmp", 2, "str"); // const void *
	ADD_PARAM_NAME("memcmp", 3, "n"); // size_t
	ADD_PARAM_NAME("strcat", 1, "str"); // char *
	ADD_PARAM_NAME("strcat", 2, "str"); // const char *
	ADD_PARAM_NAME("strchr", 1, "str"); // const char *
	ADD_PARAM_NAME("strchr", 2, "c"); // int
	ADD_PARAM_NAME("strcmp", 1, "str"); // const char *
	ADD_PARAM_NAME("strcmp", 2, "str"); // const char *
	ADD_PARAM_NAME("strcoll", 1, "str"); // const char *
	ADD_PARAM_NAME("strcoll", 2, "str"); // const char *
	ADD_PARAM_NAME("strcpy", 1, "str"); // char *
	ADD_PARAM_NAME("strcpy", 2, "str"); // const char *
	ADD_PARAM_NAME("strcspn", 1, "str"); // const char *
	ADD_PARAM_NAME("strcspn", 2, "reject"); // const char *
	ADD_PARAM_NAME("strerror", 1, "err_num"); // int
	ADD_PARAM_NAME("strlen", 1, "str"); // const char *
	ADD_PARAM_NAME("strncat", 1, "str"); // char *
	ADD_PARAM_NAME("strncat", 2, "str"); // const char *
	ADD_PARAM_NAME("strncat", 3, "n"); // size_t
	ADD_PARAM_NAME("strncmp", 1, "str"); // const char *
	ADD_PARAM_NAME("strncmp", 2, "str"); // const char *
	ADD_PARAM_NAME("strncmp", 3, "n"); // size_t
	ADD_PARAM_NAME("strncpy", 1, "str"); // char *
	ADD_PARAM_NAME("strncpy", 2, "str"); // const char *
	ADD_PARAM_NAME("strncpy", 3, "n"); // size_t
	ADD_PARAM_NAME("strpbrk", 1, "str"); // const char *
	ADD_PARAM_NAME("strpbrk", 2, "accept"); // const char *
	ADD_PARAM_NAME("strrchr", 1, "str"); // const char *
	ADD_PARAM_NAME("strrchr", 2, "c"); // int
	ADD_PARAM_NAME("strspn", 1, "str"); // const char *
	ADD_PARAM_NAME("strspn", 2, "accept"); // const char *
	ADD_PARAM_NAME("strstr", 1, "str"); // const char *
	ADD_PARAM_NAME("strstr", 2, "str"); // const char *
	ADD_PARAM_NAME("strtok", 1, "str"); // char *
	ADD_PARAM_NAME("strtok", 2, "delim"); // const char *
	ADD_PARAM_NAME("strxfrm", 1, "str"); // char *
	ADD_PARAM_NAME("strxfrm", 2, "str"); // const char *
	ADD_PARAM_NAME("strxfrm", 3, "n"); // size_t

	//
	// time.h
	//
	ADD_PARAM_NAME("asctime", 1, "tm"); // const struct tm *
	ADD_PARAM_NAME("ctime", 1, "timep"); // const time_t *
	ADD_PARAM_NAME("difftime", 1, "time1"); // time_t
	ADD_PARAM_NAME("difftime", 2, "time0"); // time_t
	ADD_PARAM_NAME("gmtime", 1, "timep"); // const time_t *
	ADD_PARAM_NAME("localtime", 1, "timep"); // const time_t *
	ADD_PARAM_NAME("mktime", 1, "tm"); // struct tm *
	ADD_PARAM_NAME("strftime", 1, "str"); // char *
	ADD_PARAM_NAME("strftime", 2, "max"); // size_t
	ADD_PARAM_NAME("strftime", 3, "format"); // const char *
	ADD_PARAM_NAME("strftime", 4, "tm"); // const struct tm *
	ADD_PARAM_NAME("time", 1, "t"); // time_t *

	//
	// wchar.h
	//
	ADD_PARAM_NAME("btowc", 1, "wc"); // int
	ADD_PARAM_NAME("fgetws", 1, "wstr"); // wchar_t *
	ADD_PARAM_NAME("fgetws", 2, "n"); // int
	ADD_PARAM_NAME("fgetws", 3, "stream"); // FILE *
	ADD_PARAM_NAME("fputws", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("fputws", 2, "stream"); // FILE *
	ADD_PARAM_NAME("fwide", 1, "stream"); // FILE *
	ADD_PARAM_NAME("fwide", 2, "mode"); // int
	ADD_PARAM_NAME("mbrlen", 1, "wstr"); // const char *
	ADD_PARAM_NAME("mbrlen", 2, "n"); // size_t
	ADD_PARAM_NAME("mbrlen", 3, "ps"); // mbstate_t *
	ADD_PARAM_NAME("mbrtowc", 1, "pwc"); // wchar_t *
	ADD_PARAM_NAME("mbrtowc", 2, "wstr"); // const char *
	ADD_PARAM_NAME("mbrtowc", 3, "n"); // size_t
	ADD_PARAM_NAME("mbrtowc", 4, "ps"); // mbstate_t *
	ADD_PARAM_NAME("mbsinit", 1, "ps"); // const mbstate_t *
	ADD_PARAM_NAME("mbsrtowcs", 1, "wstr"); // wchar_t *
	ADD_PARAM_NAME("mbsrtowcs", 2, "wstr"); // const char * *
	ADD_PARAM_NAME("mbsrtowcs", 3, "len"); // size_t
	ADD_PARAM_NAME("mbsrtowcs", 4, "ps"); // mbstate_t *
	ADD_PARAM_NAME("putwchar", 1, "wc"); // wchar_t
	ADD_PARAM_NAME("ungetwc", 1, "wc"); // wint_t
	ADD_PARAM_NAME("ungetwc", 2, "stream"); // FILE *
	ADD_PARAM_NAME("wcrtomb", 1, "wstr"); // char *
	ADD_PARAM_NAME("wcrtomb", 2, "wc"); // wchar_t
	ADD_PARAM_NAME("wcrtomb", 3, "ps"); // mbstate_t *
	ADD_PARAM_NAME("wcscat", 1, "wstr"); // wchar_t *
	ADD_PARAM_NAME("wcscat", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcschr", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcschr", 2, "wc"); // wchar_t
	ADD_PARAM_NAME("wcscmp", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcscmp", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcscoll", 1, "ws1"); // const wchar_t *
	ADD_PARAM_NAME("wcscoll", 2, "ws2"); // const wchar_t *
	ADD_PARAM_NAME("wcscpy", 1, "wstr"); // wchar_t *
	ADD_PARAM_NAME("wcscpy", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcscspn", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcscspn", 2, "reject"); // const wchar_t *
	ADD_PARAM_NAME("wcsftime", 1, "wstr"); // wchar_t * restrict
	ADD_PARAM_NAME("wcsftime", 2, "maxsize"); // size_t
	ADD_PARAM_NAME("wcsftime", 3, "format"); // const wchar_t * restrict
	ADD_PARAM_NAME("wcsftime", 4, "timeptr"); // const struct tm * restrict
	ADD_PARAM_NAME("wcslen", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcsncat", 1, "wstr"); // wchar_t *
	ADD_PARAM_NAME("wcsncat", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcsncat", 3, "n"); // size_t
	ADD_PARAM_NAME("wcsncmp", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcsncmp", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcsncmp", 3, "n"); // size_t
	ADD_PARAM_NAME("wcsncpy", 1, "wstr"); // wchar_t *
	ADD_PARAM_NAME("wcsncpy", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcsncpy", 3, "n"); // size_t
	ADD_PARAM_NAME("wcspbrk", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcspbrk", 2, "accept"); // const wchar_t *
	ADD_PARAM_NAME("wcsrchr", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcsrchr", 2, "wc"); // wchar_t
	ADD_PARAM_NAME("wcsrtombs", 1, "wstr"); // char *
	ADD_PARAM_NAME("wcsrtombs", 2, "wstr"); // const wchar_t * *
	ADD_PARAM_NAME("wcsrtombs", 3, "len"); // size_t
	ADD_PARAM_NAME("wcsrtombs", 4, "ps"); // mbstate_t *
	ADD_PARAM_NAME("wcsspn", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wcsspn", 2, "accept"); // const wchar_t *
	ADD_PARAM_NAME("wcsstr", 1, "haystack"); // const wchar_t *
	ADD_PARAM_NAME("wcsstr", 2, "needle"); // const wchar_t *
	ADD_PARAM_NAME("wcstod", 1, "wstr"); // const wchar_t * restrict
	ADD_PARAM_NAME("wcstod", 2, "wendptr"); // wchar_t * * restrict
	ADD_PARAM_NAME("wcstof", 1, "wstr"); // const wchar_t * restrict
	ADD_PARAM_NAME("wcstof", 2, "wendptr"); // wchar_t * * restrict
	ADD_PARAM_NAME("wcstok", 1, "wstr"); // wchar_t *
	ADD_PARAM_NAME("wcstok", 2, "delim"); // const wchar_t *
	ADD_PARAM_NAME("wcstok", 3, "ptr"); // wchar_t * *
	ADD_PARAM_NAME("wcstol", 1, "wstr"); // const wchar_t * restrict
	ADD_PARAM_NAME("wcstol", 2, "wendptr"); // wchar_t * * restrict
	ADD_PARAM_NAME("wcstol", 3, "base"); // int
	ADD_PARAM_NAME("wcstold", 1, "wstr"); // const wchar_t * restrict
	ADD_PARAM_NAME("wcstold", 2, "wendptr"); // wchar_t * * restrict
	ADD_PARAM_NAME("wcstoll", 1, "wstr"); // const wchar_t * restrict
	ADD_PARAM_NAME("wcstoll", 2, "wendptr"); // wchar_t * * restrict
	ADD_PARAM_NAME("wcstoll", 3, "base"); // int
	ADD_PARAM_NAME("wcstoul", 1, "wstr"); // const wchar_t * restrict
	ADD_PARAM_NAME("wcstoul", 2, "wendptr"); // wchar_t * * restrict
	ADD_PARAM_NAME("wcstoul", 3, "base"); // int
	ADD_PARAM_NAME("wcstoull", 1, "wstr"); // const wchar_t * restrict
	ADD_PARAM_NAME("wcstoull", 2, "wendptr"); // wchar_t * * restrict
	ADD_PARAM_NAME("wcstoull", 3, "base"); // int
	ADD_PARAM_NAME("wcsxfrm", 1, "ws1"); // wchar_t * restrict
	ADD_PARAM_NAME("wcsxfrm", 2, "ws2"); // const wchar_t * restrict
	ADD_PARAM_NAME("wcsxfrm", 3, "n"); // size_t
	ADD_PARAM_NAME("wctob", 1, "c"); // wint_t
	ADD_PARAM_NAME("wmemchr", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wmemchr", 2, "c"); // wchar_t
	ADD_PARAM_NAME("wmemchr", 3, "n"); // size_t
	ADD_PARAM_NAME("wmemcmp", 1, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wmemcmp", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wmemcmp", 3, "n"); // size_t
	ADD_PARAM_NAME("wmemcpy", 1, "wstr"); // wchar_t *
	ADD_PARAM_NAME("wmemcpy", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wmemcpy", 3, "n"); // size_t
	ADD_PARAM_NAME("wmemmove", 1, "wstr"); // wchar_t *
	ADD_PARAM_NAME("wmemmove", 2, "wstr"); // const wchar_t *
	ADD_PARAM_NAME("wmemmove", 3, "n"); // size_t
	ADD_PARAM_NAME("wmemset", 1, "wstr"); // wchar_t *
	ADD_PARAM_NAME("wmemset", 2, "wc"); // wchar_t
	ADD_PARAM_NAME("wmemset", 3, "n"); // size_t

	//
	// wctype.h
	//
	ADD_PARAM_NAME("iswalnum", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswalpha", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswblank", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswcntrl", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswctype", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswctype", 2, "desc"); // wctype_t
	ADD_PARAM_NAME("iswdigit", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswgraph", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswlower", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswprint", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswpunct", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswspace", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswupper", 1, "wc"); // wint_t
	ADD_PARAM_NAME("iswxdigit", 1, "wc"); // wint_t
	ADD_PARAM_NAME("towctrans", 1, "wc"); // wint_t
	ADD_PARAM_NAME("towctrans", 2, "desc"); // wctrans_t
	ADD_PARAM_NAME("towlower", 1, "wc"); // wint_t
	ADD_PARAM_NAME("towupper", 1, "wc"); // wint_t
	ADD_PARAM_NAME("wctrans", 1, "name"); // const char *
	ADD_PARAM_NAME("wctype", 1, "name"); // const char *

	return funcParamNamesMap;
}

/// Mapping of function parameter positions into the names of parameters.
const FuncParamNamesMap &FUNC_PARAM_NAMES_MAP(initFuncParamNamesMap());

} // anonymous namespace

/**
* @brief Implements getNameOfParam() for LibcSemantics.
*
* See its description for more details.
*/
Maybe<std::string> getNameOfParam(const std::string &funcName,
		unsigned paramPos) {
	return getNameOfParamFromMap(funcName, paramPos, FUNC_PARAM_NAMES_MAP);
}

} // namespace libc
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
