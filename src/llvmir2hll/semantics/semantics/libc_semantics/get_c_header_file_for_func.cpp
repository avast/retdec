/**
* @file src/llvmir2hll/semantics/semantics/libc_semantics/get_c_header_file_for_func.cpp
* @brief Implementation of semantics::libc::getCHeaderFileForFunc() for
*        LibcSemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/impl_support/get_c_header_file_for_func.h"
#include "retdec/llvmir2hll/semantics/semantics/libc_semantics/get_c_header_file_for_func.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace libc {

namespace {

/**
* @brief This function is used to initialize FUNC_C_HEADER_MAP later in the
*        file.
*/
const StringStringUMap &initFuncCHeaderMap() {
	static StringStringUMap m;

	// The following list is based on
	//
	//     - http://en.wikipedia.org/wiki/C_standard_library
	//     - http://www.cplusplus.com/reference/clibrary/
	//
	// and contains header files from C89, C99, and C11. It is by all means not
	// complete, but most of the functions should be there. If you find a
	// function which is missing, please, add it.

	// assert.h
	static const char *ASSERT_H_FUNCS[] = {
		"assert",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(ASSERT_H_FUNCS, "assert.h", m);

	// complex.h
	static const char *COMPLEX_H_FUNCS[] = {
		"cabs",
		"cabsf",
		"cabsl",
		"cacos",
		"cacosf",
		"cacosh",
		"cacoshf",
		"cacoshl",
		"cacosl",
		"carg",
		"cargf",
		"cargl",
		"casin",
		"casinf",
		"casinh",
		"casinhf",
		"casinhl",
		"casinl",
		"catan",
		"catanf",
		"catanh",
		"catanhf",
		"catanhl",
		"catanl",
		"ccos",
		"ccosf",
		"ccosh",
		"ccoshf",
		"ccoshl",
		"ccosl",
		"cexp",
		"cexpf",
		"cexpl",
		"cimag",
		"cimagf",
		"cimagl",
		"clog",
		"clogf",
		"clogl",
		"conj",
		"conjf",
		"conjl",
		"cpow",
		"cpowf",
		"cpowl",
		"cproj",
		"cprojf",
		"cprojl",
		"creal",
		"crealf",
		"creall",
		"csin",
		"csinf",
		"csinh",
		"csinhf",
		"csinhl",
		"csinl",
		"csqrt",
		"csqrtf",
		"csqrtl",
		"ctan",
		"ctanf",
		"ctanh",
		"ctanhf",
		"ctanhl",
		"ctanl",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(COMPLEX_H_FUNCS, "complex.h", m);

	// ctype.h
	static const char *CTYPE_H_FUNCS[] = {
		"isalnum",
		"isalpha",
		"isblank",
		"iscntrl",
		"isdigit",
		"isgraph",
		"islower",
		"isprint",
		"ispunct",
		"isspace",
		"isupper",
		"isxdigit",
		"tolower",
		"toupper",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(CTYPE_H_FUNCS, "ctype.h", m);

	// errno.h
	// -

	// fenv.h
	static const char *FENV_H_FUNCS[] = {
		"feclearexcept",
		"fegetenv",
		"fegetexceptflag",
		"fegetround",
		"feholdexcept",
		"feraiseexcept",
		"fesetenv",
		"fesetexceptflag",
		"fesetround",
		"fetestexcept",
		"feupdateenv",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(FENV_H_FUNCS, "fenv.h", m);

	// float.h
	// -

	// inttypes.h
	static const char *INTTYPES_H_FUNCS[] = {
		"imaxabs",
		"imaxdiv",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(INTTYPES_H_FUNCS, "inttypes.h", m);

	// iso646.h
	// -

	// limits.h
	// -

	// locale.h
	static const char *LOCALE_H_FUNCS[] = {
		"localeconv",
		"setlocale",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(LOCALE_H_FUNCS, "locale.h", m);

	// math.h
	static const char *MATH_H_FUNCS[] = {
		"acos",
		"acosf",
		"acosh",
		"acoshf",
		"acoshl",
		"acosl",
		"asin",
		"asinf",
		"asinh",
		"asinhf",
		"asinhl",
		"asinl",
		"atan",
		"atan2",
		"atan2f",
		"atan2l",
		"atanf",
		"atanh",
		"atanhf",
		"atanhl",
		"atanl",
		"cbrt",
		"cbrtf",
		"cbrtl",
		"ceil",
		"ceilf",
		"ceill",
		"copysign",
		"copysignf",
		"copysignl",
		"cos",
		"cosf",
		"cosh",
		"coshf",
		"coshl",
		"cosl",
		"erf",
		"erfc",
		"erfcf",
		"erfcl",
		"erff",
		"erfl",
		"exp",
		"exp2",
		"exp2f",
		"exp2l",
		"expf",
		"expl",
		"expm1",
		"expm1f",
		"expm1l",
		"fabs",
		"fabsf",
		"fabsl",
		"fdim",
		"fdimf",
		"fdiml",
		"floor",
		"floorf",
		"floorl",
		"fma",
		"fmaf",
		"fmal",
		"fmax",
		"fmaxf",
		"fmaxl",
		"fmin",
		"fminf",
		"fminl",
		"fmod",
		"fmodf",
		"fmodl",
		"fpclassify",
		"frexp",
		"frexpf",
		"frexpl",
		"hypot",
		"hypotf",
		"hypotl",
		"ilogb",
		"ilogbf",
		"ilogbl",
		"isfinite",
		"isgreater",
		"isgreaterequal",
		"isinf",
		"isless",
		"islessequal",
		"islessgreater",
		"isnan",
		"isnormal",
		"isunordered",
		"ldexp",
		"ldexpf",
		"ldexpl",
		"lgamma",
		"lgammaf",
		"lgammal",
		"llrint",
		"llrintf",
		"llrintl",
		"llround",
		"log",
		"log10",
		"log10f",
		"log10l",
		"log1p",
		"log1pf",
		"log1pl",
		"log2",
		"log2f",
		"log2l",
		"logb",
		"logbf",
		"logbl",
		"logf",
		"logl",
		"lrint",
		"lrintf",
		"lrintl",
		"lround",
		"modf",
		"modff",
		"modfl",
		"nan",
		"nanf",
		"nanl",
		"nearbyint",
		"nearbyintf",
		"nearbyintl",
		"nextafter",
		"nextafterf",
		"nextafterl",
		"nexttoward",
		"nexttowardf",
		"nexttowardl",
		"pow",
		"powf",
		"powl",
		"remainder",
		"remainderf",
		"remainderl",
		"remquo",
		"remquof",
		"remquol",
		"rint",
		"rintf",
		"rintl",
		"round",
		"scalbln",
		"scalblnf",
		"scalblnl",
		"scalbn",
		"scalbnf",
		"scalbnl",
		"signbit",
		"sin",
		"sinf",
		"sinh",
		"sinhf",
		"sinhl",
		"sinl",
		"sqrt",
		"sqrtf",
		"sqrtl",
		"tan",
		"tanf",
		"tanh",
		"tanhf",
		"tanhl",
		"tanl",
		"tgamma",
		"tgammaf",
		"tgammal",
		"trunc",
		"truncf",
		"truncl",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(MATH_H_FUNCS, "math.h", m);

	// setjmp.h
	static const char *SETJMP_H_FUNCS[] = {
		"setjmp",
		"longjmp",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(SETJMP_H_FUNCS, "setjmp.h", m);

	// signal.h
	static const char *SIGNAL_H_FUNCS[] = {
		"signal",
		"raise",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(SIGNAL_H_FUNCS, "signal.h", m);

	// stdalign.h
	// -

	// stdarg.h
	static const char *STDARG_H_FUNCS[] = {
		"va_start",
		"va_arg",
		"va_end",
		"va_copy",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(STDARG_H_FUNCS, "stdarg.h", m);

	// stdatomic.h
	// -

	// stdbool.h
	// -

	// stddef.h
	static const char *STDDEF_H_FUNCS[] = {
		"offsetof",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(STDDEF_H_FUNCS, "stddef.h", m);

	// stdint.h
	// -

	// stdio.h
	static const char *STDIO_H_FUNCS[] = {
		"clearerr",
		"fclose",
		"feof",
		"ferror",
		"fflush",
		"fgetc",
		"fgetpos",
		"fgets",
		"fopen",
		"fprintf",
		"fputc",
		"fputs",
		"fread",
		"freopen",
		"fscanf",
		"fseek",
		"fsetpos",
		"ftell",
		"fwrite",
		"getc",
		"getchar",
		"gets",
		"perror",
		"printf",
		"putc",
		"putchar",
		"puts",
		"remove",
		"rename",
		"rewind",
		"scanf",
		"setbuf",
		"setvbuf",
		"snprintf",
		"sprintf",
		"sscanf",
		"tmpfile",
		"tmpnam",
		"ungetc",
		"vfprintf",
		"vfscanf",
		"vprintf",
		"vscanf",
		"vsnprintf",
		"vsprintf",
		"vsscanf",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(STDIO_H_FUNCS, "stdio.h", m);

	// stdlib.h
	static const char *STDLIB_H_FUNCS[] = {
		"_Exit",
		"abort",
		"abs",
		"at_quick_exit",
		"atexit",
		"atof",
		"atoi",
		"atol",
		"atoll",
		"bsearch",
		"calloc",
		"div",
		"exit",
		"free",
		"getenv",
		"labs",
		"ldiv",
		"llabs",
		"lldiv",
		"malloc",
		"qsort",
		"quick_exit",
		"rand",
		"realloc",
		"srand",
		"strtod",
		"strtof",
		"strtol",
		"strtold",
		"strtoll",
		"strtoul",
		"strtoull",
		"system",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(STDLIB_H_FUNCS, "stdlib.h", m);

	// stdnoreturn.h
	// -

	// string.h
	static const char *STRING_H_FUNCS[] = {
		"memchr",
		"memcmp",
		"memcpy",
		"memmove",
		"memset",
		"strcat",
		"strchr",
		"strcmp",
		"strcoll",
		"strcpy",
		"strcspn",
		"strerror",
		"strlen",
		"strncat",
		"strncmp",
		"strncpy",
		"strpbrk",
		"strrchr",
		"strspn",
		"strstr",
		"strtok",
		"strxfrm",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(STRING_H_FUNCS, "string.h", m);

	// tgmath.h
	// -

	// threads.h
	// -

	// time.h
	static const char *TIME_H_FUNCS[] = {
		"difftime",
		"time",
		"clock",
		"asctime",
		"ctime",
		"strftime",
		"gmtime",
		"localtime",
		"mktime",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(TIME_H_FUNCS, "time.h", m);

	// wchar.h
	static const char *WCHAR_H_FUNCS[] = {
		"btowc",
		"fgetwc",
		"fgetws",
		"fputwc",
		"fputws",
		"fwide",
		"fwprintf",
		"fwscanf",
		"getwc",
		"getwchar",
		"mbrlen",
		"mbrtowc",
		"mbsinit",
		"mbsrtowcs",
		"putwc",
		"putwchar",
		"swprintf",
		"swscanf",
		"ungetwc",
		"vfwprintf",
		"vfwscanf",
		"vswprintf",
		"vswscanf",
		"vwprintf",
		"vwscanf",
		"wcrtomb",
		"wcscat",
		"wcschr",
		"wcscmp",
		"wcscoll",
		"wcscpy",
		"wcscspn",
		"wcsftime",
		"wcslen",
		"wcsncat",
		"wcsncmp",
		"wcsncpy",
		"wcspbrk",
		"wcsrchr",
		"wcsrtombs",
		"wcsspn",
		"wcsstr",
		"wcstod",
		"wcstof",
		"wcstok",
		"wcstol",
		"wcstold",
		"wcstoll",
		"wcstoul",
		"wcstoull",
		"wcsxfrm",
		"wctob",
		"wmemchr",
		"wmemcmp",
		"wmemcpy",
		"wmemmove",
		"wmemset",
		"wprintf",
		"wscanf",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(WCHAR_H_FUNCS, "wchar.h", m);

	// wctype.h
	static const char *WCTYPE_H_FUNCS[] = {
		"iswalnum",
		"iswalpha",
		"iswblank",
		"iswcntrl",
		"iswctype",
		"iswdigit",
		"iswgraph",
		"iswlower",
		"iswprint",
		"iswpunct",
		"iswspace",
		"iswupper",
		"iswxdigit",
		"towctrans",
		"towlower",
		"towupper",
		"wctrans",
		"wctype",
	};
	ADD_FUNCS_TO_C_HEADER_MAP(WCTYPE_H_FUNCS, "wctype.h", m);

	return m;
}

/// Mapping of function names to their corresponding header files.
const StringStringUMap &FUNC_C_HEADER_MAP(initFuncCHeaderMap());

} // anonymous namespace

/**
* @brief Implements getCHeaderFileForFunc() for LibcSemantics.
*
* See its description for more details.
*/
Maybe<std::string> getCHeaderFileForFunc(const std::string &funcName) {
	return getCHeaderFileForFuncFromMap(funcName, FUNC_C_HEADER_MAP);
}

} // namespace libc
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
