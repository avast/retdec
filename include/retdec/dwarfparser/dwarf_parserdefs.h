/**
 * @file include/retdec/dwarfparser/dwarf_parserdefs.h
 * @brief Definitions globally used in dwarfparser library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_DWARFPARSER_DWARF_PARSERDEFS_H
#define RETDEC_DWARFPARSER_DWARF_PARSERDEFS_H

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <limits>

#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

#include "retdec/utils/os.h"

#ifdef OS_WINDOWS
	#include <windows.h>
#endif

/**
 * These constants represents empty values of used data types.
 */
const std::string    EMPTY_STR      = "";
const Dwarf_Unsigned EMPTY_UNSIGNED = std::numeric_limits<Dwarf_Unsigned>::max();
const Dwarf_Signed   EMPTY_SIGNED   = std::numeric_limits<Dwarf_Signed>::max();
const Dwarf_Addr     EMPTY_ADDR     = EMPTY_UNSIGNED;
const Dwarf_Off      EMPTY_OFF      = EMPTY_UNSIGNED;

/**
 * TODO:
 * this is used to determine source section of DWARF info in some new
 * libdwarf functions
 * at the moment '.debug_info' is always used
 * implement possible use of '.debug_types' as in dwarfdump2
 */
const Dwarf_Bool is_info = true;

/**
 *
 */
const unsigned short BITS_IN_BYTE   = 8;

/**
 * @brief Variants of default DWARF registers numbers mapping initialization.
 */
enum eDefaultMap
{
	MIPS, ///<
	ARM,  ///<
	X86   ///<
};

/*
 * Debug msg printing.
 */
//#define DWARF_PARSER_RECOVERY_DEBUG
#undef DWARF_PARSER_RECOVERY_DEBUG

#ifndef OS_WINDOWS                   /* OS_WINDOWS */

const std::string DWARF_CYAN = "\33[22;36m";
const std::string DWARF_RED = "\33[22;31m";
const std::string DWARF_NOCOLOR = "\33[0m";

#ifdef DWARF_PARSER_RECOVERY_DEBUG   /* DWARF_PARSER_RECOVERY_DEBUG */

#define DWARF_ERROR(X) \
		std::cout << DWARF_RED << "Dwarfparserl Error: " << X  << " -> (" << __FILE__ << ":" << std::dec << __LINE__ << ")" << DWARF_NOCOLOR << std::endl;

#define DWARF_WARNING(X) \
		std::cout << DWARF_CYAN << "Dwarfparserl Warning: " << X  << " -> (" << __FILE__ << ":" << std::dec << __LINE__ << ")" << DWARF_NOCOLOR << std::endl;

#endif                               /* DWARF_PARSER_RECOVERY_DEBUG */

#ifndef DWARF_PARSER_RECOVERY_DEBUG  /* DWARF_PARSER_RECOVERY_DEBUG */
#define DWARF_ERROR(X) {}
#define DWARF_WARNING(X) {}
#endif                               /* DWARF_PARSER_RECOVERY_DEBUG */

#else                                /* OS_WINDOWS */

#ifdef DWARF_PARSER_RECOVERY_DEBUG   /* DWARF_PARSER_RECOVERY_DEBUG */
#define DWARF_ERROR(X) \
	{ \
		int wOldColorAttrs; \
		CONSOLE_SCREEN_BUFFER_INFO csbiInfo; \
		GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbiInfo); \
		wOldColorAttrs = csbiInfo.wAttributes; \
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_DWARF_RED | FOREGROUND_INTENSITY); \
		std::cout << "Dwarfparserl Error: " << X  << " -> (" << __FILE__ << ":" << std::dec << __LINE__ << ")" << std::endl; \
		SetConsoleTextAttribute (GetStdHandle (STD_OUTPUT_HANDLE), wOldColorAttrs);\
	}

#define DWARF_WARNING(X) \
	{ \
		int wOldColorAttrs; \
		CONSOLE_SCREEN_BUFFER_INFO csbiInfo; \
		GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbiInfo); \
		wOldColorAttrs = csbiInfo.wAttributes; \
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_INTENSITY); \
		std::cout << "Dwarfparserl Warning: " << X  << " -> (" << __FILE__ << ":" << std::dec << __LINE__ << ")" << std::endl; \
		SetConsoleTextAttribute (GetStdHandle (STD_OUTPUT_HANDLE), wOldColorAttrs); \
	}
#endif                               /* DWARF_PARSER_RECOVERY_DEBUG */

#ifndef DWARF_PARSER_RECOVERY_DEBUG  /* DWARF_PARSER_RECOVERY_DEBUG */
#define DWARF_ERROR(X) {}
#define DWARF_WARNING(X) {}
#endif                               /* DWARF_PARSER_RECOVERY_DEBUG */

#endif                               /* OS_WINDOWS */

#endif
