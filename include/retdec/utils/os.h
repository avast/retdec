/**
* @file include/retdec/utils/os.h
* @brief OS-related macros.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_UTILS_OS_H
#define RETDEC_UTILS_OS_H

// Obtain the used operating system. Currently, we only distinguish between
// Windows, macOS, and Linux.
#if defined(__WIN) || defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
	#define OS_WINDOWS
#elif defined(__APPLE__)
	#define OS_MACOS
#else
	#define OS_LINUX
#endif

// It is also useful to know whether the operating system is POSIX compliant.
#if defined(OS_MACOS) || defined(OS_LINUX)
	#define OS_POSIX
#endif

#endif
