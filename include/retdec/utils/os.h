/**
* @file include/retdec/utils/os.h
* @brief OS-related macros.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_UTILS_OS_H
#define RETDEC_UTILS_OS_H

// Obtain the used operating system. Currently, we only distinguish between
// Windows and UNIX.
#if defined(__WIN) || defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
	#define OS_WINDOWS
#else
	#define OS_UNIX
#endif

#endif
