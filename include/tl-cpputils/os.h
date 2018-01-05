/**
* @file include/tl-cpputils/os.h
* @brief OS-related macros.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef TL_CPPUTILS_OS_H
#define TL_CPPUTILS_OS_H

// Obtain the used operating system. Currently, we only distinguish between
// Windows and Linux.
#if defined(__WIN) || defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
	#define OS_WINDOWS
#else
	#define OS_LINUX
#endif

#endif
