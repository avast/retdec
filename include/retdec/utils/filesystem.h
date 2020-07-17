/**
 * @file include/retdec/utils/filesystem.h
 * @brief Wrapper for conditional include of C++17 filesystem feature.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UTILS_FILESYSTEM_H
#define RETDEC_UTILS_FILESYSTEM_H

#if __has_include(<filesystem>)
	#include <filesystem>
	namespace fs = std::filesystem;

#elif __has_include(<experimental/filesystem>)
	#include <experimental/filesystem>
	namespace fs = std::experimental::filesystem;

#else
	#error "Compiler does not have C++17 filesystem feature."

#endif

#endif
