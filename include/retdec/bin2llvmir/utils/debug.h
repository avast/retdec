/**
 * @file include/retdec/bin2llvmir/utils/debug.h
 * @brief Debugging utilities.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef INCLUDE_RETDEC_BIN2LLVMIR_UTILS_DEBUG_H_
#define INCLUDE_RETDEC_BIN2LLVMIR_UTILS_DEBUG_H_

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/utils/filesystem_path.h"

namespace retdec {
namespace bin2llvmir {

/**
 * Set \c debug_enabled to \c true to enable this LOG macro.
 */
#define LOG \
	if (!debug_enabled) {} \
	else std::cout << std::showbase

/**
 * Print any LLVM object which implements @c print(llvm::raw_string_ostream&)
 * method into std::string.
 * @param t LLVM object to print.
 * @return String with printed object.
 */
template<typename T>
std::string llvmObjToString(const T* t)
{
	std::string str;
	llvm::raw_string_ostream ss(str);
	if (t)
		t->print(ss);
	else
		ss << "nullptr";
	return ss.str();
}
std::string llvmObjToString(const llvm::Module* t);

void dumpModuleToFile(
		const llvm::Module* m,
		utils::FilesystemPath dirName,
		const std::string& fileName = "");
void dumpControFlowToJson(
		llvm::Module* m,
		utils::FilesystemPath dirName,
		const std::string& fileName = "control-flow.json");

} // namespace bin2llvmir
} // namespace retdec

#endif
