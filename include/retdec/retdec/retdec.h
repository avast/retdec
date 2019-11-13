/**
 * \file include/retdec/retdec/retdec.h
 * \brief RetDec library.
 * \copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_RETDEC_RETDEC_H
#define RETDEC_RETDEC_RETDEC_H

#include <capstone/capstone.h>
#include <llvm/IR/Module.h>

#include "retdec/common/basic_block.h"
#include "retdec/common/function.h"

namespace retdec {

/**
 * \param[in] inputPath Path the the input file to disassemble.
 * \return Pointer to LLVM module created by the disassembly,
 *         or \c nullptr if the disassembly failed.
 */
std::unique_ptr<llvm::Module> disassemble(
		const std::string& inputPath);

} // namespace retdec

#endif
