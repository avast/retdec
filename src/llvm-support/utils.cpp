/**
 * @file src/llvm-support/utils.cpp
 * @brief LLVM Utility functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/Casting.h>

#include "retdec/llvm-support/utils.h"

namespace retdec {
namespace llvm_support {

/**
 * We need special function for @c Module printing because
 * its @c print method takes one more parameter.
 * @param t Module to print.
 * @return String with printed module.
 */
std::string llvmObjToString(const llvm::Module* t)
{
	std::string str;
	llvm::raw_string_ostream ss(str);
	if (t)
		t->print(ss, nullptr);
	else
		ss << "nullptr";
	return ss.str();
}
std::string llvmObjToString(const llvm::Module& t)
{
	return llvmObjToString(&t);
}

void dumpModuleToFile(const llvm::Module* m, const std::string fileName)
{
	static unsigned cntr = 0;
	std::string n = fileName.empty()
			? "dump_" + std::to_string(cntr++) + ".ll"
			: fileName;

	std::ofstream myfile(n);
	myfile << llvmObjToString(m) << std::endl;
}

/**
 * Skips both casts and getelementptr instructions and constant expressions.
 */
llvm::Value* skipCasts(llvm::Value* val)
{
	while (true)
	{
		if (auto* c = llvm::dyn_cast_or_null<llvm::CastInst>(val))
		{
			val = c->getOperand(0);
		}
		else if (auto* p = llvm::dyn_cast_or_null<llvm::GetElementPtrInst>(val))
		{
			val = p->getOperand(0);
		}
		else if (auto* ce = llvm::dyn_cast_or_null<llvm::ConstantExpr>(val))
		{
			if (ce->isCast()
					|| ce->getOpcode() == llvm::Instruction::GetElementPtr)
			{
				val = ce->getOperand(0);
			}
			else
			{
				return val;
			}
		}
		else
		{
			return val;
		}
	}

	return val;
}

} // namespace llvm_support
} // namespace retdec
