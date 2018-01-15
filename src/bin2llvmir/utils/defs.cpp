/**
* @file src/bin2llvmir/utils/defs.cpp
* @brief Aliases for several useful types with LLVM IR items.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/utils/defs.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

RegisterCouple::RegisterCouple(
		llvm::GlobalVariable* reg1,
		llvm::GlobalVariable* reg2)
	:
		_reg1(reg1),
		_reg2(reg2)
{

}

bool RegisterCouple::hasFirst() const
{
	return _reg1 != nullptr;
}

bool RegisterCouple::hasSecond() const
{
	return _reg2 != nullptr;
}

llvm::GlobalVariable* RegisterCouple::getFirst() const
{
	return _reg1;
}

llvm::GlobalVariable* RegisterCouple::getSecond() const
{
	return _reg2;
}

void RegisterCouple::setFirst(llvm::GlobalVariable* reg)
{
	_reg1 = reg;
}

void RegisterCouple::setSecond(llvm::GlobalVariable* reg)
{
	_reg2 = reg;
}

} // namespace bin2llvmir
} // namespace retdec
