/**
 * @file src/bin2llvmir/optimizations/x86_addr_spaces/x86_addr_spaces_pass.cpp
 * @brief x86 address spaces optimization pass.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/InstIterator.h>

#include "retdec/bin2llvmir/optimizations/x86_addr_spaces/x86_addr_spaces_pass.h"
#include "retdec/bin2llvmir/optimizations/x86_addr_spaces/x86_addr_spaces.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char X86AddressSpacesPass::ID = 0;

static RegisterPass<X86AddressSpacesPass> X(
		"retdec-x86-addr-spaces",
		"x86 address spaces optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

X86AddressSpacesPass::X86AddressSpacesPass() :
		ModulePass(ID)
{

}

bool X86AddressSpacesPass::runOnModule(Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	return run();
}

bool X86AddressSpacesPass::runOnModuleCustom(llvm::Module& m, Config* c)
{
	_module = &m;
	_config = c;
	return run();
}

bool X86AddressSpacesPass::run()
{
	if (!_config->getConfig().architecture.isX86())
	{
		return false;
	}

	bool changed = false;

	for (Function& f : *_module)
	for (auto it = inst_begin(&f), eIt = inst_end(&f); it != eIt;)
	{
		Instruction* insn = &*it;
		++it;

		changed |= x86_addr_spaces::optimize(insn, _config) != nullptr;
	}

	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
