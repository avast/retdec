/**
 * @file src/bin2llvmir/optimizations/syscalls/syscalls.cpp
 * @brief Implement syscall identification and fixing pass @c SyscallFixer.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/llvm-support/utils.h"
#include "retdec/bin2llvmir/optimizations/syscalls/syscalls.h"

using namespace retdec::llvm_support;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char SyscallFixer::ID = 0;

static RegisterPass<SyscallFixer> X(
		"syscalls",
		"Syscalls optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

SyscallFixer::SyscallFixer() :
		ModulePass(ID)
{

}

bool SyscallFixer::runOnModule(llvm::Module& M)
{
	_module = &M;
	_config = ConfigProvider::getConfig(_module);
	_image = FileImageProvider::getFileImage(_module);
	_lti = LtiProvider::getLti(_module);
	return run();
}

bool SyscallFixer::runOnModuleCustom(
		llvm::Module& M,
		Config* c,
		FileImage* img,
		Lti* lti)
{
	_module = &M;
	_config = c;
	_image = img;
	_lti = lti;
	return run();
}

bool SyscallFixer::run()
{
	if (_config == nullptr)
	{
		return false;
	}

	if (_config->isMipsOrPic32())
	{
		return runMips();
	}
	else if (_config->getConfig().architecture.isArmOrThumb())
	{
		return runArm();
	}
	else if (_config->getConfig().architecture.isX86_32())
	{
		return runX86();
	}
	else
	{
		return false;
	}
}

} // namespace bin2llvmir
} // namespace retdec
