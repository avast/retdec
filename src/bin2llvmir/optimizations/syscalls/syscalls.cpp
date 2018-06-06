/**
 * @file src/bin2llvmir/optimizations/syscalls/syscalls.cpp
 * @brief Implement syscall identification and fixing pass @c SyscallFixer.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/optimizations/syscalls/syscalls.h"
#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"

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
	_abi = AbiProvider::getAbi(_module);
	return run();
}

bool SyscallFixer::runOnModuleCustom(
		llvm::Module& M,
		Config* c,
		FileImage* img,
		Lti* lti,
		Abi* abi)
{
	_module = &M;
	_config = c;
	_image = img;
	_lti = lti;
	_abi = abi;
	return run();
}

bool SyscallFixer::run()
{
	if (_config == nullptr)
	{
		return false;
	}

	if (_config->getConfig().architecture.isMipsOrPic32())
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

bool SyscallFixer::transform(
		AsmInstruction ai,
		uint64_t code,
		const std::map<uint64_t, std::string>& codeMap)
{
	// Find syscall name.
	//
	auto fit = codeMap.find(code);
	if (fit == codeMap.end())
	{
		LOG << "\tno syscall entry for code" << std::endl;
		return false;
	}
	std::string callName = fit->second;
	LOG << "\tfound in syscall map: " << callName << std::endl;

	// Find syscall function.
	//
	Function* lf = _module->getFunction(callName);
	if (lf == nullptr)
	{
		lf = _lti->getLlvmFunction(callName);
	}
	if (lf == nullptr)
	{
		LOG << "\tno function for name" << std::endl;
		return false;
	}
	for (Argument& a : lf->args())
	{
		if (!a.getType()->isFirstClassType())
		{
			LOG << "\tnone first class type argument" << std::endl;
			return false;
		}
	}

	if (ai.eraseInstructions())
	{
		LOG << "\tasm instruction cannot be erased" << std::endl;
	}

	if (auto* cf = _config->getConfigFunction(lf))
	{
		cf->setIsSyscall();
	}

	Instruction* next = ai.getLlvmToAsmInstruction()->getNextNode();
	if (next == nullptr)
	{
		LOG << "\tno next instruction (should not be possible)" << std::endl;
		return false;
	}

	unsigned cntr = 0;
	std::vector<Value*> args;
	for (Argument& a : lf->args())
	{
		if (auto* reg = _abi->getSyscallArgumentRegister(cntr++))
		{
			auto* l = new LoadInst(reg, "", next);
			args.push_back(IrModifier::convertValueToType(l, a.getType(), next));
		}
		else
		{
			// If it gets here, function has only first class type arguments.
			// Otherwise, this would fail to get undef value.
			args.push_back(UndefValue::get(a.getType()));
		}
	}

	auto* call = CallInst::Create(lf, args, "", next);
	LOG << "\t===> " << llvmObjToString(call) << std::endl;

	if (!lf->getReturnType()->isVoidTy())
	{
		if (auto* reg = _abi->getSyscallReturnRegister())
		{
			auto* conv = IrModifier::convertValueToType(
					call,
					reg->getType()->getElementType(),
					next);
			auto* s = new StoreInst(conv, reg, next);
			LOG << "\t===> " << llvmObjToString(s) << std::endl;
		}
	}

	return true;
}

} // namespace bin2llvmir
} // namespace retdec
