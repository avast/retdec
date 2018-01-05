/**
 * @file src/bin2llvmir/optimizations/dump_module/dump_module.cpp
 * @brief This is a utility debug pass that only dumps the module into LLVM IR.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/llvm-support/utils.h"
#include "retdec/bin2llvmir/optimizations/dump_module/dump_module.h"

using namespace retdec::llvm_support;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char DumpModule::ID = 0;

static RegisterPass<DumpModule> X(
		"dump-module",
		"Module to LLVM IR file dumping",
		 false, // Only looks at CFG
		 false // Analysis Pass
);

DumpModule::DumpModule() :
		ModulePass(ID)
{

}

bool DumpModule::runOnModule(Module& M)
{
	dumpModuleToFile(&M);
	return false;
}

} // namespace bin2llvmir
} // namespace retdec
