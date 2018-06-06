/**
 * @file src/bin2llvmir/optimizations/dump_module/dump_module.cpp
 * @brief An utility debug pass that dumps the module into a file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/optimizations/dump_module/dump_module.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/utils/debug.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char DumpModule::ID = 0;

static RegisterPass<DumpModule> X(
		"dump-module",
		"Module to LLVM IR file dumper",
		 false, // Only looks at CFG
		 false // Analysis Pass
);

DumpModule::DumpModule() :
		ModulePass(ID)
{

}

bool DumpModule::runOnModule(Module& M)
{
	auto* c = ConfigProvider::getConfig(&M);
	dumpModuleToFile(&M, c->getOutputDirectory());
	return false;
}

} // namespace bin2llvmir
} // namespace retdec
