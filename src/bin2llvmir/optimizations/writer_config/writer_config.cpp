/**
 * @file src/bin2llvmir/optimizations/writer_config/writer_config.cpp
 * @brief Generate the current config.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/optimizations/writer_config/writer_config.h"
#include "retdec/bin2llvmir/providers/config.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char ConfigWriter::ID = 0;

static RegisterPass<ConfigWriter> X(
		"retdec-write-config",
		"Generate the current config",
		 false, // Only looks at CFG
		 false // Analysis Pass
);

ConfigWriter::ConfigWriter() :
		ModulePass(ID)
{

}

bool ConfigWriter::runOnModule(Module& M)
{
	auto* c = ConfigProvider::getConfig(&M);
	c->doFinalization();
	return false;
}

} // namespace bin2llvmir
} // namespace retdec
