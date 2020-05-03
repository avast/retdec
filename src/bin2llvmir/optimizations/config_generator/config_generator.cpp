/**
 * @file src/bin2llvmir/optimizations/config_generator/config_generator.h
 * @brief Generate the current config.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/optimizations/config_generator/config_generator.h"
#include "retdec/bin2llvmir/providers/config.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char ConfigGenerator::ID = 0;

static RegisterPass<ConfigGenerator> X(
		"config-generator",
		"Generate the current config",
		 false, // Only looks at CFG
		 false // Analysis Pass
);

ConfigGenerator::ConfigGenerator() :
		ModulePass(ID)
{

}

bool ConfigGenerator::runOnModule(Module& M)
{
	auto* c = ConfigProvider::getConfig(&M);
	c->doFinalization();
	return false;
}

} // namespace bin2llvmir
} // namespace retdec
