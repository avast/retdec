/**
 * @file src/bin2llvmir/optimizations/provider_init/provider_init.cpp
 * @brief One time providers initialization.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/Support/CommandLine.h>

#include "retdec/bin2llvmir/optimizations/provider_init/provider_init.h"
#include "retdec/bin2llvmir/analyses/symbolic_tree.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/debugformat.h"
#include "retdec/bin2llvmir/providers/demangler.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/providers/lti.h"
#include "retdec/bin2llvmir/providers/names.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char ProviderInitialization::ID = 0;

static RegisterPass<ProviderInitialization> X(
		"provider-init",
		"Providers initialization",
		 false, // Only looks at CFG
		 false // Analysis Pass
);

cl::opt<std::string> ConfigPath(
		"config-path",
		cl::desc("Path to the config file."),
		cl::init("")
);

ProviderInitialization::ProviderInitialization() :
		ModulePass(ID)
{

}

/**
 * @return Always @c false -- this pass does not modify module.
 */
bool ProviderInitialization::runOnModule(Module& m)
{
	static bool firstRun = true;
	std::string confPath = ConfigPath;
	if (!firstRun || confPath.empty())
	{
		return false;
	}

	auto* c = ConfigProvider::addConfigFile(&m, confPath);
	if (c == nullptr)
	{
		return false;
	}

	auto* abi = AbiProvider::addAbi(&m, c);
	SymbolicTree::setAbi(abi);
	SymbolicTree::setConfig(c);

	auto* d = DemanglerProvider::addDemangler(&m, c->getConfig().tools);
	if (d == nullptr)
	{
		return false;
	}

	auto* f = FileImageProvider::addFileImage(
			&m,
			c->getConfig().getInputFile(),
			c);
	if (f == nullptr)
	{
		return false;
	}

	auto* debug = DebugFormatProvider::addDebugFormat(
			&m,
			f->getImage(),
			c->getConfig().getPdbInputFile(),
			c->getConfig().getImageBase(),
			d);

	auto* lti = LtiProvider::addLti(&m, c, f->getImage());

	NamesProvider::addNames(&m, c, debug, f, d, lti);

	AsmInstruction::clear();

	firstRun = false;

	return false;
}

/**
 * @return Always @c false -- this pass does not modify module.
 */
bool ProviderInitialization::doFinalization(Module& m)
{
	ConfigProvider::doFinalization(&m);
	return false;
}

} // namespace bin2llvmir
} // namespace retdec
