/**
 * @file src/bin2llvmir/optimizations/idioms/idioms.cpp
 * @brief Instruction idioms analysis
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include "retdec/bin2llvmir/optimizations/idioms/idioms.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_borland.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_common.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_gcc.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_intel.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_llvm.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_owatcom.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_vstudio.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

struct GlobalOpt;

char Idioms::ID = 0;
RegisterPass<Idioms> IdiomsRegistered(
		"idioms",
		"Instruction idioms optimization",
		false,
		false);

/**
 * Constructor
 */
Idioms::Idioms(): FunctionPass(ID) {
	m_idioms = nullptr;
}

/**
 * Destructor
 */
Idioms::~Idioms() {
}

/**
 * Inalization method called on every module
 *
 * @param M module
 * @return always true
 */
bool Idioms::doInitialization(Module &M) {
	return true;
}

/**
 * Finalization method called on every module
 *
 * @param M module
 * @return always true
 */
bool Idioms::doFinalization(Module &M) {
	delete m_idioms;

	return true;
}

/**
 * Instruction idioms analysis
 *
 * @return true if an exchange was made
 */
bool Idioms::runOnFunction(Function & f) {

	m_config = ConfigProvider::getConfig(f.getParent());

	if (!m_idioms)
		m_idioms = getCompilerAnalysis( *f.getParent() );

	/*
	 * Delegate to reflect architecture and compiler used.
	 */
	return m_idioms->doAnalysis(f, this);
}

/**
 * Get instance of idioms collection used depending on compiler
 *
 * @param M Module used
 * @return idioms collection
 *
 * TODO matula: Idiom analysis still has its own architecture and compiler representations.
 * It could/should use the representations from retdec::config.
 */
IdiomsAnalysis * Idioms::getCompilerAnalysis(Module &M)
{
	CC_arch i_arch = ARCH_ANY;
	CC_compiler i_cc = CC_ANY;

	if (m_config)
	{
		auto& conf = m_config->getConfig();

		// determinate architecture from metadata
		if (conf.architecture.isMips())
			i_arch = ARCH_MIPS;
		else if (conf.architecture.isPpc())
			i_arch = ARCH_POWERPC;
		else if (conf.architecture.isArm())
			i_arch = ARCH_ARM;
		else if (conf.architecture.isThumb())
			i_arch = ARCH_THUMB;
		else if (conf.architecture.isX86())
			i_arch = ARCH_x86;
		else
			i_arch = ARCH_ANY;

		// determinate compiler from metadata
		if (conf.tools.isBorland())
			i_cc = CC_Borland;
		else if (conf.tools.isGcc())
			i_cc = CC_GCC;
		else if (conf.tools.isIntel())
			i_cc = CC_Intel;
		else if (conf.tools.isLlvm())
			i_cc = CC_LLVM;
		else if (conf.tools.isWatcom())
			i_cc = CC_OWatcom;
		else if (conf.tools.isMsvc())
			i_cc = CC_VStudio;
		else
			i_cc = CC_ANY;
	}

	// Return initialized instruction idioms analyser.
	return new IdiomsAnalysis(&M, i_cc, i_arch);
}

} // namespace bin2llvmir
} // namespace retdec
