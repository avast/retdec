/**
 * @file src/retdec/retdec.cpp
 * @brief RetDec library.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/ADT/Triple.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/CallGraphSCCPass.h>
#include <llvm/Analysis/LoopPass.h>
#include <llvm/Analysis/RegionPass.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/TargetTransformInfo.h>
#include <llvm/Bitcode/BitcodeWriterPass.h>
#include <llvm/CodeGen/CommandFlags.inc>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/IRPrintingPasses.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LegacyPassNameParser.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/InitializePasses.h>
#include <llvm/LinkAllIR.h>
#include <llvm/MC/SubtargetFeature.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PluginLoader.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/SystemUtils.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/optimizations/provider_init/provider_init.h"
#include "retdec/bin2llvmir/providers/config.h"

#include "retdec/config/config.h"
#include "retdec/llvm-support/diagnostics.h"
#include "retdec/retdec/retdec.h"

/**
 * Create an empty input module.
 */
std::unique_ptr<llvm::Module> createLlvmModule(llvm::LLVMContext& Context)
{
	llvm::SMDiagnostic Err;

	std::string c = "; ModuleID = 'test'\nsource_filename = \"test\"\n";
	auto mb = llvm::MemoryBuffer::getMemBuffer(c);
	if (mb == nullptr)
	{
		throw std::runtime_error("failed to create llvm::MemoryBuffer");
	}
	std::unique_ptr<Module> M = parseIR(mb->getMemBufferRef(), Err, Context);
	if (M == nullptr)
	{
		throw std::runtime_error("failed to create llvm::Module");
	}

	// Immediately run the verifier to catch any problems before starting up the
	// pass pipelines. Otherwise we can crash on broken code during
	// doInitialization().
	if (verifyModule(*M, &errs()))
	{
		throw std::runtime_error("created llvm::Module is broken");
	}

	return M;
}

namespace retdec {

void hello(const std::string& inputPath)
{
	std::cout << "hello world" << std::endl;

	llvm::LLVMContext Context;
	std::unique_ptr<Module> M = createLlvmModule(Context);

	config::Config c;
	c.setInputFile(inputPath);
	c.architecture.setIsX86();
	c.architecture.setBitSize(64);
	c.fileFormat.setIsElf64();

	// Create a PassManager to hold and optimize the collection of passes we are
	// about to build.
	legacy::PassManager pm;

	pm.add(new retdec::bin2llvmir::ProviderInitialization(&c));
	pm.add(new retdec::bin2llvmir::Decoder());

std::cout << std::endl << "===========================================" << std::endl;
llvm::outs() << *M << "\n";
std::cout << std::endl << "===========================================" << std::endl;

	// Now that we have all of the passes ready, run them.
	pm.run(*M);

std::cout << std::endl << "===========================================" << std::endl;
llvm::outs() << *M << "\n";
std::cout << std::endl << "===========================================" << std::endl;

std::cout << "functions:" << std::endl;
for (auto& p : retdec::bin2llvmir::ConfigProvider::getConfig(M.get())->getConfig().functions)
{
	auto& f = p.second;
	std::cout << "\t" << f.getStart() << " @ " << f.getName() << std::endl;
}

}

} // namespace retdec
