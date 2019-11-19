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
#include <llvm/IR/CFG.h>
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
#include "retdec/bin2llvmir/providers/asm_instruction.h"
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

common::BasicBlock fillBasicBlock(
		bin2llvmir::Config* config,
		llvm::BasicBlock& bb,
		llvm::BasicBlock& bbEnd)
{
	common::BasicBlock ret;

	ret.setStartEnd(
		bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(&bb),
		bin2llvmir::AsmInstruction::getBasicBlockEndAddress(&bbEnd)
	);

	for (auto pit = pred_begin(&bb), e = pred_end(&bb); pit != e; ++pit)
	{
		// Find BB with address - there should always be some.
		// Some BBs may not have addresses - e.g. those inside
		// if-then-else instruction models.
		auto* pred = *pit;
		auto start = bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(pred);
		while (start.isUndefined())
		{
			pred = pred->getPrevNode();
			assert(pred);
			start = bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(pred);
		}
		ret.preds.insert(start);
	}

	for (auto sit = succ_begin(&bbEnd), e = succ_end(&bbEnd); sit != e; ++sit)
	{
		// Find BB with address - there should always be some.
		// Some BBs may not have addresses - e.g. those inside
		// if-then-else instruction models.
		auto* succ = *sit;
		auto start = bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(succ);
		while (start.isUndefined())
		{
			succ = succ->getPrevNode();
			assert(succ);
			start = bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(succ);
		}
		ret.succs.insert(start);
	}
	// MIPS likely delays slot hack - recognize generated pattern and
	// find all sucessors.
	// Also applicable to ARM cond call/return patterns, and other cases.
	if (bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(&bbEnd).isUndefined() // no addr
			&& (++pred_begin(&bbEnd)) == pred_end(&bbEnd) // single pred
			&& bbEnd.getPrevNode() == *pred_begin(&bbEnd)) // pred right before
	{
		auto* br = llvm::dyn_cast<llvm::BranchInst>(
				(*pred_begin(&bbEnd))->getTerminator());
		if (br
				&& br->isConditional()
				&& br->getSuccessor(0) == &bbEnd
				&& bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(
						br->getSuccessor(1)))
		{
			ret.succs.insert(
					bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(
							br->getSuccessor(1)));
		}
	}

	auto* nextBb = bbEnd.getNextNode(); // may be nullptr
	for (auto ai = bin2llvmir::AsmInstruction(&bb);
			ai.isValid() && ai.getBasicBlock() != nextBb;
			ai = ai.getNext())
	{
		ret.instructions.push_back(ai.getCapstoneInsn());

		for (auto& i : ai)
		{
			auto call = llvm::dyn_cast<llvm::CallInst>(&i);
			if (call && call->getCalledFunction())
			{
				auto cf = call->getCalledFunction();
				auto target = bin2llvmir::AsmInstruction::getFunctionAddress(cf);
				if (target.isUndefined())
				{
					target = config->getFunctionAddress(cf);
				}
				if (target.isDefined())
				{
					auto src = ai.getAddress();
					// MIPS hack: there are delay slots on MIPS, calls/branches
					// are placed at the end of the next instruction (delay slot)
					// we need to modify reference address.
					// This assums that all references on MIPS have delays slots of
					// 4 bytes, and therefore need to be fixed, it it is not the
					// case, it will cause problems.
					//
					if (config->getConfig().architecture.isMipsOrPic32())
					{
						src -= 4;
					}

					ret.calls.emplace(
							common::BasicBlock::CallEntry{src, target});
				}
			}
		}
	}

	return ret;
}

common::Function fillFunction(
		bin2llvmir::Config* config,
		llvm::Function& f)
{
	common::Function ret(
			bin2llvmir::AsmInstruction::getFunctionAddress(&f),
			bin2llvmir::AsmInstruction::getFunctionEndAddress(&f),
			f.getName()
	);

	for (llvm::BasicBlock& bb : f)
	{
		// There are more BBs in LLVM IR than we created in control-flow
		// decoding - e.g. BBs inside instructions that behave like
		// if-then-else created by capstone2llvmir.
		if (bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(&bb).isUndefined())
		{
			continue;
		}

		llvm::BasicBlock* bbEnd = &bb;
		while (bbEnd->getNextNode())
		{
			// Next has address -- is a proper BB.
			//
			if (bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(
					bbEnd->getNextNode()).isDefined())
			{
				break;
			}
			else
			{
				bbEnd = bbEnd->getNextNode();
			}
		}

		ret.basicBlocks.emplace(
				fillBasicBlock(config, bb, *bbEnd));
	}

	for (auto* u : f.users())
	{
		if (auto* i = llvm::dyn_cast<llvm::Instruction>(u))
		{
			if (auto ai = bin2llvmir::AsmInstruction(i))
			{
				auto addr = ai.getAddress();
				// MIPS hack: there are delay slots on MIPS, calls/branches
				// are placed at the end of the next instruction (delay slot)
				// we need to modify reference address.
				// This assums that all references on MIPS have delays slots of
				// 4 bytes, and therefore need to be fixed, it it is not the
				// case, it will cause problems.
				//
				if (config->getConfig().architecture.isMipsOrPic32())
				{
					addr -= 4;
				}
				ret.codeReferences.insert(addr);
			}
		}
	}

	return ret;
}

void fillFunctions(
		llvm::Module& module,
		retdec::common::FunctionSet* fs)
{
	if (fs == nullptr)
	{
		return;
	}

	auto* config = bin2llvmir::ConfigProvider::getConfig(&module);
	if (config == nullptr)
	{
		return;
	}

	for (llvm::Function& f : module.functions())
	{
		if (f.isDeclaration()
			|| f.empty()
			|| bin2llvmir::AsmInstruction::getFunctionAddress(&f).isUndefined())
		{
			auto sa = config->getFunctionAddress(&f);
			if (sa.isDefined())
			{
				fs->emplace(common::Function(sa, sa, f.getName()));
			}
			continue;
		}

		fs->emplace(fillFunction(config, f));
	}
}

LlvmModuleContextPair disassemble(
		const std::string& inputPath,
		retdec::common::FunctionSet* fs)
{
	auto context = std::make_unique<llvm::LLVMContext>();
	auto module = createLlvmModule(*context);

	config::Config c;
	c.setInputFile(inputPath);

	// Create a PassManager to hold and optimize the collection of passes we
	// are about to build.
	llvm::legacy::PassManager pm;

	pm.add(new bin2llvmir::ProviderInitialization(&c));
	pm.add(new bin2llvmir::Decoder());

	// Now that we have all of the passes ready, run them.
	pm.run(*module);

	fillFunctions(*module, fs);

	return LlvmModuleContextPair{std::move(module), std::move(context)};
}

} // namespace retdec
