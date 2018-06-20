/**
* @file src/bin2llvmir/optimizations/decoder/decoder.cpp
* @brief Decode input binary into LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <json/json.h>

#include <llvm/IR/Dominators.h>
#include <llvm/IR/PatternMatch.h>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/bin2llvmir/utils/capstone.h"

using namespace retdec::utils;
using namespace retdec::capstone2llvmir;
using namespace llvm;
using namespace llvm::PatternMatch;
using namespace retdec::fileformat;

namespace retdec {
namespace bin2llvmir {

char Decoder::ID = 0;

static RegisterPass<Decoder> X(
		"decoder",
		"Input binary to LLVM IR decoding",
		false, // Only looks at CFG
		false // Analysis Pass
);

Decoder::Decoder() :
		ModulePass(ID)
{

}

Decoder::~Decoder()
{
	if (_dryCsInsn)
	{
		cs_free(_dryCsInsn, 1);
	}
}

bool Decoder::runOnModule(Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	_image = FileImageProvider::getFileImage(_module);
	_debug = DebugFormatProvider::getDebugFormat(_module);
	_names = NamesProvider::getNames(_module);
	_abi = AbiProvider::getAbi(_module);
	_llvm2capstone = &AsmInstruction::getLlvmToCapstoneInsnMap(_module);
	return runCatcher();
}

bool Decoder::runOnModuleCustom(
		llvm::Module& m,
		Config* c,
		FileImage* o,
		DebugFormat* d,
		NameContainer* n,
		Abi* a)
{
	_module = &m;
	_config = c;
	_image = o;
	_debug = d;
	_names = n;
	_abi = a;
	_llvm2capstone = &AsmInstruction::getLlvmToCapstoneInsnMap(_module);
	return runCatcher();
}

bool Decoder::runCatcher()
{
	// TODO: here, we shoudl catch only the most severe capstone2llvmir
	// problems which prevents us from using it.
	// Other problems (e.g. throws in instruction translating like unxpected
	// number of operands) should get their own special exception types
	// and should be catched lower and possibly ignored.
	//
	try
	{
		return run();
	}
	catch (const Capstone2LlvmIrBaseError& e)
	{
		LOG << "[capstone2llvmir]: " << e.what() << std::endl;
		return false;
	}
}

bool Decoder::run()
{
	if (_config == nullptr || _image == nullptr)
	{
		LOG << "[ABORT] Config or object image is not available.\n";
		return false;
	}

	initTranslator();
	initDryRunCsInstruction();
	initEnvironment();
	initRanges();
	initJumpTargets();

	LOG << _ranges << std::endl;
	LOG << _jumpTargets << std::endl;

	decode();

	if (debug_enabled)
	{
		dumpModuleToFile(_module, _config->getOutputDirectory());
	}

	resolvePseudoCalls();
	patternsRecognize();
	finalizePseudoCalls();

	if (debug_enabled)
	{
		dumpControFlowToJson(_module, _config->getOutputDirectory());
		dumpModuleToFile(_module, _config->getOutputDirectory());
	}

	initConfigFunctions();

	if (debug_enabled)
	{
		dumpModuleToFile(_module, _config->getOutputDirectory());
	}

	initializeGpReg_mips();

	return false;
}

void Decoder::decode()
{
	LOG << "\n" << "decode():" << std::endl;

	JumpTarget jt;
	while (getJumpTarget(jt))
	{
		LOG << "\t" << "processing : " << jt << std::endl;
		decodeJumpTarget(jt);
	}

	if (!_somethingDecoded)
	{
		throw std::runtime_error("No instructions were decoded");
	}
}

bool Decoder::getJumpTarget(JumpTarget& jt)
{
	if (!_jumpTargets.empty())
	{
		jt = _jumpTargets.top();
		_jumpTargets.pop();
		return true;
	}
	else if (!_ranges.primaryEmpty())
	{
		jt = JumpTarget(
				_ranges.primaryFront().getStart(),
				JumpTarget::eType::LEFTOVER,
				_c2l->getBasicMode(),
				Address());
		return true;
	}
	return false;
}

void Decoder::decodeJumpTarget(const JumpTarget& jt)
{
	const Address start = jt.getAddress();
	if (start.isUndefined())
	{
		LOG << "\t\t" << "unknown target address -> skip" << std::endl;
		return;
	}

	bool alternative = false;
	auto* range = _ranges.getPrimary(start);
	if (range == nullptr && jt.getType() < JumpTarget::eType::LEFTOVER)
	{
		range = _ranges.getAlternative(start);
		alternative = true;
	}
	if (range == nullptr)
	{
		LOG << "\t\t" << "found no range -> skip" << std::endl;
		// TODO: arm-pe-ff7e029f2539e37ee590a3cb029762b6
		_ranges.remove(start, start + 1);
		return;
	}
	LOG << "\t\t" << "found range = " << *range << std::endl;

	ByteData bytes = _image->getImage()->getRawSegmentData(start);
	if (bytes.first == nullptr)
	{
		LOG << "\t\t" << "found no data -> skip" << std::endl;
		_ranges.remove(start, start + 1);
		return;
	}

	auto toRangeEnd = range->getEnd() - start;

	bytes.second = toRangeEnd < bytes.second ? toRangeEnd : bytes.second;

	if (jt.hasSize() && jt.getSize() < bytes.second)
	{
		bytes.second = jt.getSize();
	}
	if (auto nextBbAddr = getBasicBlockAddressAfter(start))
	{
		auto sz = nextBbAddr - start;
		bytes.second = sz < bytes.second ? sz : bytes.second;
	}
	else if (auto nextFncAddr = getFunctionAddressAfter(start))
	{
		auto sz = nextFncAddr - start;
		bytes.second = sz < bytes.second ? sz : bytes.second;
	}

	bool useAlt = alternative
			&& jt.getType() > JumpTarget::eType::CONTROL_FLOW_RETURN_TARGET
			&& jt.getType() != JumpTarget::eType::ENTRY_POINT;
	bool useStrict = _ranges.isStrict() && !useAlt;

	if (jt.getType() == JumpTarget::eType::LEFTOVER
			|| useAlt)
	{
		if (auto skipSz = decodeJumpTargetDryRun(jt, bytes, useStrict))
		{
			AddressRange sr(start, start+skipSz);
			LOG << "\t\t" << "dry run failed -> skip range = " << sr
					<< std::endl;
			_ranges.remove(sr);
			return;
		}
	}

	BasicBlock* bb = getBasicBlockAtAddress(start);
	if (bb == nullptr)
	{
		if (jt.getType() != JumpTarget::eType::LEFTOVER)
		{
			LOG << "\t\t" << "found no bb for jt -> skip" << std::endl;
			return;
		}

		BasicBlock* tBb = nullptr;
		Function* tFnc = nullptr;
		getOrCreateCallTarget(start, tFnc, tBb);
		if (tFnc && !tFnc->empty())
		{
			bb = &tFnc->front();
		}
		// Function can not be split, use BB. This BB does not have predecessor,
		// which is not ideal, but it might happen.
		//
		else if (tBb)
		{
			bb = tBb;
		}
		else
		{
			return;
		}
	}
	assert(bb && bb->getTerminator());
	IRBuilder<> irb(bb->getTerminator());
	_irb = &irb;

	if (_c2l->getBasicMode() != jt.getMode())
	{
		_c2l->modifyBasicMode(jt.getMode());
		LOG << "\t\t" << "switch mode -> "
				<< (jt.getMode() == CS_MODE_THUMB ? " (thumb)" : "(arm)")
				<< std::endl;
	}

	Address addr = start;
	bool bbEnd = false;
	do
	{
		LOG << "\t\t\t" << "translating = " << addr << std::endl;

		Address oldAddr = addr;
		auto res = translate(bytes, addr, irb);

		if (res.failed() || res.llvmInsn == nullptr)
		{
			if (auto* bb = getBasicBlockAtAddress(addr))
			{
				if (bb->getParent() == irb.GetInsertBlock()->getParent()
						&& bb != irb.GetInsertBlock())
				{
					auto* br = irb.CreateBr(bb);
					assert(br->getNextNode() == br->getParent()->getTerminator());
					br->getNextNode()->eraseFromParent();
					LOG << "\t\t" << "translation ended -> reached BB @ "
							<< addr << std::endl;
				}
			}
			else
			{
				LOG << "\t\t" << "translation failed" << std::endl;
			}
			break;
		}
		_somethingDecoded = true;

		_llvm2capstone->emplace(res.llvmInsn, res.capstoneInsn);

		bbEnd |= getJumpTargetsFromInstruction(oldAddr, res, bytes.second);
		bbEnd |= instructionBreaksBasicBlock(oldAddr, res);

		handleDelaySlotTypical(addr, res, bytes, irb);
		handleDelaySlotLikely(addr, res, bytes, irb);
	}
	while (!bbEnd);

	auto end = addr > start ? addr : Address(start+1);
	_ranges.remove(start, end);
	LOG << "\t\tdecoded range = " << AddressRange(start, end) << std::endl;
}

capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne
Decoder::translate(ByteData& bytes, utils::Address& addr, llvm::IRBuilder<>& irb)
{
	auto res = _c2l->translateOne(bytes.first, bytes.second, addr, irb);

	// MIPS 64-bit mode can decompile more instructions than the 32-bit mode.
	// When 32-bit mode is used, some 32-bit instructions that IDA handles fail
	// to disassemble.
	// But we cannot always use 64-bit mode, because some other (FPU)
	// instructions are disassembled differently. Try to swtich modes only if
	// translations fails.
	//
	if (_config->getConfig().architecture.isMipsOrPic32()
			&& (_c2l->getBasicMode() & CS_MODE_MIPS32)
			&& res.failed())
	{
		_c2l->modifyBasicMode(CS_MODE_MIPS64);
		res = _c2l->translateOne(bytes.first, bytes.second, addr, irb);
		_c2l->modifyBasicMode(CS_MODE_MIPS32);
	}

	return res;
}

/**
 * Check if the given jump targets and bytes can/should be decoded.
 * \return The number of bytes to skip from decoding. If zero, then dry run was
 *         ok and decoding of this chunk can proceed. If non-zero, remove the
 *         number of bytes from ranges to decode.
 */
std::size_t Decoder::decodeJumpTargetDryRun(
		const JumpTarget& jt,
		ByteData bytes,
		bool strict)
{
	// Architecture-specific dry runs.
	//
	if (_config->getConfig().architecture.isX86())
	{
		return decodeJumpTargetDryRun_x86(jt, bytes, strict);
	}
	else if (_config->getConfig().architecture.isArmOrThumb())
	{
		return decodeJumpTargetDryRun_arm(jt, bytes, strict);
	}
	else if (_config->getConfig().architecture.isMipsOrPic32())
	{
		return decodeJumpTargetDryRun_mips(jt, bytes, strict);
	}
	else if (_config->getConfig().architecture.isPpc())
	{
		return decodeJumpTargetDryRun_ppc(jt, bytes, strict);
	}
	else
	{
		assert(false);
	}

	// Common dry run.
	//
	return false;
}

cs_mode Decoder::determineMode(cs_insn* insn, utils::Address& target)
{
	if (_config->getConfig().architecture.isArmOrThumb())
	{
		return determineMode_arm(insn, target);
	}
	else
	{
		return _c2l->getBasicMode();
	}
}

bool Decoder::instructionBreaksBasicBlock(
		utils::Address addr,
		capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& tr)
{
	// On x86 halt may get generated to end the entry point function:
	// https://stackoverflow.com/questions/5213466/why-does-gcc-place-a-halt-instruction-in-programs-after-the-call-to-main
	// The check could be stricter - nop follows, all paths to halt, etc.
	//
	if (_config->getConfig().architecture.isX86()
			&& tr.llvmInsn->getFunction() == _entryPointFunction
			&& tr.capstoneInsn->id == X86_INS_HLT)
	{
		auto* ui = new UnreachableInst(_module->getContext());
		ReplaceInstWithInst(&*_irb->GetInsertPoint(), ui);
		_irb->SetInsertPoint(ui);
		return true;
	}
	// TODO: terminating syscalls.

	return false;
}

/**
 * @return @c True if this instruction ends basic block, @c false otherwise.
 */
bool Decoder::getJumpTargetsFromInstruction(
		utils::Address addr,
		capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& tr,
		std::size_t& rangeSize)
{
	CallInst*& pCall = tr.branchCall;
	auto nextAddr = addr + tr.size;

	if (_config->getConfig().architecture.isArmOrThumb())
	{
		AsmInstruction ai(tr.llvmInsn);
		patternsPseudoCall_arm(pCall, ai);
	}

	BasicBlock* tBb = nullptr;
	Function* tFnc = nullptr;

	_switchGenerated = false;

	// Function call -> insert target (if computed).
	//
	if (_c2l->isCallFunctionCall(pCall))
	{
		auto t = getJumpTarget(addr, pCall, pCall->getArgOperand(0));
		// TOOD: sometimes we want to enable calls (and other branches) to zero.

		if (t || (t == 0 && AsmInstruction(_module, 0)))
		{
			// TODO: found in x86 macho:
			//__text:00001EE6    sub     esp, 1Ch
			//__text:00001EE9    call    $+5         (target = 0x1EEE)
			//__text:00001EEE    pop     ecx
			if (t == nextAddr)
			{
				return false;
			}
			//.text:08001EE1    call    near ptr loc_8001EE1+1
			//.text:08001EE6    cmp     ebx, esi
			if (addr < t && t < nextAddr)
			{
				return false;
			}

			auto m = determineMode(tr.capstoneInsn, t);
			getOrCreateCallTarget(t, tFnc, tBb);

			if (tFnc)
			{
				transformToCall(pCall, tFnc);
			}
			else if (tBb
					&& tBb->getParent() == pCall->getFunction()
					&& tBb->getPrevNode())
			{
				// TODO
				transformToBranch(pCall, tBb);

				_jumpTargets.push(
						t,
						JumpTarget::eType::CONTROL_FLOW_BR_TRUE,
						m,
						addr);
				LOG << "\t\t" << "call @ " << addr << " -> " << t << std::endl;
				return true;
			}
			else
			{
// TODO: defer call solution to later? after all possible branches are solved?
// often, it is possible to split function here, but later it would not be,
// possible. Then, after such split, more splits are needed for those branches
// thet would make the initial split impossible -> problem, we can not
// transform them.
//				assert(false);
				return false;
			}

			_jumpTargets.push(
					t,
					JumpTarget::eType::CONTROL_FLOW_CALL_TARGET,
					determineMode(tr.capstoneInsn, t),
					addr);
			LOG << "\t\t" << "call @ " << addr << " -> " << t << std::endl;

			// The created function might be in range that we are currently
			// decoding -> if so, trim range size.
			if (nextAddr <= t && t < nextAddr + rangeSize)
			{
				rangeSize = t - nextAddr;
			}

			if (tFnc && _terminatingFncs.count(tFnc))
			{
				auto* ui = new UnreachableInst(_module->getContext());
				ReplaceInstWithInst(&*_irb->GetInsertPoint(), ui);
				_irb->SetInsertPoint(ui);
				return true;
			}
		}
	}
	// Return -> break flow, do not try to compute target.
	//
	else if (_c2l->isReturnFunctionCall(pCall))
	{
		transformToReturn(pCall);
		if (auto* cond = _c2l->isInConditionReturnFunctionCall(pCall))
		{
			// Name the block and assign an address to it -> keep up with IDA.
			auto* nextBb = cond->getSuccessor(1);

			auto* nBb = getBasicBlockAtAddress(nextAddr);
			auto* oldSucc = cond->getSuccessor(1);
			if (nBb && oldSucc->getParent() == nBb->getParent())
			{
				oldSucc->replaceAllUsesWith(nBb);
				oldSucc->eraseFromParent();
			}
			else
			{
				nextBb->setName(names::generateBasicBlockName(nextAddr));
				addBasicBlock(nextAddr, nextBb);
			}

			return false;
		}
		else
		{
			return true;
		}
	}
	// Unconditional branch -> insert target (if computed).
	//
	else if (_c2l->isBranchFunctionCall(pCall))
	{
		if (auto t = getJumpTarget(addr, pCall, pCall->getArgOperand(0)))
		{
			//.text:08001EE1    call    near ptr loc_8001EE1+1
			//.text:08001EE6    cmp     ebx, esi
			if (addr < t && t < nextAddr)
			{
				return false;
			}
			if (nextAddr <= t && t < nextAddr + rangeSize)
			{
				rangeSize = t - nextAddr;
			}

			auto m = determineMode(tr.capstoneInsn, t);

			getOrCreateBranchTarget(t, tBb, tFnc, pCall);
			if (tBb
					&& tBb->getParent() == pCall->getFunction()
					&& tBb->getPrevNode()) // can not be first in function
			{
				transformToBranch(pCall, tBb);
			}
			else if (tFnc)
			{
				transformToCall(pCall, tFnc);
			}

			// TODO: if target was from load of import addr, do not add it,
			// add everywhere, make this somehow better.
			if (_imports.count(t) == 0)
			{
				_jumpTargets.push(
						t,
						JumpTarget::eType::CONTROL_FLOW_BR_TRUE,
						m,
						addr);
			}
			LOG << "\t\t" << "br @ " << addr << " -> "	<< t << std::endl;
		}

		if (_switchGenerated)
		{
			return true;
		}

		if (auto* cond = _c2l->isInConditionBranchFunctionCall(pCall))
		{
			// Name the block and assign an address to it -> keep up with IDA.
			auto nextAddr = addr + tr.size;
			auto* nextBb = cond->getSuccessor(1);

			auto* nBb = getBasicBlockAtAddress(nextAddr);
			if (nBb && nBb->getParent() == cond->getFunction())
			{
				auto* oldSucc = cond->getSuccessor(1);
				oldSucc->replaceAllUsesWith(nBb);
				oldSucc->eraseFromParent();
			}
			else
			{
				nextBb->setName(names::generateBasicBlockName(nextAddr));
				addBasicBlock(nextAddr, nextBb);
			}

			// Break the flow if BB in which pseudo call is continues to the
			// false branch of cond br.
			auto* bodyBb = pCall->getParent();
			auto* tBr = dyn_cast<BranchInst>(bodyBb->getTerminator());
			if (tBr
					&& tBr->isUnconditional()
					&& tBr->getSuccessor(0) == cond->getSuccessor(1))
			{
				ReturnInst::Create(
						pCall->getModule()->getContext(),
						UndefValue::get(pCall->getFunction()->getReturnType()),
						tBr);
				tBr->eraseFromParent();
			}
			return false;
		}
		else
		{
			return true;
		}
	}
	// Conditional branch -> insert target (if computed), and next (flow
	// may or may not jump/continue after).
	//
	else if (_c2l->isCondBranchFunctionCall(pCall))
	{
		auto nextAddr = addr + tr.size;
		// Right now, delay slots are only in architectures with fixed
		// instruction size (more specifically, only in MIPS).
		// Therefore, we can multiply current instruction size with number of
		// instructions in the delay slot to get its size.
		// If this changes, we will have to modify this -> create nextAddr
		// target only after delay slot instructions are decoded and we know
		// their sizes.
		//
		nextAddr += _c2l->getDelaySlot(tr.capstoneInsn->id) * tr.size;

		if (auto t = getJumpTarget(addr, pCall, pCall->getArgOperand(1)))
		{
			//.text:08001EE1    call    near ptr loc_8001EE1+1
			//.text:08001EE6    cmp     ebx, esi
			if (addr < t && t < nextAddr)
			{
				return false;
			}

			auto m = determineMode(tr.capstoneInsn, t);
			getOrCreateBranchTarget(t, tBb, tFnc, pCall);

			BasicBlock* tBbN = nullptr;
			Function* tFncN = nullptr;
			getOrCreateBranchTarget(nextAddr, tBbN, tFncN, pCall);

			if (tBb && tBbN
					&& tBb->getParent() == tBbN->getParent()
					&& tBb->getParent() == pCall->getFunction()
					&& tBb->getPrevNode()) // is not first in fnct, first -> call
			{
				transformToCondBranch(pCall, pCall->getOperand(0), tBb, tBbN);
			}
			else if (tFnc && tBbN
					&& tBbN->getParent() == pCall->getFunction())
			{
				transformToCondCall(pCall, pCall->getOperand(0), tFnc, tBbN);
			}
			else if (tBb && tBbN
					&& tBb->getParent() != pCall->getFunction()
					&& tBbN->getParent() == pCall->getFunction())
			{
				// TODO: In the end, not now, transform to conditional jump out.
				return false;
			}
			else
			{
				// TODO: deal with this
				return false;
			}

			_jumpTargets.push(
					t,
					JumpTarget::eType::CONTROL_FLOW_BR_TRUE,
					m,
					addr);
			LOG << "\t\t" << "cond br @ " << addr << " -> (true) "
					<< t << std::endl;

			// There is no need to break BB and its decoding if target was not
			// found.
			//
			_jumpTargets.push(
					nextAddr,
					JumpTarget::eType::CONTROL_FLOW_BR_FALSE,
					_c2l->getBasicMode(),
					addr);
			LOG << "\t\t" << "cond br @ " << addr << " -> (false) "
					<< nextAddr << std::endl;

			return true;
		}
	}
	// Analyze ordinary (not control flow) instruction.
	// TODO: maybe move to a separate function.
	//
	else
	{
		AsmInstruction ai(tr.llvmInsn);
		for (auto& i : ai)
		{
			// Skip ranges from which there are loads.
			// Mostly for ARM where there are data references after functions
			// in .text section.
			// We do not use Symbolic tree here, since control flow is not fully
			// reconstructed - matching only constants is safe and should be
			// enough for most cases.
			//
			if (auto* l = dyn_cast<LoadInst>(&i))
			{
				SymbolicTree st(_RDA, l->getPointerOperand(), nullptr, 8);
				st.simplifyNode();

				if (auto* ci = dyn_cast<ConstantInt>(st.value))
				{
					Address t(ci->getZExtValue());
					auto sz = _abi->getTypeByteSize(l->getType());
					AddressRange r(t, t+sz);
					_ranges.remove(r);

					// Trim currently decoding range size if needed.
					auto nextAddr = addr + tr.size;
					if (nextAddr < t && t < nextAddr + rangeSize)
					{
						rangeSize = t - nextAddr;
					}

					LOG << "\t\t\t\t" << "skip " << r << std::endl;
				}
			}
		}
	}

	if (_switchGenerated)
	{
		return true;
	}

	return false;
}

utils::Address Decoder::getJumpTarget(
		utils::Address addr,
		llvm::CallInst* branchCall,
		llvm::Value* val)
{
	SymbolicTree st(_RDA, val, nullptr, 20);

	// TODO: better implementation.
	// PIC code.
	// User code is calling stub in .plt.
	// Stub in .plt is computing jmp address (address of import).
	// 4-form_grabber-b794ce9e.so.elf, .plt:00001BE0 ___ctype_toupper_loc:
	//   %u1_1be0 = load i32, i32* @ebx
	//   %u2_1be0 = add i32 %u1_1be0, %u0_1be0
	//   %u3_1be0 = load i32, i32* %u2_1be0
	//   call void @__pseudo_br(i32 %u3_1be0)
	// We do not know the value in @ebx. This should be .got.plt section
	// start -> fix value in symbolic tree before simplification.
	//
	auto* plt = _image->getFileFormat()->getSectionFromAddress(addr);
	if (plt && plt->getName() == ".plt")
	{
		// TODO: do not find this all over again every time.
		auto* gotplt = _image->getFileFormat()->getSection(".got.plt");
		if (gotplt)
		{
			auto gotpltAddr = gotplt->getAddress();
			for (auto* n : st.getPostOrder())
			{
				if (_config->isGeneralPurposeRegister(n->value))
				{
					n->value = ConstantInt::get(
							_abi->getDefaultType(),
							gotpltAddr);
				}
			}
		}
	}

	st.simplifyNode();

	if (auto* ci = dyn_cast<ConstantInt>(st.value))
	{
		return ci->getZExtValue();
	}

	// If there is load, at first try imports.
	if (isa<LoadInst>(st.value)
			&& st.ops.size() == 1
			&& isa<ConstantInt>(st.ops[0].value))
	{
		auto* ci = dyn_cast<ConstantInt>(st.ops[0].value);
		Address t = ci->getZExtValue();
		if (_imports.count(t))
		{
			return t;
		}
	}
	// TODO: Some nicer, more general solution?
	// ARM:
	// printf:
	//     116FC 00 C0 9F E5    LDR R12, =__imp_printf
	//     11700 00 F0 9C E5    LDR PC, [R12]
	// tree:
	//>|   %3 = load i32, i32* %2
	//		>|   %0 = load i32, i32* inttoptr (i32 71428 to i32*)
	//				>| i32 71428
	//
	// solveMemoryLoads() and simplifyNode() combo will solve both loads
	// -> we can not check for imports.
	//
	if (isa<LoadInst>(st.value)
			&& st.ops.size() == 1
			&& isa<LoadInst>(st.ops[0].value)
			&& st.ops[0].ops.size() == 1
			&& isa<ConstantInt>(st.ops[0].ops[0].value))
	{
		auto* ptr = dyn_cast<ConstantInt>(st.ops[0].ops[0].value);
		if (auto* ci = _image->getConstantDefault(ptr->getZExtValue()))
		{
			Address t = ci->getZExtValue();
			if (_imports.count(t))
			{
				return t;
			}
		}
	}

	// Try to recognize switch pattern.
	// getJumpTargetSwitch() doesn't return target to the caller, it takes care
	// of everything - pseudo to switch transform, jump target creation, ...
	// We just need to return from this function if it succeeds.
	//
	if (getJumpTargetSwitch(addr, branchCall, val, st))
	{
		return Address::getUndef;
	}

	// TOOD: ugly hack - recognize MIPS import stub functions.
	// We compute more than we should here -> solve load and jump to _PROCEDURE_LINKAGE_TABLE_.
	// IDA will either change the loaded word to point to synthetic import section,
	// or marks it as ?? ?? ?? ?? so it can not be used. We read _PROCEDURE_LINKAGE_TABLE_ address.
	// Can we use relocations, or something to mark these pointer not to be used.
	// Problem, this is also used in ihex, where there is even less info.
	//
	if (_config->getConfig().architecture.isMipsOrPic32())
	{
		AsmInstruction ai1(_module, addr);
		AsmInstruction ai2 = ai1.getPrev();
		AsmInstruction ai3 = ai2.getPrev();
		AsmInstruction ai4 = ai3.getPrev();
		if (ai4.isInvalid()
				&& ai1.isValid() && ai1.getDsm() == "jr $t9"
				&& ai2.isValid() && ai2.getCapstoneInsn()->id == MIPS_INS_LW
				&& ai3.isValid() && ai3.getCapstoneInsn()->id == MIPS_INS_LUI)
		{
			return Address::getUndef;
		}
	}

	// If there are loads, try to solve them.
	st.solveMemoryLoads(_image);
	st.simplifyNode();

// TODO: doing this will solve more, also it will screw up integration.ack.Test_2015_ThumbGccElf
	if (getJumpTargetSwitch(addr, branchCall, val, st))
	{
		return Address::getUndef;
	}

	if (auto* ci = dyn_cast<ConstantInt>(st.value))
	{
		return ci->getZExtValue();
	}

	return Address::getUndef;
}

/**
 * \return \c True if switch recognized, \c false otherwise.
 */
bool Decoder::getJumpTargetSwitch(
		utils::Address addr,
		llvm::CallInst* branchCall,
		llvm::Value* val,
		SymbolicTree& st)
{
	unsigned archByteSz =  _config->getConfig().architecture.getByteSize();

	// Pattern:
	//>|   %55 = load i32, i32* %54
	//		>|   %53 = add i32 Addr, %52
	//				>|   %52 = mul i32 %51, 4
	//						>| idx
	//						>| i32 4
	//				>| i32 tableAddr
	if (!(isa<LoadInst>(st.value) // load
			&& st.ops.size() == 1
			&& isa<AddOperator>(st.ops[0].value) // add
			&& st.ops[0].ops.size() == 2
			&& (isa<MulOperator>(st.ops[0].ops[0].value) // mul
					|| isa<ShlOperator>(st.ops[0].ops[0].value)) // shl
			&& st.ops[0].ops[0].ops.size() == 2
			&& isa<ConstantInt>(st.ops[0].ops[0].ops[1].value)
			&& isa<ConstantInt>(st.ops[0].ops[1].value))) // table address
	{
		return false;
	}

	bool usesMul = isa<MulOperator>(st.ops[0].ops[0].value);
	bool usesShl = isa<ShlOperator>(st.ops[0].ops[0].value);
	auto* mulShlCi = cast<ConstantInt>(st.ops[0].ops[0].ops[1].value);
	if (!((usesMul && mulShlCi->getZExtValue() == archByteSz)
			|| (usesShl
					&& static_cast<uint64_t>(1 << mulShlCi->getZExtValue()) == archByteSz)))
	{
		return false;
	}

	Address tableAddr = cast<ConstantInt>(st.ops[0].ops[1].value)->getZExtValue();
	Value* idx = cast<Instruction>(st.ops[0].ops[0].value)->getOperand(0);

	LOG << "\t\t" << "switch @ " << addr << std::endl;
	LOG << "\t\t\t" << "table addr @ " << tableAddr << std::endl;

	// Default target.
	//
	Address defAddr;
	BranchInst* brToSwitch = nullptr; // TODO: i don't like how this is used
	Value* brToSwitchCondVal = nullptr;
	auto* thisBb = branchCall->getParent();

	Address thisBbAddr = getBasicBlockAddress(thisBb);
	for (auto* p : predecessors(thisBb))
	{
		auto* br = dyn_cast<BranchInst>(p->getTerminator());
		if (br && br->isConditional())
		{
			brToSwitch = br;

			Address falseAddr = getBasicBlockAddress(br->getSuccessor(1));
			Address trueAddr = getBasicBlockAddress(br->getSuccessor(0));

			// Branching over this BB -> true branching to default case.
			if (falseAddr.isDefined() && thisBbAddr == falseAddr)
			{
				defAddr = trueAddr;
				brToSwitchCondVal = ConstantInt::getFalse(_module->getContext());
				LOG << "\t\t\t\t" << "default: branching over -> "
						<< defAddr << std::endl;
			}
			// Branching to this BB -> false branching to default case.
			else if (trueAddr.isDefined() && thisBbAddr == trueAddr)
			{
				defAddr = falseAddr;
				brToSwitchCondVal = ConstantInt::getTrue(_module->getContext());
				LOG << "\t\t\t\t" << "default: branching to -> "
						<< defAddr << std::endl;
			}

			break;
		}
	}

	// ARM:
	// 90C0 03 F1 9F 97    LDRLS PC, [PC,R3,LSL#2] ; switch jump
	// 90C4 18 01 00 EA    B     loc_952C ; jumptable 000090C0 default cas
	//
	// Pseudo call itself is conditional -> next is default.
	//
	BranchInst* armCondBr = nullptr;
	auto* cond = _c2l->isInConditionBranchFunctionCall(branchCall);
	if (cond && thisBb == cond->getSuccessor(0))
	{
		// TODO: use known current insn size, not AsmInstruction() -> slow.
		brToSwitch = nullptr;
		defAddr = addr + AsmInstruction(branchCall).getByteSize();
		armCondBr = cond;
	}

	// TODO:
	// ARM:
	// 8AB8 00 D8    BHI def_8D4A ; jumptable 00008D4A default case
	// 8ABA 43 E1    B   loc_8D44
	// ...
	// 8D44 loc_8D44:
	//               switch
	//
	if (defAddr.isUndefined()
			|| (armCondBr == nullptr
					&& (brToSwitch == nullptr || brToSwitchCondVal == nullptr)))
	{
		LOG << "\t\t\t" << "no default target -> skip" << std::endl;
		// TODO: detected labels still should become jump targets.
		// problem, we don't know the jump target type -> they can be functions,
		// not just branch targets.
		// e.g. 04023A3 @ call ds:___CTOR_LIST__[ebx*4]
		return false;
	}
	else
	{
		LOG << "\t\t\t" << "default label @ " << defAddr << std::endl;
	}

	// Jump table size.
	// maybe we could check that compared value is indeed index value.
	//
	unsigned tableSize = 0;
if (brToSwitch)
{
	SymbolicTree stCond(_RDA, brToSwitch->getCondition());
	stCond.simplifyNode();

	auto levelOrd = stCond.getLevelOrder();
	for (SymbolicTree* n : levelOrd)
	{
		// x86:
		//>|   %331 = or i1 %329, %330
		//		>|   %317 = icmp ult i8 %312, 90
		//				>|   %296 = sub i32 %295, 32
		//				>| i8 90
		//		>|   %322 = icmp eq i8 %313, 0
		//				>|   %313 = sub i8 %312, 90
		//						>|   %312 = trunc i32 %311 to i8
		//						>| i8 90
		//				>| i8 0
		if (isa<BinaryOperator>(n->value)
				&& cast<BinaryOperator>(n->value)->getOpcode()
						== Instruction::Or
				&& n->ops.size() == 2
				&& isa<ICmpInst>(n->ops[0].value)
				&& cast<ICmpInst>(n->ops[0].value)->getPredicate()
						== ICmpInst::ICMP_ULT
				&& n->ops[0].ops.size() == 2
				&& isa<ConstantInt>(n->ops[0].ops[1].value)
				&& isa<ICmpInst>(n->ops[1].value)
				&& cast<ICmpInst>(n->ops[1].value)->getPredicate()
						== ICmpInst::ICMP_EQ
				&& n->ops[1].ops.size() == 2
				&& isa<ConstantInt>(n->ops[1].ops[1].value)
				&& cast<ConstantInt>(n->ops[1].ops[1].value)->isZero())
		{
			auto* ci = cast<ConstantInt>(n->ops[0].ops[1].value);
			tableSize = ci->getZExtValue() + 1;
			LOG << "\t\t\t" << "table size (1) = " << tableSize << std::endl;
			break;
		}
		// mips (???):
		//>|   %319 = icmp ne i32 %318, 0
		//		>|   %316 = icmp ult i32 %315, 121
		//				>|   %314 = and i32 %313, 255
		//				>| i32 121
		//		>| i32 0
		else if (isa<ICmpInst>(n->value)
				&& cast<ICmpInst>(n->value)->getPredicate()
						== ICmpInst::ICMP_NE
				&& isa<ICmpInst>(n->ops[0].value)
				&& cast<ICmpInst>(n->ops[0].value)->getPredicate()
						== ICmpInst::ICMP_ULT
				&& isa<ConstantInt>(n->ops[0].ops[1].value)
				&& !cast<ConstantInt>(n->ops[0].ops[1].value)->isZero()
				&& isa<ConstantInt>(n->ops[1].value)
				&& cast<ConstantInt>(n->ops[1].value)->isZero())
		{
			auto* ci = cast<ConstantInt>(n->ops[0].ops[1].value);
			tableSize = ci->getZExtValue();
			LOG << "\t\t\t" << "table size (2) = " << tableSize << std::endl;
			break;
		}
		// TODO: apply this only if it si branching over?
		// TODO: apply prev (very similar to this) only if branching to?
		// mips (branching over):
		//>|   %33 = icmp ne i32 %32, 0
		//		>|   %22 = icmp ult i32 %20, %21
		//				>| i32 8
		//				>|   %19 = add i32 %18, -20
		//		>| i32 0
		else if (isa<ICmpInst>(n->value)
				&& cast<ICmpInst>(n->value)->getPredicate()
						== ICmpInst::ICMP_NE
				&& isa<ICmpInst>(n->ops[0].value)
				&& cast<ICmpInst>(n->ops[0].value)->getPredicate()
						== ICmpInst::ICMP_ULT
				&& isa<ConstantInt>(n->ops[0].ops[0].value)
				&& !cast<ConstantInt>(n->ops[0].ops[0].value)->isZero()
				&& isa<ConstantInt>(n->ops[1].value)
				&& cast<ConstantInt>(n->ops[1].value)->isZero())
		{
			auto* ci = cast<ConstantInt>(n->ops[0].ops[0].value);
			tableSize = ci->getZExtValue();
			LOG << "\t\t\t" << "table size (2.5) = " << tableSize << std::endl;
			break;
		}
		// mips:
		//>|   %524 = icmp eq i32 %523, 0
		//		>|   %449 = icmp ult i32 %448, 5
		//				>| i32 3
		//				>| i32 5
		//		>| i32 0
		else if (isa<ICmpInst>(n->value)
				&& cast<ICmpInst>(n->value)->getPredicate()
						== ICmpInst::ICMP_EQ
				&& isa<ICmpInst>(n->ops[0].value)
				&& cast<ICmpInst>(n->ops[0].value)->getPredicate()
						== ICmpInst::ICMP_ULT
				&& isa<ConstantInt>(n->ops[0].ops[1].value)
				&& !cast<ConstantInt>(n->ops[0].ops[1].value)->isZero()
				&& isa<ConstantInt>(n->ops[1].value)
				&& cast<ConstantInt>(n->ops[1].value)->isZero())
		{
			auto* ci = cast<ConstantInt>(n->ops[0].ops[1].value);
			tableSize = ci->getZExtValue();
			LOG << "\t\t\t" << "table size (3) = " << tableSize << std::endl;
			break;
		}
	}
}

	// integration.current.switch.TestEXE (switch-test-msvc-O0.ex)
	// Two jump tables.
	//
	std::vector<unsigned> idxs;
	unsigned maxIdx = 0;
	SymbolicTree idxRoot(_RDA, idx);
	idxRoot.simplifyNode();
	if (_config->getConfig().architecture.isX86()
			&& tableSize
			&& isa<LoadInst>(idxRoot.value)
			&& cast<LoadInst>(idxRoot.value)->getType()->isIntegerTy()
			&& idxRoot.ops.size() == 1
			&& isa<AddOperator>(idxRoot.ops[0].value)
			&& idxRoot.ops[0].ops.size() == 2
			&& isa<Instruction>(idxRoot.ops[0].ops[0].value)
			&& cast<Instruction>(idxRoot.ops[0].ops[0].value)->getType()->isIntegerTy()
			&& isa<ConstantInt>(idxRoot.ops[0].ops[1].value))
	{
		auto* l = cast<LoadInst>(idxRoot.value);
		auto* it = cast<IntegerType>(l->getType());
		auto* ci = cast<ConstantInt>(idxRoot.ops[0].ops[1].value);
		retdec::utils::Address tableAddr2(ci->getZExtValue());

		LOG << "\t\t\t" << "second table addr @ " << tableAddr2 << std::endl;

		// Switch index must not be the table offset.
		// We have to use the original index.
		idx = cast<Instruction>(idxRoot.ops[0].ops[0].value);

		while (true)
		{
			auto* ci = _image->getConstantInt(it, tableAddr2);
			if (ci == nullptr)
			{
				break;
			}
			// A safer condition to end this would be to track constant
			// (second table size) used in comparison in instruction
			// before the cond jmp instruction.
			unsigned idx = ci->getZExtValue();
			if (tableSize > 0 && idxs.size() == tableSize)
			{
				break;
			}

			LOG << "\t\t\t\t" << idx << std::endl;

			maxIdx = idx > maxIdx ? idx : maxIdx;
			idxs.push_back(idx);
			tableAddr2 += _abi->getTypeByteSize(ci->getType());
		}
	}

	// Get targets from jump table.
	//
	LOG << "\t\t\t" << "table labels:" << std::endl;
	std::vector<Address> cases;
	Address tableItemAddr = tableAddr;
	Address nextTableAddr;
	auto swTblIt = _switchTableStarts.upper_bound(tableAddr);
	if (swTblIt != _switchTableStarts.end())
	{
		nextTableAddr = swTblIt->first;
	}
	while (true)
	{
		auto* ci = _image->getImage()->isPointer(tableItemAddr)
				? _image->getConstantDefault(tableItemAddr)
				: nullptr;
		if (ci == nullptr)
		{
			break;
		}

		Address item = ci->getZExtValue();
		LOG << "\t\t\t\t" << item << " @ " << tableItemAddr << std::endl;

		tableItemAddr += archByteSz;
		cases.push_back(item);

		if (tableSize > 0 && cases.size() == tableSize)
		{
			break;
		}
		// idx from zero, there can be one more item than max idx number.
		if (maxIdx > 0 && cases.size() > maxIdx)
		{
			break;
		}
		if (nextTableAddr.isUndefined() && tableItemAddr >= nextTableAddr)
		{
			break;
		}
	}
	if (cases.empty())
	{
		LOG << "\t\t\t" << "no targets @ " << tableAddr << " -> skip"
				<< std::endl;
		return false;
	}
	Address tableAddrEnd = tableItemAddr;

	// Put together two tables.
	//
	if (!idxs.empty())
	{
		std::vector<Address> tmp = std::move(cases);
		cases.clear();

		for (auto& i : idxs)
		{
			if (tmp.size() > i)
			{
				cases.push_back(tmp[i]);
			}
		}
	}

	//
	//
	std::vector<BasicBlock*> casesBbs;
	for (auto c : cases)
	{
		BasicBlock* tBb = nullptr;
		Function* tFnc = nullptr;
		// TODO: do not split functions here.
		// if case in another function, do not use it - it may belong to another
		// switch table.
		getOrCreateBranchTarget(c, tBb, tFnc, branchCall);
		if (tBb && tBb->getParent() == branchCall->getFunction())
		{
			casesBbs.push_back(tBb);
		}
		else
		{
			return false;
		}
	}

	Function* tFnc = nullptr;
	BasicBlock* defBb = nullptr;
	// TODO: do not split functions here
	getOrCreateBranchTarget(defAddr, defBb, tFnc, branchCall);
	if (defBb == nullptr
			|| defBb->getParent() != branchCall->getFunction())
	{
		assert(false);
		return false;
	}

	auto* sw = transformToSwitch(branchCall, idx, defBb, casesBbs);

	// TODO: create only for those that were transformed to BBs.
	for (auto c : cases)
	{
		_jumpTargets.push(
				c,
				JumpTarget::eType::CONTROL_FLOW_SWITCH_CASE,
				_c2l->getBasicMode(), // mode should not change here
				addr);
		LOG << "\t\t" << "switch -> (case) " << c << std::endl;
	}

	_jumpTargets.push(
			defAddr,
			JumpTarget::eType::CONTROL_FLOW_SWITCH_CASE,
			_c2l->getBasicMode(), // mode should bot change here
			addr);
	LOG << "\t\t" << "switch -> (default) " << defAddr << std::endl;

	_ranges.remove(tableAddr, tableAddrEnd);

	_switchTableStarts[tableAddr].insert(sw);
	_switchGenerated = true;

	if (brToSwitch && brToSwitchCondVal)
	{
		brToSwitch->setCondition(brToSwitchCondVal);
	}

	if (armCondBr)
	{
		BranchInst::Create(armCondBr->getSuccessor(0), armCondBr);
		auto* rmSucc = armCondBr->getSuccessor(1);
		armCondBr->eraseFromParent();
		rmSucc->eraseFromParent();
	}

	return true;
}

/**
 * ; ASM branch insn
 * ; ASM delay slot insn
 *
 * ==>
 *
 * ; ASM branch insn
 *     LLVM IR body without branch
 * ; ASM delay slot insn
 *     LLVM IR body
 *     branch from prev insn
 */
void Decoder::handleDelaySlotTypical(
		utils::Address& addr,
		capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& res,
		ByteData& bytes,
		llvm::IRBuilder<>& irb)
{
	if (!_c2l->hasDelaySlotTypical(res.capstoneInsn->id))
	{
		return;
	}

	assert(res.branchCall);
	assert(_c2l->getDelaySlot(res.capstoneInsn->id));
	assert(_c2l->getDelaySlot(res.capstoneInsn->id) == 1);

	auto* oldIp = res.branchCall->getParent()->getTerminator();

	irb.SetInsertPoint(res.branchCall);
	std::size_t sz = _c2l->getDelaySlot(res.capstoneInsn->id);
	for (std::size_t i = 0; i < sz; ++i)
	{
		auto r = translate(bytes, addr, irb);
		if (r.failed() || r.llvmInsn == nullptr)
		{
			break;
		}
		_llvm2capstone->emplace(r.llvmInsn, r.capstoneInsn);
	}

	irb.SetInsertPoint(oldIp);
}

/**
 *     br cond, target_true, target_false
 *     delay_slot_likely_insn
 *
 * ==>
 *
 *     br cond, ds_likely_bb, target_false
 *  ds_likely_bb:
 *     delay_slot_likely_insn
 *     br target_true
 *  target_false:
 *     ...
 */
void Decoder::handleDelaySlotLikely(
		utils::Address& addr,
		capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& res,
		ByteData& bytes,
		llvm::IRBuilder<>& irb)
{
	if (!_c2l->hasDelaySlotLikely(res.capstoneInsn->id))
	{
		return;
	}

	assert(res.branchCall);
	assert(_c2l->getDelaySlot(res.capstoneInsn->id));
	assert(_c2l->getDelaySlot(res.capstoneInsn->id) == 1);

	auto* br = dyn_cast<BranchInst>(res.branchCall->getNextNode());
	if (br && br->isConditional())
	{
		auto* nextBb = br->getParent()->getNextNode();
		auto* newBb = BasicBlock::Create(
				_module->getContext(),
				"",
				br->getFunction(),
				nextBb);

		auto* target = br->getSuccessor(0);
		br->setSuccessor(0, newBb);
		auto* newTerm = BranchInst::Create(target, newBb);
		irb.SetInsertPoint(newTerm);

		std::size_t sz = _c2l->getDelaySlot(res.capstoneInsn->id);
		for (std::size_t i = 0; i < sz; ++i)
		{
			auto res = translate(bytes, addr, irb);
			if (res.failed() || res.llvmInsn == nullptr)
			{
				break;
			}
			_llvm2capstone->emplace(res.llvmInsn, res.capstoneInsn);
		}

		_likelyBb2Target.emplace(newBb, target);
	}
	else
	{
		// TODO: This assumes that the pseudo cond branch was solved and cond
		// branch created, but we should handle likely ds even if it was not.
	}
}

void Decoder::resolvePseudoCalls()
{
	// TODO: fix point algorithm that tries to re-solve all solved and unsolved
	// pseudo calls?
	// - the same result -> ok, nothing
	// - no result -> revert transformation
	// - new result -> new transformation
	// This will not be easy. Can fixpoint even be reached? Reverts, etc. are
	// hard and ugly.

	for (Function& f : *_module)
	for (BasicBlock& b : f)
	for (auto i = b.begin(), e = b.end(); i != e;)
	{
		CallInst* pseudo = dyn_cast<CallInst>(&*i);
		++i;
		if (pseudo == nullptr)
		{
			continue;
		}
		if (!_c2l->isCallFunctionCall(pseudo)
				&& !_c2l->isReturnFunctionCall(pseudo)
				&& !_c2l->isBranchFunctionCall(pseudo)
				&& !_c2l->isCondBranchFunctionCall(pseudo))
		{
			continue;
		}

		Instruction* real = pseudo->getNextNode();
		if (real == nullptr)
		{
			continue;
		}
		++i;

		// TODO: fix calls, maybe we could create the calls for the first time
		// here.
		//
		if (_c2l->isCallFunctionCall(pseudo)
				&& isa<CallInst>(real))
		{
			Address t = getJumpTarget(
					AsmInstruction::getInstructionAddress(real),
					pseudo,
					pseudo->getArgOperand(0));

			if (t.isUndefined())
			{
				++i;
				auto* st = cast<StoreInst>(*real->user_begin());
				st->eraseFromParent();
				real->eraseFromParent();
			}
		}
	}
}

void Decoder::finalizePseudoCalls()
{
	for (auto& f : *_module)
	for (auto& b : f)
	for (auto i = b.begin(), e = b.end(); i != e;)
	{
		CallInst* pseudo = dyn_cast<CallInst>(&*i);
		++i;
		if (pseudo == nullptr)
		{
			continue;
		}
		if (!_c2l->isCallFunctionCall(pseudo)
				&& !_c2l->isReturnFunctionCall(pseudo)
				&& !_c2l->isBranchFunctionCall(pseudo)
				&& !_c2l->isCondBranchFunctionCall(pseudo))
		{
			continue;
		}

		Instruction* it = pseudo->getPrevNode();
		pseudo->eraseFromParent();

		bool mipsFirstAsmInstr = true;
		while (it)
		{
			if (AsmInstruction::isLlvmToAsmInstruction(it))
			{
				if (_config->getConfig().architecture.isMipsOrPic32()
						&& mipsFirstAsmInstr)
				{
					mipsFirstAsmInstr = false;
				}
				else
				{
					break;
				}
			}

			auto* i = it;
			it = it->getPrevNode();

			// Return address store to stack in x86 calls.
			//
			if (_config->getConfig().architecture.isX86()
					&& (_c2l->isCallFunctionCall(pseudo)
							|| _c2l->isReturnFunctionCall(pseudo)))
			if (auto* st = dyn_cast<StoreInst>(i))
			{
				if (_config->isStackPointerRegister(st->getPointerOperand())
						|| isa<ConstantInt>(st->getValueOperand()))
				{
					st->eraseFromParent();
				}
			}

			// Return address store to register in MIPS calls.
			//
			if (_config->getConfig().architecture.isMipsOrPic32()
					&& _c2l->isCallFunctionCall(pseudo))
			if (auto* st = dyn_cast<StoreInst>(i))
			{
				if (_c2l->isRegister(st->getPointerOperand())
						&& st->getPointerOperand()->getName() == "ra")
				{
					st->eraseFromParent();
				}
			}

			// Return address store to register in MIPS calls.
			// TODO: what about other possible LR stores? e.g. see
			// patternsPseudoCall_arm().
			//
			if (_config->getConfig().architecture.isArmOrThumb()
					&& _c2l->isCallFunctionCall(pseudo))
			if (auto* st = dyn_cast<StoreInst>(i))
			{
				if (_c2l->isRegister(st->getPointerOperand())
						&& st->getPointerOperand()->getName() == "lr")
				{
					st->eraseFromParent();
				}
			}

			// TOOD: again, other possible stores && r32 stores.
			//
			if (_config->getConfig().architecture.isPpc()
					&& _c2l->isCallFunctionCall(pseudo))
			if (auto* st = dyn_cast<StoreInst>(i))
			{
				if (_c2l->isRegister(st->getPointerOperand())
						&& st->getPointerOperand()->getName() == "lr")
				{
					st->eraseFromParent();
				}
			}

			if (!i->getType()->isVoidTy() && i->use_empty())
			{
				i->eraseFromParent();
			}
		}
	}
}

} // namespace bin2llvmir
} // namespace retdec
