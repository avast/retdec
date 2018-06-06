/**
 * @file src/bin2llvmir/providers/asm_instruction.cpp
 * @brief Mapping of LLVM instructions to underlying ASM instructions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>

#include "retdec/utils/container.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/names.h"
#include "retdec/bin2llvmir/utils/debug.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/llvm.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

std::vector<AsmInstruction::ModuleGlobalPair> AsmInstruction::_module2global;
std::vector<AsmInstruction::ModuleInstructionMap> AsmInstruction::_module2instMap;

AsmInstruction::AsmInstruction()
{

}

AsmInstruction::AsmInstruction(llvm::Instruction* inst)
{
	if (inst == nullptr)
	{
		return;
	}

	auto* bb = inst->getParent();
	while (inst && !isLlvmToAsmInstructionPrivate(inst))
	{
		if (&bb->front() == inst)
		{
			if (&bb->getParent()->front() == bb)
			{
				return;
			}
			else
			{
				bb = bb->getPrevNode();
				inst = &bb->back();
			}
		}
		else
		{
			inst = inst->getPrevNode();
		}
	}

	auto* s = dyn_cast_or_null<StoreInst>(inst);
	_llvmToAsmInstr = isLlvmToAsmInstructionPrivate(s) ? s : nullptr;
}

AsmInstruction::AsmInstruction(llvm::BasicBlock* bb)
{
	if (bb == nullptr || bb->empty())
	{
		return;
	}

	*this = AsmInstruction(&bb->front());
}

AsmInstruction::AsmInstruction(llvm::Function* f)
{
	if (f == nullptr || f->empty())
	{
		return;
	}

	for (auto it = inst_begin(f), e = inst_end(f); it != e; ++it)
	{
		Instruction* i = &(*it);
		if (isLlvmToAsmInstructionPrivate(i))
		{
			_llvmToAsmInstr = dyn_cast_or_null<StoreInst>(i);
			return;
		}
	}
}

AsmInstruction::AsmInstruction(llvm::Module* m, retdec::utils::Address addr)
{
	if (m == nullptr)
	{
		return;
	}

	ConstantInt* ci = ConstantInt::get(
			Type::getInt64Ty(m->getContext()),
			addr,
			false);
	if (ci == nullptr)
	{
		return;
	}

	for (auto* u : ci->users())
	{
		if (isLlvmToAsmInstructionPrivate(u))
		{
			_llvmToAsmInstr = dyn_cast_or_null<StoreInst>(u);
			return;
		}
	}
}

bool AsmInstruction::operator<(const AsmInstruction& o) const
{
	return getAddress() < o.getAddress();
}

bool AsmInstruction::operator==(const AsmInstruction& o) const
{
	return getLlvmToAsmInstruction() == o.getLlvmToAsmInstruction();
}

bool AsmInstruction::operator!=(const AsmInstruction& o) const
{
	return !(*this == o);
}

/**
 * @return @c True it @c AsmInstruction is valid, @c false otherwise.
 */
AsmInstruction::operator bool() const
{
	return isValid();
}

AsmInstruction::iterator AsmInstruction::begin()
{
	return iterator(_llvmToAsmInstr);
}
AsmInstruction::iterator AsmInstruction::end()
{
	return iterator(_llvmToAsmInstr, true);
}
AsmInstruction::reverse_iterator AsmInstruction::rbegin()
{
	return reverse_iterator(end());
}
AsmInstruction::reverse_iterator AsmInstruction::rend()
{
	return reverse_iterator(begin());
}
AsmInstruction::const_iterator AsmInstruction::begin() const
{
	return const_iterator(_llvmToAsmInstr);
}
AsmInstruction::const_iterator AsmInstruction::end() const
{
	return const_iterator(_llvmToAsmInstr, true);
}
AsmInstruction::const_reverse_iterator AsmInstruction::rbegin() const
{
	return const_reverse_iterator(end());
}
AsmInstruction::const_reverse_iterator AsmInstruction::rend() const
{
	return const_reverse_iterator(begin());
}

const llvm::GlobalVariable* AsmInstruction::getLlvmToAsmGlobalVariablePrivate(
		llvm::Module* m) const
{
	if (_llvmToAsmInstr)
	{
		return cast<GlobalVariable>(_llvmToAsmInstr->getPointerOperand());
	}
	else
	{
		return getLlvmToAsmGlobalVariable(m);
	}
}

Llvm2CapstoneMap& AsmInstruction::getLlvmToCapstoneInsnMap(
		const llvm::Module* m)
{
	for (auto& p : _module2instMap)
	{
		if (p.first == m)
		{
			return p.second;
		}
	}

	auto it = _module2instMap.emplace(_module2instMap.end(), std::make_pair(
			m,
			std::map<llvm::StoreInst*, cs_insn*>()));
	return it->second;
}

llvm::GlobalVariable* AsmInstruction::getLlvmToAsmGlobalVariable(
		const llvm::Module* m)
{
	for (auto& p : _module2global)
	{
		if (p.first == m)
		{
			return p.second;
		}
	}
	return nullptr;
}

void AsmInstruction::setLlvmToAsmGlobalVariable(
		const llvm::Module* m,
		llvm::GlobalVariable* gv)
{
	_module2global.emplace_back(m, gv);
}

retdec::utils::Address AsmInstruction::getInstructionAddress(
		llvm::Instruction* inst)
{
	retdec::utils::Address ret;
	AsmInstruction ai(inst);
	if (ai.isValid())
	{
		ret = ai.getAddress();
	}
	return ret;
}

retdec::utils::Address AsmInstruction::getBasicBlockAddress(
		llvm::BasicBlock* bb)
{
	return bb->empty()
			? retdec::utils::Address()
			: getInstructionAddress(&bb->front());
}

retdec::utils::Address AsmInstruction::getFunctionAddress(
		llvm::Function* f)
{
	return f->empty()
			? retdec::utils::Address()
			: getBasicBlockAddress(&f->front());
}

bool AsmInstruction::isLlvmToAsmInstructionPrivate(llvm::Value* inst) const
{
	auto* s = dyn_cast_or_null<StoreInst>(inst);
	if (s == nullptr)
	{
		return false;
	}
	auto* m = s->getModule();
	return s->getPointerOperand() == getLlvmToAsmGlobalVariablePrivate(m);
}

bool AsmInstruction::isLlvmToAsmInstruction(const llvm::Value* inst)
{
	auto* s = dyn_cast_or_null<StoreInst>(inst);
	if (s == nullptr)
	{
		return false;
	}
	auto* m = s->getModule();
	return s->getPointerOperand() == getLlvmToAsmGlobalVariable(m);
}

void AsmInstruction::clear()
{
	_module2global.clear();
	_module2instMap.clear();
}

bool AsmInstruction::isValid() const
{
	return _llvmToAsmInstr != nullptr;
}

bool AsmInstruction::isInvalid() const
{
	return !isValid();
}

cs_insn* AsmInstruction::getCapstoneInsn() const
{
	for (auto& p : _module2instMap)
	{
		if (p.first == _llvmToAsmInstr->getModule())
		{
			auto it =  p.second.find(_llvmToAsmInstr);
			return it != p.second.end() ? it->second : nullptr;
		}
	}

	return nullptr;
}

bool AsmInstruction::isThumb() const
{
	cs_insn* ci = getCapstoneInsn();
	if (ci == nullptr)
	{
		return false;
	}

	for (auto g : ci->detail->groups)
	{
		if (g == ARM_GRP_THUMB2DSP
				|| g == ARM_GRP_THUMB
				|| g == ARM_GRP_THUMB1ONLY
				|| g == ARM_GRP_THUMB2)
		{
			return true;
		}
	}

	return false;
}

bool AsmInstruction::isConditional(Config* conf) const
{
	auto* i = getCapstoneInsn();
	return conf && conf->getConfig().architecture.isArmOrThumb() && i
			? i->detail->arm.cc != ARM_CC_AL && i->detail->arm.cc != ARM_CC_INVALID
			: false;
}

std::string AsmInstruction::getDsm() const
{
	auto* i = getCapstoneInsn();
	return std::string(i->mnemonic) + " " + std::string(i->op_str);
}

std::size_t AsmInstruction::getByteSize() const
{
	return getCapstoneInsn()->size;
}

retdec::utils::Address AsmInstruction::getAddress() const
{
	assert(isValid());
	auto* ci = dyn_cast<ConstantInt>(_llvmToAsmInstr->getValueOperand());
	assert(ci);
	return ci->getZExtValue();
}

retdec::utils::Address AsmInstruction::getEndAddress() const
{
	assert(isValid());
	return getAddress() + getByteSize();
}

std::size_t AsmInstruction::getBitSize() const
{
	assert(isValid());
	return getByteSize() * 8;
}

bool AsmInstruction::contains(retdec::utils::Address addr) const
{
	return isValid() ? getAddress() <= addr && addr < getEndAddress() : false;
}

llvm::StoreInst* AsmInstruction::getLlvmToAsmInstruction() const
{
	return _llvmToAsmInstr;
}

retdec::utils::Maybe<unsigned> AsmInstruction::getLatency() const
{
	assert(false && "AsmInstruction::getLatency() not implemented.");
	retdec::utils::Maybe<unsigned> ret;
	return ret;
}

/**
 * @return Next ASM instruction after this ASM instrution. If there is none,
 *         returned ASM instruction is invalid.
 */
AsmInstruction AsmInstruction::getNext() const
{
	if (isInvalid())
	{
		return AsmInstruction();
	}

	Instruction* i = _llvmToAsmInstr;
	auto* bb = i->getParent();
	while (i && (i == _llvmToAsmInstr || !isLlvmToAsmInstructionPrivate(i)))
	{
		if (&bb->back() == i)
		{
			if (&bb->getParent()->back() == bb)
			{
				return AsmInstruction();
			}
			else
			{
				bb = bb->getNextNode();
				i = &bb->front();
			}
		}
		else
		{
			i = i->getNextNode();
		}
	}

	return AsmInstruction(i);
}

/**
 * @return Previous ASM instruction before this ASM instrution. If there is
 *         none, returned ASM instruction is invalid.
 */
AsmInstruction AsmInstruction::getPrev() const
{
	if (isInvalid())
	{
		return AsmInstruction();
	}

	Instruction* i = _llvmToAsmInstr;
	auto* bb = i->getParent();
	while (i && (i == _llvmToAsmInstr || !isLlvmToAsmInstructionPrivate(i)))
	{
		if (&bb->front() == i)
		{
			if (&bb->getParent()->front() == bb)
			{
				return AsmInstruction();
			}
			else
			{
				bb = bb->getPrevNode();
				i = &bb->back();
			}
		}
		else
		{
			i = i->getPrevNode();
		}
	}

	return AsmInstruction(i);
}

/**
 * It is possible to erase LLVM instructions, if none of them is used outside
 * of this ASM instruction -- when erased, there will not be any users left.
 * @return @c True if instruction can be erase, @c false otherwise.
 */
bool AsmInstruction::instructionsCanBeErased()
{
	auto bbs = getBasicBlocks();

	retdec::utils::NonIterableSet<const Value*> seen;
	for (auto it = rbegin(), e = rend(); it != e; ++it)
	{
		auto* i = &(*it);
		for (auto* u : i->users())
		{
			if (seen.hasNot(u) && i != u)
			{
				return false;
			}
		}
		seen.insert(i);
	}
	for (BasicBlock* bb : bbs)
	{
		if (bb != _llvmToAsmInstr->getParent())
		{
			for (auto* u : bb->users())
			{
				if (seen.hasNot(u))
				{
					return false;
				}
			}
		}
	}
	return true;
}

/**
 * If possible (see @c instructionsCanBeErased()), erase LLVM instructions
 * belonging to this ASM instruction.
 * If instructions can not be erased, they are not changed at all.
 * @return @c True if all instructions were successfully erased,
 *         @c false otherwise.
 */
bool AsmInstruction::eraseInstructions()
{
	if (!instructionsCanBeErased())
	{
		return false;
	}

	Function* genRet = nullptr;
	BasicBlock* nextBb = nullptr;
	auto insts = getInstructions();
	auto bbs = getBasicBlocks();

	for (auto it = insts.rbegin(); it != insts.rend(); ++it)
	{
		auto* i = *it;

		if (it == insts.rbegin()
				&& &i->getParent()->back() == i) // last inst in bb
		{
			auto* bb = i->getParent();
			if (&bb->getParent()->back() == bb) // las bb in function
			{
				genRet = bb->getParent();
			}
			else
			{
				nextBb = bb->getNextNode();
			}
		}

		i->eraseFromParent();
	}

	for (BasicBlock* bb : bbs)
	{
		if (bb->user_empty() && bb->empty())
		{
			bb->eraseFromParent();
		}
	}

	if (nextBb)
	{
		auto* br = BranchInst::Create(nextBb);
		br->insertAfter(_llvmToAsmInstr);
	}
	if (genRet)
	{
		auto* m = _llvmToAsmInstr->getModule();
		Value* retVal = nullptr;
		if (!genRet->getReturnType()->isVoidTy())
		{
			auto* ci = ConstantInt::get(Abi::getDefaultType(m), 0);
			retVal = IrModifier::convertConstantToType(ci, genRet->getReturnType());
		}

		auto* ret = ReturnInst::Create(m->getContext(), retVal);
		ret->insertAfter(_llvmToAsmInstr);
	}

	return true;
}

/**
 * Make this ASM instruction terminal -- last in BB, ending with
 * @c TerminatorInst.
 * If it already is terminal, nothing is modified and an existing terminator is
 * returned.
 * If it is not terminal yet, BB is split on the next ASM instruction, this
 * instruction ends with an unconditional branch to the new BB, and this branch
 * is returned.
 */
llvm::TerminatorInst* AsmInstruction::makeTerminal()
{
	auto next = getNext();
	if (next.isValid())
	{
		auto* last = back();
		BasicBlock* bb = last ? last->getParent() : getBasicBlock();

		if (bb == next.getBasicBlock())
		{
			next.getBasicBlock()->splitBasicBlock(
					next.getLlvmToAsmInstruction(),
					names::generateBasicBlockName(next.getAddress()));
			auto* b = dyn_cast_or_null<TerminatorInst>(back());
			assert(b);
			return b;
		}
		// Next in different BB -> no need to split -> ends with terminator.
		//
		else
		{
			auto* b = dyn_cast_or_null<TerminatorInst>(back());
			assert(b);
			return b;
		}
	}
	// No next -> last in function -> ends with terminator.
	//
	else
	{
		auto* b = dyn_cast_or_null<TerminatorInst>(back());
		assert(b);
		return b;
	}
}

/**
 * Make this ASM instruction start in basic block -- first in BB.
 * If it already is first, nothing is modified and an existing BB is returned.
 * If it is not first yet, split BB on it to create a new BB
 */
llvm::BasicBlock* AsmInstruction::makeStart(const std::string& name)
{
	// No previous node -> first in BB.
	//
	if (_llvmToAsmInstr->getPrevNode() == nullptr)
	{
		getBasicBlock()->setName(name.empty()
				? names::generateBasicBlockName(getAddress())
				: name);
		return getBasicBlock();
	}

	return getBasicBlock()->splitBasicBlock(
			_llvmToAsmInstr,
			name.empty() ? names::generateBasicBlockName(getAddress()) : name);
}

/**
 * @return Basic block where LLVM to ASM instruction belongs, or @c nullptr
 *         if ASM instruction not valid.
 */
llvm::BasicBlock* AsmInstruction::getBasicBlock() const
{
	return _llvmToAsmInstr ? _llvmToAsmInstr->getParent() : nullptr;
}

/**
 * @return Function where LLVM to ASM instruction belongs, or @c nullptr
 *         if ASM instruction not valid.
 */
llvm::Function* AsmInstruction::getFunction() const
{
	return _llvmToAsmInstr ? _llvmToAsmInstr->getFunction() : nullptr;
}

/**
 * @return Module where LLVM to ASM instruction belongs, or @c nullptr
 *         if ASM instruction not valid.
 */
llvm::Module* AsmInstruction::getModule() const
{
	return _llvmToAsmInstr ? _llvmToAsmInstr->getModule() : nullptr;
}

/**
 * @return Context where LLVM to ASM instruction belongs
 *         Use only on valid assembly instructions.
 */
llvm::LLVMContext& AsmInstruction::getContext() const
{
	return _llvmToAsmInstr->getContext();
}

std::vector<llvm::Instruction*> AsmInstruction::getInstructions()
{
	std::vector<llvm::Instruction*> ret;
	for (Instruction& i : *this)
	{
		ret.push_back(&i);
	}
	return ret;
}

std::vector<llvm::BasicBlock*> AsmInstruction::getBasicBlocks()
{
	std::vector<llvm::BasicBlock*> ret;
	for (Instruction& i : *this)
	{
		if (ret.empty() || ret.back() != i.getParent())
		{
			ret.push_back(i.getParent());
		}
	}
	return ret;
}

/**
 * @return First LLVM instruction in this ASM instruction, or @c nullptr if
 *         ASM instruction is empty.
 * @note Special LLVM to ASM mapping instruction is ignored, use dedicated
 *       method to get it.
 */
llvm::Instruction* AsmInstruction::front()
{
	auto b = begin();
	return b != end() ? &(*b) : nullptr;
}

bool AsmInstruction::empty()
{
	return front() == nullptr;
}

/**
 * @return Last LLVM instruction in this ASM instruction, or @c nullptr if
 *         ASM instruction is empty.
 * @note Special LLVM to ASM mapping instruction is ignored, use dedicated
 *       method to get it.
 */
llvm::Instruction* AsmInstruction::back()
{
	auto rb = rbegin();
	return rb != rend() ? &(*rb) : nullptr;
}

/**
 * Insert instruction @a i at the end of LLVM instructions associated with this
 * ASM instruction.
 * @note Be careful, this does not take care of potential terminators.
 *       If the last LLVM instruction is a terminator and you insert something
 *       after it, you will probably create an invalid module.
 * @return Inserted instruction.
 */
llvm::Instruction* AsmInstruction::insertBack(llvm::Instruction* i)
{
	auto* b = back();
	auto* l = b ? b : _llvmToAsmInstr;
	if (l)
	{
		i->insertAfter(l);
	}
	return i;
}

/**
 * Same as @c insertBack() but if asm instruction ends with terminator, the
 * new instruction is inserted before it.
 */
llvm::Instruction* AsmInstruction::insertBackSafe(llvm::Instruction* i)
{
	auto* b = back();
	auto* l = b ? b : _llvmToAsmInstr;
	if (l)
	{
		if (l->isTerminator())
		{
			i->insertBefore(l);
		}
		else
		{
			i->insertAfter(l);
		}
	}
	return i;
}

bool AsmInstruction::storesValue(llvm::Value* val) const
{
	for (auto& i : *this)
	{
		if (auto* s = dyn_cast<StoreInst>(&i))
		{
			if (s->getPointerOperand() == val)
			{
				return true;
			}
		}
	}

	return false;
}

std::string AsmInstruction::dump() const
{
	std::stringstream out;
	if (isValid())
	{
		out << "[ASM: " << getDsm() << " @ " << getAddress()
				<< " -- " << getEndAddress() << "]" << std::endl;

		out << llvmObjToString(_llvmToAsmInstr) << std::endl;
		const BasicBlock* bb = _llvmToAsmInstr->getParent();
		for (auto& i : *this)
		{
			if (bb != i.getParent())
			{
				bb = i.getParent();
				out << bb->getName().str() << ":" << std::endl;
			}
			out << llvmObjToString(&i) << std::endl;
		}
	}
	else
	{
		out << "INVALID" << std::endl;
	}

	return out.str();
}

std::ostream& operator<<(std::ostream& out, const AsmInstruction& a)
{
	return out << a.dump();
}

} // namespace bin2llvmir
} // namespace retdec
