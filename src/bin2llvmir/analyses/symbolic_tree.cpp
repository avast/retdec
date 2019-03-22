/**
 * @file src/bin2llvmir/analyses/symbolic_tree.cpp
 * @brief Construction of symbolic tree from the given node.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>
#include <ostream>
#include <sstream>

#include <llvm/IR/Constants.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Operator.h>

#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/analyses/symbolic_tree.h"
#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/utils/debug.h"
#include "retdec/bin2llvmir/utils/symbolic_tree_match.h"

using namespace llvm;
using namespace retdec::bin2llvmir::st_match;

#define debug_enabled false

namespace retdec {
namespace bin2llvmir {

/**
 * No ReachingDefinitionsAnalysis -> on-demand UseDef/DefUse chains are used.
 */
SymbolicTree::SymbolicTree(
		llvm::Value* v,
		unsigned maxNodeLevel)
		:
		SymbolicTree(nullptr, v, nullptr, maxNodeLevel)
{

}

SymbolicTree::SymbolicTree(
		ReachingDefinitionsAnalysis& rda,
		llvm::Value* v,
		unsigned maxNodeLevel)
		:
		SymbolicTree(&rda, v, nullptr, maxNodeLevel)
{

}

SymbolicTree::SymbolicTree(
		ReachingDefinitionsAnalysis& rda,
		llvm::Value* v,
		std::map<llvm::Value*, llvm::Value*>* val2val,
		unsigned maxNodeLevel)
		:
		SymbolicTree(&rda, v, val2val, maxNodeLevel)
{

}

/**
 * Them main "public" ctor -- it is not really public, but all public ctors
 * end up here and it does all the work.
 */
SymbolicTree::SymbolicTree(
		ReachingDefinitionsAnalysis* rda,
		llvm::Value* v,
		std::map<llvm::Value*, llvm::Value*>* val2val,
		unsigned maxNodeLevel)
		:
		value(v)
{
	ops.reserve(_naryLimit);

	if (!_simplifyAtCreation)
	{
		maxNodeLevel += maxNodeLevel;
	}
	_val2valUsed = false;

	if (val2val)
	{
		auto fIt = val2val->find(value);
		if (fIt != val2val->end())
		{
			value = fIt->second;
			_val2valUsed = true;
			return;
		}
	}

	if (getLevel() == maxNodeLevel)
	{
		return;
	}

	std::unordered_set<Value*> processed;
	expandNode(rda, val2val, maxNodeLevel, processed);
}

SymbolicTree::SymbolicTree(
		ReachingDefinitionsAnalysis* rda,
		llvm::Value* v,
		llvm::Value* u,
		std::unordered_set<llvm::Value*>& processed,
		unsigned nodeLevel,
		unsigned maxNodeLevel,
		std::map<llvm::Value*, llvm::Value*>* val2val)
		:
		value(v),
		user(u),
		_level(nodeLevel)
{
	if (val2val)
	{
		auto fIt = val2val->find(value);
		if (fIt != val2val->end())
		{
			value = fIt->second;
			_val2valUsed = true;
			return;
		}
	}

	if (getLevel() == maxNodeLevel)
	{
		return;
	}

	expandNode(rda, val2val, maxNodeLevel, processed);
}

unsigned SymbolicTree::getLevel() const
{
	return _level;
}

SymbolicTree& SymbolicTree::operator=(SymbolicTree&& other)
{
	if (this != &other)
	{
		value = other.value;
		user = other.user;
		// Do NOT use `ops = std::move(other.ops);` to allow use like
		// `*this = ops[0];`. Use std::swap() instead.
		std::swap(ops, other.ops);
	}
	return *this;
}

bool SymbolicTree::operator==(const SymbolicTree& o) const
{
	if (ops != o.ops)
	{
		return false;
	}
	if (isa<Constant>(value) && isa<Constant>(o.value))
	{
		return value == o.value;
	}
	else if (isa<Instruction>(value) && isa<Instruction>(o.value))
	{
		auto* i1 = cast<Instruction>(value);
		auto* i2 = cast<Instruction>(o.value);
		return i1->isSameOperationAs(i2);
	}
	else
	{
		return false;
	}
}

bool SymbolicTree::operator!=(const SymbolicTree& o) const
{
	return !(*this == o);
}

void SymbolicTree::expandNode(
		ReachingDefinitionsAnalysis* RDA,
		std::map<llvm::Value*, llvm::Value*>* val2val,
		unsigned maxNodeLevel,
		std::unordered_set<llvm::Value*>& processed)
{
	if (RDA && RDA->wasRun())
	{
		auto fIt = processed.find(value);
		if (fIt != processed.end())
		{
			return;
		}
	}
	processed.insert(value);

	if (auto* l = dyn_cast<LoadInst>(value))
	{
		if (!_trackThroughAllocaLoads
				&& isa<AllocaInst>(l->getPointerOperand()))
		{
			return;
		}

		if (_trackOnlyFlagRegisters
				&& _abi
				&& _abi->isRegister(l->getPointerOperand())
				&& !_abi->isFlagRegister(l->getPointerOperand()))
		{
			return;
		}

		if (!_trackThroughGeneralRegisterLoads
				&& _abi
				&& _abi->isGeneralPurposeRegister(l->getPointerOperand()))
		{
			return;
		}

		if (RDA && RDA->wasRun())
		{
			auto defs = RDA->defsFromUse(l);
			if (defs.size() > _naryLimit)
			{
				ops.emplace_back(UndefValue::get(l->getType()));
				return;
			}
			else
			for (auto* d : defs)
			{
				ops.emplace_back(
						RDA,
						d->def,
						l,
						processed,
						getLevel() + 1,
						maxNodeLevel,
						val2val);
			}
		}
		else
		{
			auto defs = ReachingDefinitionsAnalysis::defsFromUse_onDemand(l);
			if (defs.size() > _naryLimit)
			{
				ops.emplace_back(UndefValue::get(l->getType()));
				return;
			}

			for (auto* d : defs)
			{
				ops.emplace_back(
						RDA,
						d,
						l,
						processed,
						getLevel() + 1,
						maxNodeLevel,
						val2val);
			}
		}

		if (ops.empty())
		{
			ops.emplace_back(
					RDA,
					l->getPointerOperand(),
					l,
					processed,
					getLevel() + 1,
					maxNodeLevel,
					val2val);
		}
	}
	else if (auto* s = dyn_cast<StoreInst>(value))
	{
		if (_simplifyAtCreation)
		{
			*this = SymbolicTree(
					RDA,
					s->getValueOperand(),
					s,
					processed,
					getLevel(),
					maxNodeLevel,
					val2val);
		}
		else
		{
			ops.emplace_back(
					RDA,
					s->getValueOperand(),
					s,
					processed,
					getLevel() + 1,
					maxNodeLevel,
					val2val);
		}
	}
	else if (isa<AllocaInst>(value)
			|| isa<CallInst>(value)
			|| (_abi
					&& _abi->isRegister(value)
					&& !_abi->isStackPointerRegister(value)
					&& !_abi->isZeroRegister(value)
					&& value != _abi->getRegister(MIPS_REG_GP, _abi->isMips())))
	{
		// nothing
	}
	else if (_simplifyAtCreation
			&& (isa<CastInst>(value) || isa<ConstantExpr>(value)))
	{
		auto* U = cast<User>(value);
		*this = SymbolicTree(
				RDA,
				U->getOperand(0),
				U,
				processed,
				getLevel(),
				maxNodeLevel,
				val2val);
	}
	else if (User* U = dyn_cast<User>(value))
	{
		for (unsigned i = 0; i < U->getNumOperands(); ++i)
		{
			ops.emplace_back(
					RDA,
					U->getOperand(i),
					U,
					processed,
					getLevel() + 1,
					maxNodeLevel,
					val2val);
		}
	}
}

void SymbolicTree::simplifyNode()
{
	_simplifyNode();
	fixLevel();
}

void SymbolicTree::_simplifyNode()
{
	if (ops.empty())
	{
		return;
	}

	for (auto &o : ops)
	{
		o._simplifyNode();
	}

	if (isa<LoadInst>(value) && ops.size() > 1)
	{
		bool allEq = true;

		SymbolicTree& op0 = ops[0];
		for (auto &o : ops)
		{
			if (op0 != o)
			{
				allEq = false;
				break;
			}
		}

		if (allEq)
		{
			ops.erase(ops.begin()+1, ops.end());
		}
	}

	Value* val = nullptr;
	LoadInst* load = nullptr;
	GlobalVariable* global = nullptr;
	ConstantInt* c1 = nullptr;
	ConstantInt* c2 = nullptr;

	if (isa<CastInst>(value))
	{
		*this = std::move(ops[0]);
	}
	else if (ConstantExpr* ce = dyn_cast<ConstantExpr>(value))
	{
		if (ce->isCast())
		{
			*this = std::move(ops[0]);
		}
	}
	else if (isa<StoreInst>(value))
	{
		*this = std::move(ops[0]);
	}
	// MIPS, use function address for t9.
	//
	else if (_abi->isMips()
			&& match(*this, m_Load(
					m_Specific(_abi->getRegister(MIPS_REG_T9)),
					&load)))
	{
		auto addr = AsmInstruction::getFunctionAddress(load->getFunction());
		value = ConstantInt::get(load->getType(), addr);
		ops.clear();
	}
	else if (match(*this, m_Load(m_GlobalVariable(global), &load))
			&& global == load->getPointerOperand()
			&& ops[0].ops.size() == 1)
	{
		*this = std::move(ops[0].ops[0]);
	}
	else if (match(*this, m_Load(m_Value(val), &load))
			&& (isa<AllocaInst>(llvm_utils::skipCasts(load->getPointerOperand()))
			|| isa<GlobalVariable>(llvm_utils::skipCasts(load->getPointerOperand()))))
	{
		*this = std::move(ops[0]);
	}
	else if (match(*this, m_Add(m_ConstantInt(c1), m_ConstantInt(c2))))
	{
		value = ConstantInt::get(
				c1->getType(),
				c1->getSExtValue() + c2->getSExtValue());
		ops.clear();
	}
	else if (match(*this, m_Sub(m_ConstantInt(c1), m_ConstantInt(c2))))
	{
		value = ConstantInt::get(
				c1->getType(),
				c1->getSExtValue() - c2->getSExtValue());
		ops.clear();
	}
	else if (match(*this, m_Or(m_ConstantInt(c1), m_ConstantInt(c2))))
	{
		value = ConstantInt::get(
				c1->getType(),
				c1->getSExtValue() | c2->getSExtValue());
		ops.clear();
	}
	else if (match(*this, m_And(m_ConstantInt(c1), m_ConstantInt(c2))))
	{
		value = ConstantInt::get(
				c1->getType(),
				c1->getSExtValue() & c2->getSExtValue());
		ops.clear();
	}
	else if (match(*this, m_Add(m_GlobalVariable(global), m_ConstantInt(c1)))
			&& ops[0].user && !isa<LoadInst>(ops[0].user)
			&& _config)
	{
		if (auto addr = _config->getGlobalAddress(global))
		{
			value = ConstantInt::get(c1->getType(), addr + c1->getSExtValue());
			ops.clear();
		}
	}
	else if (match(*this, m_Add(m_Value(), m_Zero()))
			|| match(*this, m_Sub(m_Value(), m_Zero())))
	{
		*this = std::move(ops[0]);
	}
	else if (match(*this, m_Add(m_Zero(), m_Value()))
			|| match(*this, m_Sub(m_Zero(), m_Value())))
	{
		*this = std::move(ops[1]);
	}
	else if (match(*this, m_Add(
			m_Add(m_Value(), m_ConstantInt(c1)),
			m_ConstantInt(c2))))
	{
		ops[0] = std::move(ops[0].ops[0]);
		ops[1].value = ConstantInt::get(
				c1->getType(),
				c1->getSExtValue() + c2->getSExtValue());
	}

	// Move Constants from ops[0] to ops[1].
	//
	auto* i = dyn_cast<Instruction>(value);
	if (i && (i->isCommutative() || isa<LoadInst>(i))
			&& ops.size() == 2
			&& isa<Constant>(ops[0].value)
			&& !isa<Constant>(ops[1].value))
	{
		std::swap(ops[0], ops[1]);
	}
}

/**
 * If at address 33888 in @a image is value 76092 then transform:
 * >|   %u6_83f0 = load i32, i32* inttoptr (i32 33888 to i32*), align 32
 *        >| i32 33888
 * Into:
 * >|   76092
 *
 */
void SymbolicTree::solveMemoryLoads(FileImage* image)
{
	for (auto &o : ops)
	{
		o.solveMemoryLoads(image);
	}

	auto* t = dyn_cast<IntegerType>(value->getType());
	if (isa<LoadInst>(value)
			&& t
			&& ops.size() == 1
			&& isa<ConstantInt>(ops[0].value))
	{
		auto* ci = cast<ConstantInt>(ops[0].value);
		auto* seg = image->getImage()->getSegmentFromAddress(ci->getZExtValue());
		auto* sec = seg ? seg->getSecSeg() : nullptr;
		if (seg && (sec == nullptr || !sec->isBss()))
		{
			auto* res = image->getConstantInt(t, ci->getZExtValue());
			if (res)
			{
				value = res;
				ops.clear();
			}
		}
	}
}

SymbolicTree* SymbolicTree::getMaxIntValue()
{
	SymbolicTree* max = nullptr;

	if (!isa<GlobalVariable>(value))
	for (auto &o : ops)
	{
		auto* m = o.getMaxIntValue();
		auto* mc = m ? dyn_cast_or_null<ConstantInt>(m->value) : nullptr;
		auto* maxc = max ? dyn_cast_or_null<ConstantInt>(max->value) : nullptr;
		if (max == nullptr || maxc == nullptr)
		{
			max = m;
		}
		else if (m && mc && mc->getSExtValue() > maxc->getSExtValue())
		{
			max = m;
		}
	}

	if (auto* c = dyn_cast<ConstantInt>(value))
	{
		auto* maxc = max ? dyn_cast_or_null<ConstantInt>(max->value) : nullptr;
		if (max == nullptr || maxc == nullptr)
		{
			max = this;
		}
		else if (c->getSExtValue() > maxc->getSExtValue())
		{
			max = this;
		}
	}

	return max;
}

std::string SymbolicTree::print(unsigned indent) const
{
	std::stringstream out;
	if (Function* F = dyn_cast<Function>(value))
		out << retdec::utils::getIndentation(indent) << ">| "
			<< F->getName().str() << std::endl;
	else
		out << retdec::utils::getIndentation(indent) << ">| "
			<< llvmObjToString(value) << std::endl;

	++indent;
	for (const auto& o : ops)
		out << o.print(indent);
	return out.str();
}

std::ostream& operator<<(std::ostream& out, const SymbolicTree& s)
{
	out << "-----------------------------------------------" << std::endl;
	out << s.print(0);
	out << "-----------------------------------------------" << std::endl;
	return out;
}

/**
 * @return Tree nodes linearized using a pre-order traversal.
 * @note You can change the nodes (they are not constant) but keep in mind
 * that your changes might make the vector inconsistent -- i.e. changes you
 * make are not reflected in it. For example, if you change children of some
 * node and then continue to iterate over the vector, vector elements will
 * not be the real children after the change.
 * Post-order vector is much more suitable for modifications.
 */
std::vector<SymbolicTree*> SymbolicTree::getPreOrder() const
{
	std::vector<SymbolicTree*> ret;
	_getPreOrder(ret);
	return ret;
}

/**
 * @return Tree nodes linearized using a post-order traversal.
 * @note See note for @c getPreOrder(). The same holds here -- you may damage
 * vector's consistency if you make changes to nodes as you iterate over them.
 * However, thanks to the bottom-up nature of post-order traversal, this may
 * not be a problem if you modify only the actual node and its children -- they
 * were already iterated over.
 */
std::vector<SymbolicTree*> SymbolicTree::getPostOrder() const
{
	std::vector<SymbolicTree*> ret;
	_getPostOrder(ret);
	return ret;
}

/**
 * @return Tree nodes linearized using a level-order traversal.
 */
std::vector<SymbolicTree*> SymbolicTree::getLevelOrder() const
{
	std::vector<SymbolicTree*> ret;
	_getPreOrder(ret);

	std::stable_sort(ret.begin(), ret.end(),
			[](const SymbolicTree* a, const SymbolicTree* b) -> bool
			{
				return a->getLevel() < b->getLevel();
			});

	return ret;
}

void SymbolicTree::_getPreOrder(std::vector<SymbolicTree*>& res) const
{
	res.emplace_back(const_cast<SymbolicTree*>(this));
	for (auto &o : ops)
	{
		o._getPreOrder(res);
	}
}

void SymbolicTree::_getPostOrder(std::vector<SymbolicTree*>& res) const
{
	for (auto &o : ops)
	{
		o._getPostOrder(res);
	}
	res.emplace_back(const_cast<SymbolicTree*>(this));
}

void SymbolicTree::fixLevel(unsigned level)
{
	if (level == 0)
	{
		level = _level;
	}
	else
	{
		_level = level;
	}
	for (auto &o : ops)
	{
		o.fixLevel(level + 1);
	}
}

bool SymbolicTree::isNullary() const
{
	return ops.size() == 0;
}

bool SymbolicTree::isUnary() const
{
	return ops.size() == 1;
}

bool SymbolicTree::isBinary() const
{
	return ops.size() == 2;
}

bool SymbolicTree::isTernary() const
{
	return ops.size() == 3;
}

bool SymbolicTree::isNary(unsigned N) const
{
	return ops.size() == N;
}

//
//==============================================================================
// Static methods.
//==============================================================================
//

Abi* SymbolicTree::_abi = nullptr;
Config* SymbolicTree::_config = nullptr;
bool SymbolicTree::_val2valUsed = false;
bool SymbolicTree::_trackThroughAllocaLoads = true;
bool SymbolicTree::_trackThroughGeneralRegisterLoads = true;
bool SymbolicTree::_trackOnlyFlagRegisters = false;
bool SymbolicTree::_simplifyAtCreation = true;
unsigned SymbolicTree::_naryLimit = 3;

void SymbolicTree::setToDefaultConfiguration()
{
	_trackThroughAllocaLoads = true;
	_trackThroughGeneralRegisterLoads = true;
	_trackOnlyFlagRegisters = false;
	_simplifyAtCreation = true;
	_naryLimit = 3;
}

bool SymbolicTree::isVal2ValMapUsed()
{
	return _val2valUsed;
}

void SymbolicTree::setAbi(Abi* abi)
{
	_abi = abi;
}

void SymbolicTree::setConfig(Config* config)
{
	_config = config;
}

void SymbolicTree::setTrackThroughAllocaLoads(bool b)
{
	_trackThroughAllocaLoads = b;
}

void SymbolicTree::setTrackThroughGeneralRegisterLoads(bool b)
{
	_trackThroughGeneralRegisterLoads = b;
}

void SymbolicTree::setTrackOnlyFlagRegisters(bool b)
{
	_trackOnlyFlagRegisters = b;
}

void SymbolicTree::setSimplifyAtCreation(bool b)
{
	_simplifyAtCreation = b;
}

void SymbolicTree::setNaryLimit(unsigned n)
{
	_naryLimit = n;
}

} // namespace bin2llvmir
} // namespace retdec
