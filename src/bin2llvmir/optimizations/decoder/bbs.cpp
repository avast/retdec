/**
* @file src/bin2llvmir/optimizations/decoder/bbs.cpp
* @brief Decode input binary into LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

/**
 * \return Start address for basic block \p f.
 */
utils::Address Decoder::getBasicBlockAddress(llvm::BasicBlock* b)
{
	auto likelyIt = _likelyBb2Target.find(b);
	if (likelyIt != _likelyBb2Target.end())
	{
		b = likelyIt->second;
	}

	auto fIt = _bb2addr.find(b);
	return fIt != _bb2addr.end() ? fIt->second : Address();
}

/**
 * \return End address for basic block \p b - the end address of the last
 *         instruction in the basic block.
 */
utils::Address Decoder::getBasicBlockEndAddress(llvm::BasicBlock* b)
{
	if (b->empty())
	{
		return getBasicBlockAddress(b);
	}

	AsmInstruction ai(&b->back());
	return ai.isValid() ? ai.getEndAddress() : getBasicBlockAddress(b);
}

/**
 * \return Address of the first basic block after address \p a.
 */
utils::Address Decoder::getBasicBlockAddressAfter(utils::Address a)
{
	auto it = _addr2bb.upper_bound(a);
	return it != _addr2bb.end() ? it->first : Address();
}

/**
 * \return Basic block exactly at address \p a.
 */
llvm::BasicBlock* Decoder::getBasicBlockAtAddress(utils::Address a)
{
	auto fIt = _addr2bb.find(a);
	return fIt != _addr2bb.end() ? fIt->second : nullptr;
}

/**
 * \return The first basic block before or at address \p a.
 */
llvm::BasicBlock* Decoder::getBasicBlockBeforeAddress(utils::Address a)
{
	if (_addr2bb.empty())
	{
		return nullptr;
	}

	// Iterator to the first element whose key goes after a.
	auto it = _addr2bb.upper_bound(a);

	// The first BB is after a -> no BB before a.
	if (it == _addr2bb.begin())
	{
		return nullptr;
	}
	// No BB after a -> the last BB before a.
	else if (it == _addr2bb.end())
	{
		return _addr2bb.rbegin()->second;
	}
	// BB after a exists -> the one before it is before a.
	else
	{
		--it;
		return it->second;
	}
}

/**
 * \return The first basic block after address \p a.
 */
llvm::BasicBlock* Decoder::getBasicBlockAfterAddress(utils::Address a)
{
	auto it = _addr2bb.upper_bound(a);
	return it != _addr2bb.end() ? it->second : nullptr;
}

/**
 * \return Basic block that contains the address \p a. I.e. \p a is between
 * basic blocks's start and end address.
 */
llvm::BasicBlock* Decoder::getBasicBlockContainingAddress(utils::Address a)
{
	auto* b = getBasicBlockBeforeAddress(a);
	if (b == nullptr)
	{
		return nullptr;
	}

	llvm::BasicBlock* bbEnd = b;
	while (bbEnd->getNextNode())
	{
		// Next has address -- is a proper BB.
		//
		if (getBasicBlockAddress(bbEnd->getNextNode()).isDefined())
		{
			break;
		}
		else
		{
			bbEnd = bbEnd->getNextNode();
		}
	}
	Address end = getBasicBlockEndAddress(bbEnd);
	return a.isDefined() && end.isDefined() && a < end ? b : nullptr;
}

/**
 * Create basic block at address \p a in function \p f right after basic
 * block \p insertAfter.
 * \return Created function.
 */
llvm::BasicBlock* Decoder::createBasicBlock(
		utils::Address a,
		llvm::Function* f,
		llvm::BasicBlock* insertAfter)
{
	auto* next = insertAfter ? insertAfter->getNextNode() : nullptr;
	while (!(next == nullptr || _bb2addr.count(next)))
	{
		next = next->getNextNode();
	}

	auto* b = BasicBlock::Create(
			_module->getContext(),
			names::generateBasicBlockName(a),
			f,
			next);

	IRBuilder<> irb(b);
	irb.CreateRet(UndefValue::get(f->getReturnType()));

	addBasicBlock(a, b);

	return b;
}

void Decoder::addBasicBlock(utils::Address a, llvm::BasicBlock* b)
{
	_addr2bb[a] = b;
	_bb2addr[b] = a;
}

} // namespace bin2llvmir
} // namespace retdec
