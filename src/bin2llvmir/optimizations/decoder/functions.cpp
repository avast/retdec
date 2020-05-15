/**
* @file src/bin2llvmir/optimizations/decoder/functions.cpp
* @brief Decode input binary into LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"

using namespace retdec::common;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

/**
 * \return Start address for function \p f.
 */
common::Address Decoder::getFunctionAddress(llvm::Function* f)
{
	auto fIt = _fnc2addr.find(f);
	return fIt != _fnc2addr.end() ? fIt->second : Address();
}

/**
 * \return End address for function \p f.
 * \note End address is one byte beyond the function, i.e. <start, end).
 */
common::Address Decoder::getFunctionEndAddress(llvm::Function* f)
{
	if (f->empty() || f->back().empty())
	{
		return getFunctionAddress(f);
	}

	AsmInstruction ai(&f->back().back());
	return ai.isValid() ? ai.getEndAddress() : getFunctionAddress(f);
}

common::Address Decoder::getFunctionAddressAfter(common::Address a)
{
	auto it = _addr2fnc.upper_bound(a);
	return it != _addr2fnc.end() ? it->first : Address();
}

/**
 * \return Function exactly at address \p a.
 */
llvm::Function* Decoder::getFunctionAtAddress(common::Address a)
{
	auto fIt = _addr2fnc.find(a);
	return fIt != _addr2fnc.end() ? fIt->second : nullptr;
}

/**
 * \return The first function before or at address \p a.
 */
llvm::Function* Decoder::getFunctionBeforeAddress(common::Address a)
{
	if (_addr2fnc.empty())
	{
		return nullptr;
	}

	// Iterator to the first element whose key goes after a.
	auto it = _addr2fnc.upper_bound(a);

	// The first function is after a -> no function before a.
	if (it == _addr2fnc.begin())
	{
		return nullptr;
	}
	// No function after a -> the last function before a.
	else if (it == _addr2fnc.end())
	{
		return _addr2fnc.rbegin()->second;
	}
	// Function after a exists -> the one before it is before a.
	else
	{
		--it;
		return it->second;
	}
}

llvm::Function* Decoder::getFunctionAfterAddress(common::Address a)
{
	auto it = _addr2fnc.upper_bound(a);
	return it != _addr2fnc.end() ? it->second : nullptr;
}

/**
 * \return Function that contains the address \p a. I.e. \p a is between
 * function's start and end address.
 */
llvm::Function* Decoder::getFunctionContainingAddress(common::Address a)
{
	if (auto* f = getFunctionBeforeAddress(a))
	{
		Address end = getFunctionEndAddress(f);
		return a.isDefined() && end.isDefined() && a < end ? f : nullptr;
	}
	return nullptr;
}

/**
 * Create function at address \p a.
 * \return Created function.
 */
llvm::Function* Decoder::createFunction(common::Address a, bool declaration)
{
	auto existing = _addr2fnc.find(a);
	if (existing != _addr2fnc.end())
	{
		return existing->second;
	}

	bool known = _image->getImage()->hasDataOnAddress(a);

	std::string n = _names->getPreferredNameForAddress(a);
	if (n.empty())
	{
		n = known
				? names::generateFunctionName(a)
				: names::generateFunctionNameUnknown(a);
	}

	auto* f = llvm::Function::Create(
			FunctionType::get(
					Abi::getDefaultType(_module),
					false),
			GlobalValue::ExternalLinkage,
			n);

	Module::FunctionListType& fl = _module->getFunctionList();
	if (llvm::Function* before = getFunctionBeforeAddress(a))
	{
		fl.insertAfter(before->getIterator(), f);
	}
	else
	{
		fl.insert(fl.begin(), f);
	}

	if (!declaration && known)
	{
		createBasicBlock(a, f);
	}

	addFunction(a, f);

	return f;
}

void Decoder::addFunction(common::Address a, llvm::Function* f)
{
	_addr2fnc[a] = f;
	_fnc2addr[f] = a;
}

/**
 * Size \p sz is added only if function's \p f size was not set so far.
 * Use this function in more reliable, higher priority sources first.
 */
void Decoder::addFunctionSize(llvm::Function* f, std::optional<std::size_t> sz)
{
	if (_fnc2sz.count(f) == 0 && sz.has_value())
	{
		_fnc2sz.emplace(f, sz.value());
	}
}

} // namespace bin2llvmir
} // namespace retdec
