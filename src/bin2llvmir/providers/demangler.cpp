/**
 * @file src/bin2llvmir/providers/demangler.cpp
 * @brief Demangler provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/demangler.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

std::map<Module*, DemanglerProvider::Demangler> DemanglerProvider::_module2demangler;

/**
 * Create and add to provider a demangler for the given module @a m
 * and tools @a t.
 * @return Created and added demangler or @c nullptr if something went wrong
 *         and it was not successfully created.
 */
retdec::demangler::CDemangler* DemanglerProvider::addDemangler(
		llvm::Module* m,
		const retdec::config::ToolInfoContainer& t)
{
	std::unique_ptr<retdec::demangler::CDemangler> d;

	if (t.isGcc())
	{
		d = retdec::demangler::CDemangler::createGcc();
	}
	else if (t.isMsvc())
	{
		d = retdec::demangler::CDemangler::createMs();
	}
	else if (t.isBorland())
	{
		d = retdec::demangler::CDemangler::createBorland();
	}
	else
	{
		d = retdec::demangler::CDemangler::createGcc();
	}

	auto p = _module2demangler.insert(std::make_pair(m, std::move(d)));

	return p.first->second.get();
}

/**
 * @return Get demangler associated with the given module @a m or @c nullptr
 *         if there is no associated demangler.
 */
retdec::demangler::CDemangler* DemanglerProvider::getDemangler(llvm::Module* m)
{
	auto f = _module2demangler.find(m);
	return f != _module2demangler.end() ? f->second.get() : nullptr;
}

/**
 * Get demangler @a d associated with the module @a m.
 * @param[in]  m Module for which to get demangler.
 * @param[out] d Set to demangler associated with @a m module, or @c nullptr
 *               if there is no associated demangler.
 * @return @c True if demangler @a d was set ok and can be used.
 *         @c False otherwise.
 */
bool DemanglerProvider::getDemangler(
		llvm::Module* m,
		retdec::demangler::CDemangler*& d)
{
	d = getDemangler(m);
	return d != nullptr;
}

/**
 * Clear all stored data.
 */
void DemanglerProvider::clear()
{
	_module2demangler.clear();
}

} // namespace bin2llvmir
} // namespace retdec
