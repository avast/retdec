/**
 * @file src/bin2llvmir/providers/demangler.cpp
 * @brief Demangler provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/demangler.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

/******************************************************************/
/************************** Demangler *****************************/
/******************************************************************/

Demangler::Demangler(
	std::unique_ptr<retdec::demangler::Demangler> demangler,
	std::shared_ptr<ctypes::Module> &module) :
	_demangler(std::move(demangler)), _module(module) {}

std::string Demangler::demangleToString(const std::string &mangled)
{
	return _demangler->demangleToString(mangled);
}

//Demangler::FunctionPair Demangler::getPairFunction(const std::string &mangled)
//{
//	auto ctypes
//}

/******************************************************************/
/********************** Demangler Factory *************************/
/******************************************************************/

/**
 * @brief Abstracts instation logic, when we want specific demangler.
 * @param compiler Name of compiler mangling scheme.
 * @return Specific demangler on success or nullptr on failure.
 */
std::unique_ptr<Demangler> DemanglerFactory::getDemangler(
	const std::string &compiler,
	std::shared_ptr<ctypes::Module> &module)
{
	if (compiler == "itanium" || compiler == "gcc" || compiler == "clang") {
		return getItaniumDemangler(module);
	} else if (compiler == "microsoft") {
		return getMicrosoftDemangler(module);
	} else if (compiler == "borland") {
		return getBorlandDemangler(module);
	}

	// default get itanium
	return getItaniumDemangler(module);
}

/**
 * @brief Crates new instance of ItaniumDemangler.
 * @return unique_ptr to created demangler instance
 */
std::unique_ptr<Demangler> DemanglerFactory::getItaniumDemangler(
	std::shared_ptr<ctypes::Module> &module)
{
	return std::make_unique<Demangler>(std::make_unique<demangler::ItaniumDemangler>(), module);
}

/**
 * @brief Crates new instance of MicrosoftDemangler.
 * @return unique_ptr to created demangler instance
 */
std::unique_ptr<Demangler> DemanglerFactory::getMicrosoftDemangler(
	std::shared_ptr<ctypes::Module> &module)
{
	return std::make_unique<Demangler>(std::make_unique<demangler::MicrosoftDemangler>(), module);
}

/**
 * @brief Crates new instance of BorlandDemangler.
 * @return unique_ptr to created demangler instance
 */
std::unique_ptr<Demangler> DemanglerFactory::getBorlandDemangler(
	std::shared_ptr<ctypes::Module> &module)
{
	return std::make_unique<Demangler>(std::make_unique<demangler::BorlandDemangler>(), module);
}

/******************************************************************/
/********************** Demangler Provider ************************/
/******************************************************************/
std::map<Module *, std::unique_ptr<Demangler>> DemanglerProvider::_module2demangler;

/**
 * Create and add to provider a demangler for the given module @a m
 * and tools @a t.
 * @return Created and added demangler or @c nullptr if something went wrong
 *         and it was not successfully created.
 */
Demangler *DemanglerProvider::addDemangler(
	llvm::Module *m,
	const retdec::config::ToolInfoContainer &t,
	std::shared_ptr<ctypes::Module> &ltiModule)
{
	std::unique_ptr<Demangler> d;

	if (t.isGcc()) {
		d = DemanglerFactory::getItaniumDemangler(ltiModule);
	} else if (t.isMsvc()) {
		d = DemanglerFactory::getMicrosoftDemangler(ltiModule);
	} else if (t.isBorland()) {
		d = DemanglerFactory::getBorlandDemangler(ltiModule);
	} else {
		d = DemanglerFactory::getItaniumDemangler(ltiModule);
	}

	auto p = _module2demangler.insert(std::make_pair(m, std::move(d)));

	return p.first->second.get();
}

/**
 * @return Get demangler associated with the given module @a m or @c nullptr
 *         if there is no associated demangler.
 */
Demangler *DemanglerProvider::getDemangler(llvm::Module *m)
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
	llvm::Module *m,
	Demangler *&d)
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
