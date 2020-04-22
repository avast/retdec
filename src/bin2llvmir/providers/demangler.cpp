/**
 * @file src/bin2llvmir/providers/demangler.cpp
 * @brief Demangler provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <retdec/loader/loader/image.h>
#include "retdec/bin2llvmir/providers/demangler.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/utils/ctypes2llvm.h"
#include "retdec/ctypes/module.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/function_type.h"
#include "retdec/ctypesparser/type_config.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

/******************************************************************/
/************************** Demangler *****************************/
/******************************************************************/

Demangler::Demangler(
	llvm::Module *llvmModule,
	Config *config,
	const std::shared_ptr<ctypesparser::TypeConfig> &typeConfig,
	std::unique_ptr<retdec::demangler::Demangler> demangler) :
	_llvmModule(llvmModule),
	_config(config),
	_ctypesModule(std::make_unique<ctypes::Module>(std::make_shared<ctypes::Context>())),
	_typeConfig(typeConfig),
	_demangler(std::move(demangler)) {}

std::string Demangler::demangleToString(const std::string &mangled)
{
	return _demangler->demangleToString(mangled);
}

Demangler::FunctionPair Demangler::getPairFunction(const std::string &mangled)
{
	auto ctypesFunction = _demangler->demangleFunctionToCtypes(
		mangled,
		_ctypesModule,
		_typeConfig->typeWidths(),
		_typeConfig->typeSignedness(),
		_typeConfig->defaultBitWidth()
	);
	if (ctypesFunction == nullptr) {
		return {};
	}

	auto *ft = dyn_cast<FunctionType>(getLlvmType(ctypesFunction->getType()));
	assert(ft);

	auto *ret = Function::Create(ft, GlobalValue::ExternalLinkage, ctypesFunction->getName());

	return {ret, ctypesFunction};
}

llvm::Type *Demangler::getLlvmType(std::shared_ptr<retdec::ctypes::Type> type)
{
	Ctypes2LlvmTypeVisitor visitor(_llvmModule, _config);
	type->accept(&visitor);
	return visitor.getLlvmType();
}

demangler::Demangler* Demangler::getDemangler()
{
	return _demangler.get();
}

/******************************************************************/
/********************** Demangler Factory *************************/
/******************************************************************/

/**
 * @brief Crates new instance of ItaniumDemangler.
 * @return unique_ptr to created demangler instance
 */
std::unique_ptr<Demangler> DemanglerFactory::getItaniumDemangler(
	llvm::Module *m,
	Config *config,
	const std::shared_ptr<ctypesparser::TypeConfig> &typeConfig)
{
	return std::make_unique<Demangler>(
		m, config, typeConfig, std::make_unique<demangler::ItaniumDemangler>());
}

/**
 * @brief Crates new instance of MicrosoftDemangler.
 * @return unique_ptr to created demangler instance
 */
std::unique_ptr<Demangler> DemanglerFactory::getMicrosoftDemangler(
	llvm::Module *m,
	Config *config,
	const std::shared_ptr<ctypesparser::TypeConfig> &typeConfig)
{
	return std::make_unique<Demangler>(
		m, config, typeConfig, std::make_unique<demangler::MicrosoftDemangler>());
}

/**
 * @brief Crates new instance of BorlandDemangler.
 * @return unique_ptr to created demangler instance
 */
std::unique_ptr<Demangler> DemanglerFactory::getBorlandDemangler(
	llvm::Module *m,
	Config *config,
	const std::shared_ptr<ctypesparser::TypeConfig> &typeConfig)
{
	return std::make_unique<Demangler>(
		m, config, typeConfig, std::make_unique<demangler::BorlandDemangler>());
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
	llvm::Module *llvmModule,
	Config *config,
	const std::shared_ptr<ctypesparser::TypeConfig> &typeConfig)
{
	auto t = config->getConfig().tools;

	std::unique_ptr<Demangler> d;
	if (t.isGcc() || t.isMingw()) {
		d = DemanglerFactory::getItaniumDemangler(llvmModule, config, typeConfig);
	} else if (t.isMsvc()) {
		d = DemanglerFactory::getMicrosoftDemangler(llvmModule, config, typeConfig);
	} else if (t.isBorland() || t.isDelphi()) {
		d = DemanglerFactory::getBorlandDemangler(llvmModule, config, typeConfig);
	} else {
		d = DemanglerFactory::getItaniumDemangler(llvmModule, config, typeConfig);
	}

	auto p = _module2demangler.insert(std::make_pair(llvmModule, std::move(d)));

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
