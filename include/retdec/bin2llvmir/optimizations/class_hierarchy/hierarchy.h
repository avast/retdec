/**
 * @file include/retdec/bin2llvmir/optimizations/class_hierarchy/hierarchy.h
 * @brief Represents class hierarchy.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_CLASS_HIERARCHY_HIERARCHY_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_CLASS_HIERARCHY_HIERARCHY_H

#include <list>
#include <set>
#include <vector>

#include <llvm/IR/Function.h>

#include "retdec/bin2llvmir/optimizations/vtable/vtable.h"
#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

/**
 *
 */
class Class
{
	public:
		std::string dump() const;
		retdec::config::Class getConfigClass(
				llvm::Module* m,
				Config* config) const;

	public:
		std::string name;
		std::set<const llvm::Function*> constructors;
		std::set<const llvm::Function*> destructors;
		std::set<const llvm::Function*> methods;
		std::set<const llvm::Function*> virtualFunctions;
		std::set<const Vtable*> virtualFunctionTables;
		std::set<Class*> superClasses;
		llvm::Value* structure;

		ClassTypeInfo* gccRtti;
		RTTITypeDescriptor* msvcRtti;
};

/**
 *
 */
class ClassHierarchy
{
	public:
		Class* addAndGetNewClass();

		std::string dump() const;

	public:
		std::list<Class> classes;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
