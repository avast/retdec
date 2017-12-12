/**
 * @file include/bin2llvmir/optimizations/class_hierarchy/hierarchy.h
 * @brief Represents class hierarchy.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef BIN2LLVMIR_OPTIMIZATIONS_CLASS_HIERARCHY_HIERARCHY_H
#define BIN2LLVMIR_OPTIMIZATIONS_CLASS_HIERARCHY_HIERARCHY_H

#include <list>
#include <set>
#include <vector>

#include <llvm/IR/Function.h>

#include "bin2llvmir/optimizations/vtable/vtable.h"
#include "bin2llvmir/providers/config.h"

namespace bin2llvmir {

/**
 *
 */
class Class
{
	public:
		std::string dump() const;
		retdec_config::Class getConfigClass(
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

#endif
