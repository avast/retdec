/**
 * @file src/bin2llvmir/optimizations/class_hierarchy/hierarchy.cpp
 * @brief Represents class hierarchy.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "retdec/demangler/demangler.h"
#include "retdec/bin2llvmir/optimizations/class_hierarchy/hierarchy.h"
#include "retdec/bin2llvmir/providers/demangler.h"

namespace retdec {
namespace bin2llvmir {

//
//=============================================================================
//  Class
//=============================================================================
//

std::string Class::dump() const
{
	std::stringstream out;

	out << "\tname         : " << name << std::endl;

	out << "\tsuperclasses :" << std::endl;
	for (auto* c : superClasses)
		out << "\t\t" << c->name << std::endl;

	out << "\tconstructors :" << std::endl;
	for (auto* f : constructors)
		out << "\t\t" << f->getName().str() << std::endl;

	out << "\tdestructors  :" << std::endl;
	for (auto* f : destructors)
		out << "\t\t" << f->getName().str() << std::endl;

	out << "\tvirtual fncs :" << std::endl;
	for (auto* f : virtualFunctions)
		out << "\t\t" << f->getName().str() << std::endl;

	out << "\tmethods      :" << std::endl;
	for (auto* f : methods)
		out << "\t\t" << f->getName().str() << std::endl;

	out << "\tvtables      :" << std::endl;
	for (auto* vt : virtualFunctionTables)
		out << "\t\t" << vt->vtableAddress << std::endl;

	return out.str();
}

retdec::config::Class Class::getConfigClass(
		llvm::Module* m,
		Config* config) const
{
	retdec::config::Class c(name);

	auto* demangler = DemanglerProvider::getDemangler(m);
	if (demangler)
	{
		c.setDemangledName(demangler->demangleToString(name));
	}

	for (auto* s : superClasses)
	{
		c.addSuperClass(s->name);
	}

	for (auto* f : constructors)
	{
		c.constructors.insert(f->getName().str());
		auto* cf = config->getConfigFunction(f);
		if (cf)
		{
			cf->setIsConstructor(true);
		}
	}

	for (auto* f : destructors)
	{
		c.destructors.insert(f->getName().str());
		auto* cf = config->getConfigFunction(f);
		if (cf)
		{
			cf->setIsDestructor(true);
		}
	}

	for (auto* f : virtualFunctions)
	{
		c.virtualMethods.insert(f->getName().str());
		auto* cf = config->getConfigFunction(f);
		if (cf)
		{
			cf->setIsVirtual(true);
		}
	}

	for (auto* f : methods)
	{
		c.methods.insert(f->getName().str());
	}

	for (auto* vt : virtualFunctionTables)
	{
		c.virtualTables.insert(names::generateVtableName(vt->vtableAddress));
	}

	return c;
}

//
//=============================================================================
//  ClassHierarchy
//=============================================================================
//

Class* ClassHierarchy::addAndGetNewClass()
{
	classes.push_back( Class() );
	return &classes.back();
}

std::string ClassHierarchy::dump() const
{
	std::stringstream out;

	unsigned cntr = 0;
	for (auto& c : classes)
	{
		out << "Class #" << cntr++ << std::endl;
		out << c.dump();
	}

	return out.str();
}

} // namespace bin2llvmir
} // namespace retdec
