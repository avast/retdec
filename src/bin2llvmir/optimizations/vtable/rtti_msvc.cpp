/**
 * @file src/bin2llvmir/optimizations/vtable/rtti_msvc.cpp
 * @brief Search for msvc RTTI in input file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>
#include <sstream>

#include "retdec/bin2llvmir/optimizations/vtable/rtti_msvc.h"
#include "retdec/bin2llvmir/utils/defs.h"

#define debug_enabled false

namespace retdec {
namespace bin2llvmir {

//
//=============================================================================
//  RTTITypeDescriptor
//=============================================================================
//

std::string RTTITypeDescriptor::dump() const
{
	std::stringstream out;
	out << "RTTITypeDescriptor @ " << address << "\n";
	out << "\tvt addr = " << vtableAddr << "\n";
	out << "\tspare   = " << spare << "\n";
	out << "\tname    = " << name << "\n";
	return out.str();
}

//
//=============================================================================
//  RTTIBaseClassDescriptor
//=============================================================================
//

std::string RTTIBaseClassDescriptor::dump() const
{
	assert(typeDescriptor);

	std::stringstream out;
	out << "RTTIBaseClassDescriptor @ " << address << "\n";
	out << "\ttd addr = " << typeDescriptorAddr << "\n";
	out << "\tnum bs  = " << numContainedBases << "\n";
	out << "\t\tmdistp  = " << where.mdisp << "\n";
	out << "\t\tpdisp   = " << where.pdisp << "\n";
	out << "\t\tvdisp   = " << where.vdisp << "\n";
	out << "\tattrs   = " << attributes << "\n";
	out << typeDescriptor->dump();
	return out.str();
}

//
//=============================================================================
//  RTTIClassHierarchyDescriptor
//=============================================================================
//

std::string RTTIClassHierarchyDescriptor::dump() const
{
	std::stringstream out;
	out << "RTTIClassHierarchyDescriptor @ " << address << "\n";
	out << "\tsign    = " << signature << "\n";
	out << "\tattr    = " << attributes << "\n";
	out << "\tbase num= " << numBaseClasses << "\n";
	out << "\tbase aa = " << baseClassArrayAddr << "\n";
	out << "\tbase a  =";
	for (auto a : baseClassArray)
		out << " " << a;
	out << "\n";
	for (auto a : baseClasses)
		out << a->dump();
	out << "\n";

	return out.str();
}

//
//=============================================================================
//  RTTICompleteObjectLocator
//=============================================================================
//

std::string RTTICompleteObjectLocator::dump() const
{
	assert(typeDescriptor);
	assert(classDescriptor);

	std::stringstream out;
	out << "\n=========================================================\n";
	out << "RTTICompleteObjectLocator @ " << address << "\n";
	out << "\tsign    = " << signature << "\n";
	out << "\toff     = " << offset << "\n";
	out << "\tcd off  = " << cdOffset << "\n";
	out << "\ttd addr = " << typeDescriptorAddr << "\n";
	out << "\tcd addr = " << classDescriptorAddr << "\n";
	out << typeDescriptor->dump();
	out << classDescriptor->dump();
	out << "=========================================================\n\n";
	return out.str();
}

} // namespace bin2llvmir
} // namespace retdec
