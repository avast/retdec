/**
 * @file src/bin2llvmir/optimizations/vtable/rtti_gcc.cpp
 * @brief Search for gcc&clang RTTI in input file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>
#include <sstream>

#include "retdec/bin2llvmir/optimizations/vtable/rtti_gcc.h"
#include "retdec/bin2llvmir/utils/defs.h"

#define debug_enabled false

namespace retdec {
namespace bin2llvmir {

//
//=============================================================================
//  TypeInfo
//=============================================================================
//

TypeInfo::~TypeInfo()
{
}

bool TypeInfo::operator==(const TypeInfo& o) const
{
	return nameAddr == o.nameAddr;
}

bool TypeInfo::operator!=(const TypeInfo& o) const
{
	return !(*this == o);
}

std::string TypeInfo::dump() const
{
	std::stringstream out;
	out << "TypeInfo @ " << address << "\n";
	out << "\tvptr addr = " << vtableAddr << "\n";
	out << "\tname addr = " << nameAddr << "\n";
	out << "\tname ntbs = " << name << "\n";
	return out.str();
}

//
//=============================================================================
//  ClassTypeInfo
//=============================================================================
//

std::string ClassTypeInfo::dump() const
{
	std::stringstream out;
	out << TypeInfo::dump();
	out << "\tClassTypeInfo" << "\n";
	return out.str();
}

//
//=============================================================================
//  SiClassTypeInfo
//=============================================================================
//

std::string SiClassTypeInfo::dump() const
{
	assert(baseClass);

	std::stringstream out;
	out << ClassTypeInfo::dump();
	out << "\tSiClassTypeInfo" << "\n";
	out << "\t\tbase addr = " << baseClassAddr << "\n";
	out << "\t\tbase name = " << baseClass->name << "\n";
	return out.str();
}

//
//=============================================================================
//  VmiClassTypeInfo
//=============================================================================
//

std::string VmiClassTypeInfo::dump() const
{
	std::stringstream out;
	out << ClassTypeInfo::dump();
	out << "\tVmiClassTypeInfo" << "\n";
	out << "\t\tflags     = " << std::hex << flags << "\n";
	out << "\t\tbase cnt  = " << std::dec << baseCount << "\n";
	for (const auto& bi : baseInfo)
	{
		out << "\n" << bi.dump() << "\n";
	}
	return out.str();
}

//
//=============================================================================
//  BaseClassTypeInfo
//=============================================================================
//

std::string BaseClassTypeInfo::dump() const
{
	assert(baseClass);

	std::stringstream out;
	out << "\t\tbase addr = " << baseClassAddr << "\n";
	out << "\t\tbase name = " << baseClass->name << "\n";
	out << "\t\toff flags = " << std::hex << offsetFlags << "\n";
	return out.str();
}

} // namespace bin2llvmir
} // namespace retdec
