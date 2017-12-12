/**
 * @file include/bin2llvmir/optimizations/vtable/rtti_analysis.h
 * @brief Search for RTTI in input file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef BIN2LLVMIR_OPTIMIZATIONS_VTABLE_RTTI_ANALYSIS_H
#define BIN2LLVMIR_OPTIMIZATIONS_VTABLE_RTTI_ANALYSIS_H

#include <map>
#include <set>

#include "tl-cpputils/address.h"
#include "bin2llvmir/optimizations/data_references/data_references.h"
#include "bin2llvmir/optimizations/vtable/rtti_gcc.h"
#include "bin2llvmir/optimizations/vtable/rtti_msvc.h"

namespace bin2llvmir {

class RttiAnalysis
{
	public:
		~RttiAnalysis();

		ClassTypeInfo* parseGccRtti(
				loader::Image* objfile,
				DataReferences* RA,
				tl_cpputils::Address rttiAddr);
		void processGccRttis();

		RTTICompleteObjectLocator* parseMsvcObjectLocator(
				loader::Image* objfile,
				tl_cpputils::Address rttiAddr);
		void processMsvcRttis();

	private:
		RTTITypeDescriptor* parseMsvcTypeDescriptor(
				tl_cpputils::Address typeDescriptorAddr);
		RTTIClassHierarchyDescriptor* parseMsvcClassDescriptor(
				tl_cpputils::Address classDescriptorAddr);
		RTTIBaseClassDescriptor* parseMsvcBaseClassDescriptor(
				tl_cpputils::Address baseDescriptorAddr);

	public:
		std::map<tl_cpputils::Address, ClassTypeInfo*> gccRttis;
		std::map<tl_cpputils::Address, RTTICompleteObjectLocator> msvcObjLocators;
		std::map<tl_cpputils::Address, RTTITypeDescriptor> msvcTypeDescriptors;
		std::map<tl_cpputils::Address, RTTIBaseClassDescriptor> msvcBaseClassDescriptors;
		std::map<tl_cpputils::Address, RTTIClassHierarchyDescriptor> msvcClassDescriptors;

	private:
		loader::Image *objf = nullptr;
};

} // namespace bin2llvmir

#endif
