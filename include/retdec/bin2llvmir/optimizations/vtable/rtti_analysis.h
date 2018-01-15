/**
 * @file include/retdec/bin2llvmir/optimizations/vtable/rtti_analysis.h
 * @brief Search for RTTI in input file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_VTABLE_RTTI_ANALYSIS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_VTABLE_RTTI_ANALYSIS_H

#include <map>
#include <set>

#include "retdec/utils/address.h"
#include "retdec/bin2llvmir/optimizations/data_references/data_references.h"
#include "retdec/bin2llvmir/optimizations/vtable/rtti_gcc.h"
#include "retdec/bin2llvmir/optimizations/vtable/rtti_msvc.h"

namespace retdec {
namespace bin2llvmir {

class RttiAnalysis
{
	public:
		~RttiAnalysis();

		ClassTypeInfo* parseGccRtti(
				retdec::loader::Image* objfile,
				DataReferences* RA,
				retdec::utils::Address rttiAddr);
		void processGccRttis();

		RTTICompleteObjectLocator* parseMsvcObjectLocator(
				retdec::loader::Image* objfile,
				retdec::utils::Address rttiAddr);
		void processMsvcRttis();

	private:
		RTTITypeDescriptor* parseMsvcTypeDescriptor(
				retdec::utils::Address typeDescriptorAddr);
		RTTIClassHierarchyDescriptor* parseMsvcClassDescriptor(
				retdec::utils::Address classDescriptorAddr);
		RTTIBaseClassDescriptor* parseMsvcBaseClassDescriptor(
				retdec::utils::Address baseDescriptorAddr);

	public:
		std::map<retdec::utils::Address, ClassTypeInfo*> gccRttis;
		std::map<retdec::utils::Address, RTTICompleteObjectLocator> msvcObjLocators;
		std::map<retdec::utils::Address, RTTITypeDescriptor> msvcTypeDescriptors;
		std::map<retdec::utils::Address, RTTIBaseClassDescriptor> msvcBaseClassDescriptors;
		std::map<retdec::utils::Address, RTTIClassHierarchyDescriptor> msvcClassDescriptors;

	private:
		retdec::loader::Image *objf = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
