/**
 * @file include/retdec/bin2llvmir/optimizations/class_hierarchy/hierarchy_analysis.h
 * @brief Analyse results of other analyses to reconstruct class hierarchy.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_CLASS_HIERARCHY_HIERARCHY_ANALYSIS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_CLASS_HIERARCHY_HIERARCHY_ANALYSIS_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/optimizations/class_hierarchy/hierarchy.h"
#include "retdec/bin2llvmir/analyses/ctor_dtor.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"

namespace retdec {
namespace bin2llvmir {

class ClassHierarchyAnalysis : public llvm::ModulePass
{
	public:
		static char ID;
		ClassHierarchyAnalysis();
		virtual bool runOnModule(llvm::Module& M) override;

		void processRttiGcc();
		void processRttiMsvc();
		void processVtablesGcc(std::map<const rtti_finder::ClassTypeInfo*, Class*> &rtti2class);
		void processVtablesMsvc(std::map<const rtti_finder::RTTITypeDescriptor*, Class*> &rtti2class);
		void processCtorsDtors();

		void setToConfig(llvm::Module* m) const;

	private:
		Config* config = nullptr;
		FileImage* image = nullptr;

		CtorDtor ctorDtor;
		ClassHierarchy classHierarchy;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
