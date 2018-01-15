/**
* @file include/retdec/llvmir2hll/analysis/no_init_var_def_analysis.h
* @brief An analysis which returns variable-defining statements without an
*        initializer in given functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_ANALYSIS_NO_INIT_VAR_DEF_ANALYSIS_H
#define RETDEC_LLVMIR2HLL_ANALYSIS_NO_INIT_VAR_DEF_ANALYSIS_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class NoInitVarDefAnalysis: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	NoInitVarDefAnalysis();
	virtual ~NoInitVarDefAnalysis() override;

	VarDefStmtSet getNoInitVarDefStmts(ShPtr<Function> func);

private:
	/// @name OrderedAllVisitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<VarDefStmt> stmt) override;
	/// @}

private:
	/// Result set with all variable-defining statements without an
	/// initializer.
	VarDefStmtSet noInitVarDefs;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
