/**
* @file include/retdec/llvmir2hll/analysis/written_into_globals_visitor.h
* @brief A visitor for obtaining written-into global variables in functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_ANALYSIS_WRITTEN_INTO_GLOBALS_VISITOR_H
#define RETDEC_LLVMIR2HLL_ANALYSIS_WRITTEN_INTO_GLOBALS_VISITOR_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Module;
class Function;

/**
* @brief A visitor for obtaining written-into global variables in functions.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class WrittenIntoGlobalsVisitor: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~WrittenIntoGlobalsVisitor() override;

	static VarSet getWrittenIntoGlobals(ShPtr<Function> func,
		ShPtr<Module> module);

private:
	WrittenIntoGlobalsVisitor(ShPtr<Module> module);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<Variable> var) override;
	virtual void visit(ShPtr<ArrayIndexOpExpr> expr) override;
	virtual void visit(ShPtr<StructIndexOpExpr> expr) override;
	virtual void visit(ShPtr<DerefOpExpr> expr) override;
	virtual void visit(ShPtr<AssignStmt> stmt) override;
	virtual void visit(ShPtr<VarDefStmt> stmt) override;
	virtual void visit(ShPtr<ForLoopStmt> stmt) override;
	/// @}

private:
	/// The current module.
	ShPtr<Module> module;

	/// Global variables in @c module. This is here to speedup the analysis. By
	/// using this set, we do not have to ask @c module every time we need such
	/// an information.
	VarSet globalVars;

	/// Written-into global variables for the current function.
	VarSet writtenIntoGlobals;

	/// Are we writing into a variable?
	bool writing;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
