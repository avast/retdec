/**
* @file include/retdec/llvmir2hll/analysis/var_uses_visitor.h
* @brief A visitor for obtaining the uses of variables in a function.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_ANALYSIS_VAR_USES_VISITOR_H
#define RETDEC_LLVMIR2HLL_ANALYSIS_VAR_USES_VISITOR_H

#include <map>

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Representation of uses of a variable.
*/
class VarUses {
public:
	VarUses(Variable* var = nullptr, Function* func = nullptr,
		StmtSet dirUses = StmtSet(), StmtSet indirUses = StmtSet()):
			var(var), func(func), dirUses(dirUses), indirUses(indirUses) {}

	/// Variable whose uses this class contains.
	Variable* var = nullptr;

	/// Function which contains the uses.
	Function* func = nullptr;

	/// Direct uses of @c var.
	StmtSet dirUses;

	/// Indirect uses of @c var (may or must).
	StmtSet indirUses;
};

/**
* @brief A visitor for obtaining the uses of variables in a function.
*
* Use create() to create instances. Instances of this class have
* reference object semantics.
*/
// Note: Support/Caching hasn't been used because storing and obtaining results
//       using Support/Caching would be tedious (we use a map of maps in this
//       class). We rather use a custom caching mechanism.
class VarUsesVisitor: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	bool isUsed(Variable* var, Function* func,
		bool doNotIncludeFirstUse = false);
	VarUses* getUses(Variable* var, Function* func);

	/// @name Caching
	/// @{
	void enableCaching();
	void disableCaching();
	void clearCache();
	bool isCachingEnabled() const;
	void stmtHasBeenAdded(Statement* stmt, Function* func);
	void stmtHasBeenChanged(Statement* stmt, Function* func);
	void stmtHasBeenRemoved(Statement* stmt, Function* func);
	/// @}

	static VarUsesVisitor* create(ValueAnalysis* va,
		bool enableCaching = false, Module* module = nullptr);

private:
	/// Mapping of a variable into its uses.
	// Note: Using a hash table (i.e. std::unordered_map) does not
	//       significantly speeds up the execution.
	using VarUsesMap = std::map<Variable*, VarUses*>;

	/// Mapping of a function into uses of its variables.
	using FuncVarUsesMap = std::map<Function*, VarUsesMap>;

private:
	VarUsesVisitor(ValueAnalysis* va, bool enableCaching = false);

	void precomputeEverything(Module* module);
	void findAndStoreUses(Statement* stmt);
	void dumpCache();

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(AssignStmt* stmt) override;
	virtual void visit(VarDefStmt* stmt) override;
	virtual void visit(CallStmt* stmt) override;
	virtual void visit(ReturnStmt* stmt) override;
	virtual void visit(EmptyStmt* stmt) override;
	virtual void visit(IfStmt* stmt) override;
	virtual void visit(SwitchStmt* stmt) override;
	virtual void visit(WhileLoopStmt* stmt) override;
	virtual void visit(ForLoopStmt* stmt) override;
	virtual void visit(UForLoopStmt* stmt) override;
	virtual void visit(BreakStmt* stmt) override;
	virtual void visit(ContinueStmt* stmt) override;
	virtual void visit(GotoStmt* stmt) override;
	virtual void visit(UnreachableStmt* stmt) override;
	/// @}

private:
	/// Variable whose uses are obtained.
	Variable* var = nullptr;

	/// Function whose body is being traversed.
	Function* func = nullptr;

	/// Analysis of values.
	ValueAnalysis* va = nullptr;

	/// Uses of @c var.
	VarUses* varUses = nullptr;

	/// Are we pre-computing everything?
	bool precomputing;

	/// Has everything been successfully precomputed?
	bool precomputingHasBeenDone;

	/// Is caching enabled?
	bool cachingEnabled;

	/// Cache.
	FuncVarUsesMap cache;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
