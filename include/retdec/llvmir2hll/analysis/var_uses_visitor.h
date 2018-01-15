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
	VarUses(ShPtr<Variable> var = nullptr, ShPtr<Function> func = nullptr,
		StmtSet dirUses = StmtSet(), StmtSet indirUses = StmtSet()):
			var(var), func(func), dirUses(dirUses), indirUses(indirUses) {}

	/// Variable whose uses this class contains.
	ShPtr<Variable> var;

	/// Function which contains the uses.
	ShPtr<Function> func;

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
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~VarUsesVisitor() override;

	bool isUsed(ShPtr<Variable> var, ShPtr<Function> func,
		bool doNotIncludeFirstUse = false);
	ShPtr<VarUses> getUses(ShPtr<Variable> var, ShPtr<Function> func);

	/// @name Caching
	/// @{
	void enableCaching();
	void disableCaching();
	void clearCache();
	bool isCachingEnabled() const;
	void stmtHasBeenAdded(ShPtr<Statement> stmt, ShPtr<Function> func);
	void stmtHasBeenChanged(ShPtr<Statement> stmt, ShPtr<Function> func);
	void stmtHasBeenRemoved(ShPtr<Statement> stmt, ShPtr<Function> func);
	/// @}

	static ShPtr<VarUsesVisitor> create(ShPtr<ValueAnalysis> va,
		bool enableCaching = false, ShPtr<Module> module = nullptr);

private:
	/// Mapping of a variable into its uses.
	// Note: Using a hash table (i.e. std::unordered_map) does not
	//       significantly speeds up the execution.
	using VarUsesMap = std::map<ShPtr<Variable>, ShPtr<VarUses>>;

	/// Mapping of a function into uses of its variables.
	using FuncVarUsesMap = std::map<ShPtr<Function>, VarUsesMap>;

private:
	VarUsesVisitor(ShPtr<ValueAnalysis> va, bool enableCaching = false);

	void precomputeEverything(ShPtr<Module> module);
	void findAndStoreUses(ShPtr<Statement> stmt);
	void dumpCache();

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<AssignStmt> stmt) override;
	virtual void visit(ShPtr<VarDefStmt> stmt) override;
	virtual void visit(ShPtr<CallStmt> stmt) override;
	virtual void visit(ShPtr<ReturnStmt> stmt) override;
	virtual void visit(ShPtr<EmptyStmt> stmt) override;
	virtual void visit(ShPtr<IfStmt> stmt) override;
	virtual void visit(ShPtr<SwitchStmt> stmt) override;
	virtual void visit(ShPtr<WhileLoopStmt> stmt) override;
	virtual void visit(ShPtr<ForLoopStmt> stmt) override;
	virtual void visit(ShPtr<UForLoopStmt> stmt) override;
	virtual void visit(ShPtr<BreakStmt> stmt) override;
	virtual void visit(ShPtr<ContinueStmt> stmt) override;
	virtual void visit(ShPtr<GotoStmt> stmt) override;
	virtual void visit(ShPtr<UnreachableStmt> stmt) override;
	/// @}

private:
	/// Variable whose uses are obtained.
	ShPtr<Variable> var;

	/// Function whose body is being traversed.
	ShPtr<Function> func;

	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

	/// Uses of @c var.
	ShPtr<VarUses> varUses;

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
