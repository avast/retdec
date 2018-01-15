/**
* @file include/retdec/llvmir2hll/analysis/used_vars_visitor.h
* @brief A visitor for obtaining the used variables in a value.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_ANALYSIS_USED_VARS_VISITOR_H
#define RETDEC_LLVMIR2HLL_ANALYSIS_USED_VARS_VISITOR_H

#include <cstddef>
#include <map>

#include "retdec/llvmir2hll/support/caching.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Value;

/**
* @brief Used variables for a value (expression, statement).
*
* See UsedVarsVisitor for a way of creating instances of this class.
*
* Instances of this class have value object semantics.
*/
class UsedVars {
	friend class UsedVarsVisitor;

public:
	/// Variables iterator.
	using var_iterator = VarSet::const_iterator;

public:
	UsedVars(const UsedVars &other);
	~UsedVars();

	UsedVars &operator=(const UsedVars &other);
	bool operator==(const UsedVars &other) const;
	bool operator!=(const UsedVars &other) const;

	VarSet getReadVars() const;
	VarSet getWrittenVars() const;
	VarSet getAllVars() const;
	std::size_t getCount(bool read = true, bool written = true) const;
	std::size_t getNumOfUses(ShPtr<Variable> var) const;
	bool isUsed(ShPtr<Variable> var, bool read = true,
		bool written = true) const;

	/// @name Used Variables Accessors
	/// @{
	var_iterator read_begin() const;
	var_iterator read_end() const;

	var_iterator written_begin() const;
	var_iterator written_end() const;

	var_iterator all_begin() const;
	var_iterator all_end() const;
	/// @}

private:
	/// Mapping of a variable into a count.
	using VarCountMap = std::map<ShPtr<Variable>, std::size_t>;

private:
	UsedVars();

	void clear();

private:
	/// Set of variables that are read.
	VarSet readVars;

	/// Set of variables into which something is written.
	VarSet writtenVars;

	/// Set of all variables (read or written).
	VarSet allVars;

	/// Number of uses of a variable.
	VarCountMap numOfVarUses;
};

/**
* @brief A visitor for obtaining the used variables in a value.
*
* This class may be used in the following two ways:
*   (1) Without a need to create any instances. Use the static function
*       getUsedVars().
*   (2) By creating an instance using create(). May be much more faster than
*       (1). Also supports caching of the results. Use the member function
*       getUsedVars_(). TODO Use a different name?
*/
class UsedVarsVisitor: private OrderedAllVisitor,
	private retdec::utils::NonCopyable,
	public Caching<ShPtr<Value>, ShPtr<UsedVars>> {

public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~UsedVarsVisitor() override;

	ShPtr<UsedVars> getUsedVars_(ShPtr<Value> value);

	static ShPtr<UsedVarsVisitor> create(bool visitSuccessors = true,
		bool visitNestedStmts = true, bool enableCaching = false);
	static ShPtr<UsedVars> getUsedVars(ShPtr<Value> value,
		bool visitSuccessors = true, bool visitNestedStmts = true);

private:
	explicit UsedVarsVisitor(bool visitSuccessors = true,
		bool visitNestedStmts = true, bool enableCaching = false);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<Function> func) override;
	virtual void visit(ShPtr<Variable> var) override;
	virtual void visit(ShPtr<ArrayIndexOpExpr> expr) override;
	virtual void visit(ShPtr<StructIndexOpExpr> expr) override;
	virtual void visit(ShPtr<DerefOpExpr> expr) override;
	virtual void visit(ShPtr<AssignStmt> stmt) override;
	virtual void visit(ShPtr<VarDefStmt> stmt) override;
	virtual void visit(ShPtr<ForLoopStmt> stmt) override;
	/// @}

private:
	/// Used variables that are currently being computed.
	ShPtr<UsedVars> usedVars;

	/// Are we writing into a variable?
	bool writing;

	/// Should statements' successor be accessed?
	bool visitSuccessors;

	/// Should nested statements be accessed?
	bool visitNestedStmts;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
