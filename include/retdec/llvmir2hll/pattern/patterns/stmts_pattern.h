/**
* @file include/retdec/llvmir2hll/pattern/patterns/stmts_pattern.h
* @brief A pattern that is composed of zero or more statements.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_PATTERN_PATTERNS_STMTS_PATTERN_H
#define RETDEC_LLVMIR2HLL_PATTERN_PATTERNS_STMTS_PATTERN_H

#include "retdec/llvmir2hll/pattern/pattern.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class Function;

/**
* @brief A pattern that is composed of zero or more statements.
*
* Use create() to create instances of this class.
*/
class StmtsPattern: public Pattern {
public:
	/// Iterator over statements.
	using stmt_iterator = StmtVector::const_iterator;

public:
	virtual void print(llvm::raw_ostream &os,
		const std::string &indentation = "") const override;

	/// @name Statement Accessors
	/// @{
	bool isEmpty() const;
	void addStmt(ShPtr<Statement> stmt);
	StmtVector::size_type getNumOfStmts() const;
	stmt_iterator stmt_begin() const;
	stmt_iterator stmt_end() const;
	/// @}

	static ShPtr<StmtsPattern> create();
	static ShPtr<StmtsPattern> create(ShPtr<Statement> stmt);

protected:
	StmtsPattern();
	explicit StmtsPattern(ShPtr<Statement> stmt);

protected:
	/// Statements that form the pattern.
	StmtVector stmts;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
