/**
* @file src/llvmir2hll/pattern/patterns/stmts_pattern.cpp
* @brief Implementation of StmtsPattern.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/pattern/patterns/stmts_pattern.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs an empty pattern.
*/
StmtsPattern::StmtsPattern():
	Pattern() {}

/**
* @brief Constructs a pattern containing @a stmt.
*/
StmtsPattern::StmtsPattern(ShPtr<Statement> stmt):
	Pattern(), stmts(1, stmt) {}

void StmtsPattern::print(llvm::raw_ostream &os,
		const std::string &indentation) const {
	for (auto i = stmt_begin(), e = stmt_end(); i != e; ++i) {
		os << indentation << *i << "\n";
	}
}

/**
* @brief Returns @c true if the pattern is empty, @c false otherwise.
*
* Empty means that the pattern is composed of no statements. This means that
* isEmpty() returns @c true if and only if getNumOfStmts() returns a non-zero
* number.
*/
bool StmtsPattern::isEmpty() const {
	return stmts.empty();
}

/**
* @brief Adds a new statement into the pattern.
*
* Iterators returned by stmt_begin() and stmt_end() may be invalidated after
* this call.
*/
void StmtsPattern::addStmt(ShPtr<Statement> stmt) {
	stmts.push_back(stmt);
}

/**
* @brief Returns the number of statements in the pattern.
*/
StmtVector::size_type StmtsPattern::getNumOfStmts() const {
	return stmts.size();
}

/**
* @brief Returns an iterator to the first statement in the pattern.
*
* The returned iterator is a constant iterator so there is no way of modifying
* the pattern during iterator.
*/
StmtsPattern::stmt_iterator StmtsPattern::stmt_begin() const {
	return stmts.begin();
}

/**
* @brief Returns an iterator past the last statement in the pattern.
*
* The returned iterator is a constant iterator so there is no way of modifying
* the pattern during iterator.
*/
StmtsPattern::stmt_iterator StmtsPattern::stmt_end() const {
	return stmts.end();
}

/**
* @brief Creates an empty pattern.
*/
ShPtr<StmtsPattern> StmtsPattern::create() {
	return ShPtr<StmtsPattern>(new StmtsPattern());
}

/**
* @brief Creates a pattern containing @a stmt.
*/
ShPtr<StmtsPattern> StmtsPattern::create(ShPtr<Statement> stmt) {
	return ShPtr<StmtsPattern>(new StmtsPattern(stmt));
}

} // namespace llvmir2hll
} // namespace retdec
