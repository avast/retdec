/**
* @file src/llvmir2hll/ir/statement.cpp
* @brief Implementation of Statement.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/llvm/llvm_support.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/conversion.h"

using retdec::utils::toString;

namespace retdec {
namespace llvmir2hll {
namespace {

/**
* @brief Ensures that the label is preserved.
*/
void preserveLabel(ShPtr<Statement> origStmt, ShPtr<Statement> newStmt) {
	if (origStmt->hasLabel()) {
		newStmt->setLabel(origStmt->getLabel());
	}
}

} // anonymous namespace

/**
* @brief Constructs a new statement.
*/
Statement::Statement():
	succ(), preds(), label() {
}

/**
* @brief Destructs the statement.
*/
Statement::~Statement() {}

/**
* @brief Sets @a newSucc as the current statement's successor.
*
* Example: Consider the following situation:
* @code
* int a = 5; // <-- this stmt
* @endcode
* The following call in pseudocode
* @code
* stmt->setSuccessor(`return a`)
* @endcode
* results in
* @code
* int a = 5; // <-- this stmt
* return a;
* @endcode
*
* The original successor (if any) is discarded. If you do not want it to be
* discarded, use appendStatement() instead.
*/
void Statement::setSuccessor(ShPtr<Statement> newSucc) {
	if (succ) {
		// Update the predecessors of the old successor.
		succ->preds.erase(succ);
	}

	if (newSucc) {
		// Update the non-goto predecessors of the new successor.
		newSucc->removePredecessors(true);
		newSucc->preds.insert(ucast<Statement>(shared_from_this()));
	}

	succ = newSucc;
}

/**
* @brief Removes the successor of the statement (if there is any).
*
* Note that the actual successor is not removed, only after calling this
* function, the statement will no longer have a successor.
*/
void Statement::removeSuccessor() {
	setSuccessor(ShPtr<Statement>());
}

/**
* @brief Returns the successor of statement.
*
* If there is no successor, it returns the null pointer.
*/
ShPtr<Statement> Statement::getSuccessor() const {
	return succ;
}

/**
* @brief Returns @c true if the statement has a successor, @c false otherwise.
*/
bool Statement::hasSuccessor() const {
	return succ != ShPtr<Statement>();
}

/**
* @brief Prepends @a stmt to the statement.
*
* @param[in] stmt Statement to be prepended.
*
* Example: Consider the following situation:
* @code
* int b = 5;
* return a; // <-- this stmt
* @endcode
* The following call in pseudocode
* @code
* stmt->prependStatement(`int a = b;`)
* @endcode
* results in
* @code
* int b = 5;
* int a = b;
* return a; // <-- this stmt
* @endcode
*
* If @a stmt is actually a sequence of statements, it prepends all of them so
* the successor of the last statement in this sequence is the statement on
* which this function is called.
*
* If you want to add another predecessor while leaving the original predecessor
* of the current statement untouched, use addPredecessor() instead.
*
* @par Preconditions
*  - @a stmt is non-null
*/
void Statement::prependStatement(ShPtr<Statement> stmt) {
	PRECONDITION_NON_NULL(stmt);

	// Point direct (e.g. not via goto) predecessors of the current statement
	// to stmt. Since we may modify the predecessors set of the current
	// statement in the following loop, we have to create a copy of it and
	// iterate over this copy rather than over preds.
	auto thisStmt = shared_from_this();
	for (auto &pred : StmtSet(preds)) {
		if (pred->getSuccessor() == thisStmt) {
			pred->setSuccessor(stmt);
		}
	}

	// Get to the end of a possible sequence of statements in stmt.
	ShPtr<Statement> lastStmt(Statement::getLastStatement(stmt));

	// Set lastStmt as the only non-goto predecessor of the current statement.
	removePredecessors(true);
	preds.insert(lastStmt);

	// Set the current statement as lastStmt's successor.
	lastStmt->setSuccessor(ucast<Statement>(thisStmt));

	// Use the observer/subject interface in the case when the current
	// statement is the first statement in a block.
	notifyObservers(stmt);
}

/**
* @brief Appends @a stmt to the statement.
*
* @param[in] stmt Statement to be appended.
*
* If @a stmt is actually a sequence of statements, it appends all of them so
* the successor of the last statement in this sequence is the current
* statement's successor.
*
* Notice that this function differs from setSuccessor(). Indeed, setSuccessor()
* just sets @a stmt as the statement's successor, discarding the original
* successor, while this function places @a stmt between the current statements
* and its successor. For example, lets have the following sequence of
* statements:
* @code
* A --> B
* @endcode
* When we call @c A->setSuccessor(stmt), we get
* @code
* A --> stmt
* @endcode
* However, if we call @c A->appendStatement(stmt), we get
* @code
* A --> stmt -> B
* @endcode
*
* @par Preconditions
*  - @a stmt is non-null
*/
void Statement::appendStatement(ShPtr<Statement> stmt) {
	PRECONDITION_NON_NULL(stmt);

	// Get to the end of a possible sequence of statements in stmt.
	ShPtr<Statement> lastStmt(Statement::getLastStatement(stmt));

	lastStmt->setSuccessor(succ);
	succ = stmt;

	stmt->removePredecessors(true);
	stmt->preds.insert(ucast<Statement>(shared_from_this()));
}

/**
* @brief Returns @c true if the statement has any predecessor, @c false
*        otherwise.
*/
bool Statement::hasPredecessors() const {
	return !preds.empty();
}

/**
* @brief Adds a new predecessor: @a stmt.
*
* @param[in] stmt Statement to be added as a predecessor.
*
* Notice that this function differs from prependStatement(). Indeed,
* prependStatement() inserts @a stmt between the current statement and its
* predecessor while this function creates a new predecessor. For example, lets
* have the following sequence of statements:
* @code
* A --> B
* @endcode
* When we call @c B->addPredecessor(stmt), we get
* @code
* A --> B
*       ^
*       |
* stmt --
* @endcode
* However, if we call @c B->prependStatement(stmt), we get
* @code
* A --> stmt -> B
* @endcode
* Therefore, if you want to add a statement before the current statement, use
* prependStatement() instead.
*
* By using this function, a statement may have more than one predecessor. This
* comes handy in terms of goto statements.
*/
void Statement::addPredecessor(ShPtr<Statement> stmt) {
	preds.insert(stmt);
}

/**
* @brief Returns the number of predecessors of the current statement.
*
* Recall that by using addPredecessor(), a statement may have more than one
* predecessor. This is the case when goto statements are used.
*/
std::size_t Statement::getNumberOfPredecessors() const {
	return preds.size();
}

/**
* @brief Returns the unique predecessor of the current statement.
*
* If the statement has no predecessors, or if there is more than one
* predecessor, the null pointer is returned.
*/
ShPtr<Statement> Statement::getUniquePredecessor() const {
	if (preds.size() != 1) {
		return ShPtr<Statement>();
	}
	return *(preds.begin());
}

/**
* @brief Returns an iterator to the first predecessor (if any).
*/
Statement::predecessor_iterator Statement::predecessor_begin() const {
	return preds.begin();
}

/**
* @brief Returns an iterator past the last predecessor.
*/
Statement::predecessor_iterator Statement::predecessor_end() const {
	return preds.end();
}

/**
* @brief Removes this statement from a block which contains it.
*
* @param[in] stmt Statement to be removed.
*
* After calling this function, @a stmt will have no predecessors and no
* successor.
*
* @par Preconditions
*  - @a stmt is non-null
*/
void Statement::removeStatement(ShPtr<Statement> stmt) {
	PRECONDITION_NON_NULL(stmt);

	// If some predecessor of stmt is a goto statement and stmt doesn't have a
	// successor, we have to replace it with an empty statement. Indeed, we
	// need to preserve the goto target. To this end, we first check whether
	// stmt is a goto target and doesn't have a successor, and if this is the
	// case, we replace it with a dummy empty statement.
	if (stmt->isGotoTarget() && !stmt->hasSuccessor()) {
		auto replacement = EmptyStmt::create();
		preserveLabel(stmt, replacement);
		Statement::replaceStatement(stmt, replacement);
		return;
	}

	// Replace the successors/targets of all predecessors. Since we may
	// modify the predecessors set of stmt in the following loop, we have
	// to create a copy of it and iterate over this copy.
	for (auto &pred : StmtSet(stmt->preds)) {
		if (pred->getSuccessor() == stmt) {
			pred->setSuccessor(stmt->getSuccessor());
		}

		// In gotos, we may need to change both the successor and target.
		if (ShPtr<GotoStmt> gotoStmt = cast<GotoStmt>(pred)) {
			if (gotoStmt->getTarget() == stmt) {
				gotoStmt->setTarget(stmt->getSuccessor());
			}
		}
	}

	// Update the stmt's successor (if any).
	if (stmt->succ) {
		stmt->succ->preds.erase(stmt);
		preserveLabel(stmt, stmt->succ);
	}

	// Use the observer/subject interface to remove it also from all statements
	// which contain it.
	stmt->notifyObservers(stmt->succ);

	stmt->removePredecessors();
	stmt->removeSuccessor();
}

/**
* @brief Removes the given statement, but keeps its debug comment (if any).
*
* An empty statement may be introduced if either there is no successor of @a
* stmt or its successor already has its debug comment.
*
* After calling this function, @a stmt will have no predecessors and no
* successor.
*/
void Statement::removeStatementButKeepDebugComment(ShPtr<Statement> stmt) {
	if (stmt->getMetadata() == "") {
		// There is no debug comment.
		Statement::removeStatement(stmt);
		return;
	}

	// Check whether we can store the metadata of stmt into its successor.
	if (ShPtr<Statement> stmtSuccessor = stmt->getSuccessor()) {
		if (stmtSuccessor->getMetadata() == "") {
			stmtSuccessor->setMetadata(stmt->getMetadata());
			Statement::removeStatement(stmt);
			return;
		}
	}

	// We cannot exploit the successor, so create an empty statement, attach
	// the metadata to it, and replace stmt with the empty statement.
	ShPtr<EmptyStmt> emptyStmt(EmptyStmt::create());
	emptyStmt->setMetadata(stmt->getMetadata());
	Statement::replaceStatement(stmt, emptyStmt);
}

/**
* @brief Returns @c true if @a stmts1 and @a stmts are equal, @c false
*        otherwise.
*
* @a stmts1 and @a stmts2 may be sequences of statements, in which case their
* successors are also checked.
*
* If @a stmts1 and @a stmts2 are the null pointers, @c true is returned.
*
* This function recursively calls itself.
*/
bool Statement::areEqualStatements(ShPtr<Statement> stmts1,
		ShPtr<Statement> stmts2) {
	// Check that both statements are non-null.
	if (!stmts1 && !stmts2) {
		return true;
	} else if (!stmts1 && stmts2) {
		return false;
	} else if (stmts1 && !stmts2) {
		return false;
	}

	// Check the equality of stmts1 and stmts2 without their successors.
	if (!stmts1->isEqualTo(stmts2)) {
		return false;
	}

	// Check their successors.
	return areEqualStatements(stmts1->getSuccessor(),
		stmts2->getSuccessor());
}

/**
* @brief Returns @c true if statement @a stmt is in the sequence of statements
*        @a stmts, @c false otherwise.
*
* @param[in] stmt Statement to be checked.
* @param[in] stmts Sequence of statements (may be empty).
*
* Only successors of statements in @a stmts are searched, i.e. if there is a
* compound statement, no search in the nested statements is done.
*
* Precondition:
*  - @a stmt is non-null
*/
bool Statement::isStatementInStatements(ShPtr<Statement> stmt, ShPtr<Statement>
		stmts) {
	PRECONDITION_NON_NULL(stmt);

	ShPtr<Statement> currStmt(stmts);
	while (currStmt && currStmt != stmt) {
		currStmt = currStmt->getSuccessor();
	}
	return currStmt == stmt;
}

/**
* @brief Removes the last statements in the sequence of statements @a stmts.
*
* @par Preconditions
*  - @a stmts is non-null
*/
void Statement::removeLastStatement(ShPtr<Statement> stmts) {
	PRECONDITION_NON_NULL(stmts);

	Statement::removeStatement(Statement::getLastStatement(stmts));
}

/**
* @brief Replaces @a oldStmt with @a newStmt.
*
* @param[in] oldStmt Old statement to be replaced.
* @param[in] newStmt Replacement.
*
* @par Preconditions
*  - @a oldStmt is non-null
*
* If @a oldStmt has a successor and @a newStmt is the null pointer, then the
* successor of @a oldStmt is (of course) lost.
*
* @a newStmt can be a list of statements, not necessary just a single
* statement.
*
* After calling this function, @a oldStmt will have no predecessors and no
* successor.
*/
void Statement::replaceStatement(ShPtr<Statement> oldStmt,
		ShPtr<Statement> newStmt) {
	PRECONDITION_NON_NULL(oldStmt);

	// Copy the successor of oldStmt (since newStmt can be a list of
	// statements, use Statement::mergeStatements() instead of just setting
	// newStmt->succ).
	if (newStmt) {
		newStmt = Statement::mergeStatements(newStmt, oldStmt->succ);
	}

	// Update all predecessors of oldStmt.
	// Since we may modify the predecessors set of oldStmt in the following
	// loop, we have to create a copy of it and iterate over this copy.
	StmtSet oldStmtPreds(oldStmt->preds);
	for (auto &pred : oldStmtPreds) {
		if (pred->getSuccessor() == oldStmt) {
			pred->setSuccessor(newStmt);
		}

		// In gotos, we may need to change both the successor and target.
		if (ShPtr<GotoStmt> gotoStmt = cast<GotoStmt>(pred)) {
			if (gotoStmt->getTarget() == oldStmt) {
				gotoStmt->setTarget(newStmt);
			}
		}
	}

	preserveLabel(oldStmt, newStmt);

	// Use the observer/subject interface to replace it also in all statements
	// which contain it.
	oldStmt->notifyObservers(newStmt);

	oldStmt->removePredecessors();
	oldStmt->removeSuccessor();
}

/**
* @brief Merges the two given statements.
*
* @param[in] stmt1 First statement to be merged.
* @param[in] stmt2 Second statement to be merged.
*
* @return Merged @a stmt1 and @a stmt2.
*
* If @a stmt1 contains a, b, c, ..., and @a stmt2 contains 0, 1, 2, ...,
* then the result will contain a, b, c, ..., 0, 1, 2, ...
*/
ShPtr<Statement> Statement::mergeStatements(ShPtr<Statement> stmt1,
		ShPtr<Statement> stmt2) {
	if (!stmt1) {
		return stmt2;
	} else if (!stmt2) {
		return stmt1;
	}

	// Both stmt1 and stmt2 are nonempty. Go through stmt1 to its end and append
	// stmt2 there.
	ShPtr<Statement> lastStmt(getLastStatement(stmt1));
	lastStmt->setSuccessor(stmt2);
	return stmt1;
}

/**
* @brief Clones the given list of statements.
*
* @return Cloned list of statements appearing in @a stmts.
*
* Clones the given list of statements, one by one, by calling @c clone() on
* every one of them. Successors are properly set. If @a stmts is the null
* pointer, the null pointer is returned.
*
* Note that @c Statement::clone() doesn't clone successors. Hence, if you want
* to clone a sequence of statements, including successors, use this
* function.
*/
ShPtr<Statement> Statement::cloneStatements(ShPtr<Statement> stmts) {
	ShPtr<Statement> clonedStmts;

	ShPtr<Statement> currStmt = stmts;
	while (currStmt) {
		// TODO This can be done more efficiently.
		clonedStmts = Statement::mergeStatements(clonedStmts,
			ucast<Statement>(currStmt->clone()));
		currStmt = currStmt->getSuccessor();
	}

	return clonedStmts;
}

/**
* @brief Returns the last statement in @a stmts.
*
* @param[in] stmts Sequence of statements.
*
* If @a stmts is null, then it returns the null pointer.
*/
ShPtr<Statement> Statement::getLastStatement(ShPtr<Statement> stmts) {
	if (!stmts) {
		return ShPtr<Statement>();
	}

	ShPtr<Statement> lastStmt(stmts);
	while (lastStmt->hasSuccessor()) {
		lastStmt = lastStmt->getSuccessor();
	}
	return lastStmt;
}

/**
* @brief Removes the predecessor @a stmt.
*
* @param[in] stmt Predecessor to be removed.
*
* If @a stmt is not a predecessor of the current statement, this function does
* nothing.
*/
void Statement::removePredecessor(ShPtr<Statement> stmt) {
	preds.erase(stmt);
}

/**
* @brief Removes all predecessors of the statement.
*
* @param[in] onlyNonGoto Removes only non-goto statements.
*
* It only removes them from being the current statement's predecessors, it
* doesn't delete them.
*/
void Statement::removePredecessors(bool onlyNonGoto) {
	if (!onlyNonGoto) {
		preds.clear();
		return;
	}

	// We remove only non-goto statements.
	// Since iterators and references to the erased elements of a std::set are
	// invalidated, we cannot erase statements while iterating over them. To
	// circumvent this limitation, we store them into a separate set and erase
	// them afterwards.
	StmtSet toRemoveStmts;
	auto thisStmt = shared_from_this();
	for (const auto &pred : preds) {
		if (pred->getSuccessor() == thisStmt) {
			toRemoveStmts.insert(pred);
		}
	}
	// For each node to be removed...
	for (const auto &stmt : toRemoveStmts) {
		preds.erase(stmt);
	}
}

/**
* @brief Returns the parent of the given statement.
*
* A parent of a statement @c stmt is a statement which directly contains it.
* For example, consider the following code:
* @code
* def testStr():
*     i = 0                        (1)
*     while str[i] != 0:           (2)
*         i = i + 1                (3)
*         printf("test: %d", i)    (4)
*     printf("end")                (5)
* @endcode
*
* In this example, statements (1), (2), and (5) do not have any parents, and
* statement (2) is the parent of statements (3) and (4).
*/
ShPtr<Statement> Statement::getParent() const {
	// If there are no non-goto predecessors, we're done, i.e. we can use the
	// set of observers.
	if (preds.empty() || containsJustGotosToCurrentStatement(preds)) {
		for (auto i = observer_begin(), e = observer_end(); i != e ; ++i) {
			if (ShPtr<Statement> observerStmt = cast<Statement>(i->lock())) {
				// Skip goto observers.
				if (isa<GotoStmt>(observerStmt)) {
					continue;
				}

				// We assume that each statement has at most one parent, see
				// the class description.
				return observerStmt;
			}
		}
	} else {
		// For each predecessor...
		for (auto &pred : preds) {
			// Skip goto predecessors that jump to the current statement.
			if (ShPtr<GotoStmt> gotoPred = cast<GotoStmt>(pred)) {
				if (targetIsCurrentStatement(gotoPred)) {
					continue;
				}
			}

			return pred->getParent();
		}
	}

	// There is no parent.
	return ShPtr<Statement>();
}

/**
* @brief Returns @c true if the statement is the target of a goto statement,
*        @c false otherwise.
*/
bool Statement::isGotoTarget() const {
	for (auto pred : preds) {
		if (auto gotoStmt = cast<GotoStmt>(pred)) {
			if (targetIsCurrentStatement(gotoStmt)) {
				return true;
			}
		}
	}
	return false;
}

/**
* @brief Redirects gotos to the statement to the given statement @a stmt.
*
* If the statement is not a goto target, this function does nothing.
*
* Labels are also transferred.
*
* @par Preconditions
*  - @a stmt is non-null
*/
void Statement::redirectGotosTo(ShPtr<Statement> stmt) {
	PRECONDITION_NON_NULL(stmt);

	// We need to iterate over a copy of predecessors because we may need to
	// modify them during the iteration.
	for (auto pred : StmtSet(preds)) {
		if (auto gotoStmt = cast<GotoStmt>(pred)) {
			if (targetIsCurrentStatement(gotoStmt)) {
				gotoStmt->setTarget(stmt);
				preds.erase(pred);
			}
		}
	}
	transferLabelTo(stmt);
}

/**
* @brief Does the statement has a label set?
*/
bool Statement::hasLabel() const {
	return !label.empty();
}

/**
* @brief Returns the statement's label.
*/
std::string Statement::getLabel() const {
	return label;
}

/**
* @brief Removes the statement's label (if any).
*/
void Statement::removeLabel() {
	label.clear();
}

/**
* @brief Sets a new label of the statement.
*
* @par Preconditions
*  - @a newLabel is non-empty
*/
void Statement::setLabel(const std::string &newLabel) {
	PRECONDITION(!newLabel.empty(), "the statement's label cannot be empty");

	label = newLabel;
}

/**
* @brief Transfers the label from the given statement to the current statement.
*/
void Statement::transferLabelFrom(ShPtr<Statement> stmt) {
	label = stmt->label;
	stmt->label.clear();
}

/**
* @brief Transfers the label from the current statement to the given statement.
*/
void Statement::transferLabelTo(ShPtr<Statement> stmt) {
	stmt->label = label;
	label.clear();
}

/**
* @brief Does @a gotoStmt target the current statement?
*/
bool Statement::targetIsCurrentStatement(ShPtr<GotoStmt> gotoStmt) const {
	// When iterating over predecessors, it may happen that the predecessor is
	// a goto statement but its target is not the current statement, e.g.
	//
	//     goto lab1; <-- predecessor
	//     goto lab2; <-- current statement
	//
	// To this end, we have to also check if the target of the predecessor is
	// the current statement.
	return gotoStmt->getTarget() == shared_from_this();
}

/**
* @brief Returns @c true if @a stmts contains just goto statements to the
*        current statement (or it is empty), @c false otherwise.
*/
bool Statement::containsJustGotosToCurrentStatement(const StmtSet &stmts) const {
	// For each statement in stmts...
	for (const auto &stmt : stmts) {
		if (auto gotoStmt = cast<GotoStmt>(stmt)) {
			if (targetIsCurrentStatement(gotoStmt)) {
				continue;
			}
		}
		return false;
	}
	return true;
}

} // namespace llvmir2hll
} // namespace retdec
