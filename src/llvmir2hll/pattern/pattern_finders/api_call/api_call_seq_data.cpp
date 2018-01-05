/**
* @file src/llvmir2hll/pattern/pattern_finders/api_call/api_call_seq_data.cpp
* @brief Implementation of APICallSeqData.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_seq_data.h"
#include "retdec/llvmir2hll/pattern/patterns/stmts_pattern.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/utils/container.h"

using retdec::utils::addToMap;

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Skips irrelevant parts of @a expr.
*
* A part of an expression is @e irrelevant if its presence should have no
* impact when two values are matched.
*/
ShPtr<Expression> skipIrrelevantParts(ShPtr<Expression> expr) {
	ShPtr<Expression> oldResult;
	ShPtr<Expression> newResult(expr);
	while (oldResult != newResult) {
		oldResult = newResult;
		newResult = skipCasts(newResult);
		newResult = skipDerefs(newResult);
		newResult = skipAddresses(newResult);
	}
	return newResult;
}

} // anonymous namespace

/**
* @brief Constructs data from the given information.
*
* It starts with the first information in @a info and an empty pattern.
*
* @par Preconditions
*  - @a info is non-empty
*/
APICallSeqData::APICallSeqData(const APICallInfoSeq &info):
	allInfos(info), currInfo(&allInfos.front()), currInfoIter(allInfos.begin()),
	boundValues(), pattern(StmtsPattern::create()) {}

/**
* @brief Constructs data from @a data.
*/
APICallSeqData::APICallSeqData(const APICallSeqData &data):
	allInfos(data.allInfos), currInfo(data.currInfo),
	currInfoIter(data.currInfoIter), boundValues(data.boundValues),
	pattern(/* TODO clone */) {
		// TODO
		FAIL("APICallSeqData::APICallSeqData() is not implemented");
	}

/**
* @brief Assigns @a data into the current data.
*/
APICallSeqData &APICallSeqData::operator=(const APICallSeqData &data) {
	// TODO
	FAIL("APICallSeqData::operator=() is not implemented");
	return *this;
}

/**
* @brief Returns @c true if this data equal the @a other data, @c false
*        otherwise.
*/
bool APICallSeqData::operator==(const APICallSeqData &other) const {
	return allInfos == other.allInfos &&
		currInfo == other.currInfo &&
		currInfoIter == other.currInfoIter &&
		boundValues == other.boundValues &&
		pattern == other.pattern;
}

/**
* @brief Returns @c true if this data differ from the @a other data, @c false
*        otherwise.
*/
bool APICallSeqData::operator!=(const APICallSeqData &other) const {
	return !(*this == other);
}

/**
* @brief Returns @a true if @a call matches the currently set API call
*        information, @c false otherwise.
*/
bool APICallSeqData::matches(ShPtr<CallExpr> call) const {
	return funcNameMatches(call->getCalledExpr()) && argsMatch(call);
}

/**
* @brief Applies @a call that occur in @a stmt.
*
* In a greater detail, this function adds the information to the currently
* build pattern, binds values occurring in @a call, and advances to the next
* API call information.
*
* Note: This function should be called only after matches() returned @c true.
*/
void APICallSeqData::apply(ShPtr<Statement> stmt, ShPtr<CallExpr> call) {
	addToPattern(stmt, call);
	bindValues(stmt, call);
	advanceToNextInfo();
}

/**
* @brief Returns @c true if the pattern is complete, @c false otherwise.
*
* A pattern is complete if all API call information has been successfully matched.
*/
bool APICallSeqData::patternIsComplete() const {
	return allInfos.size() == pattern->getNumOfStmts();
}

/**
* @brief Returns the current version of the built pattern.
*
* This functions returns a complete pattern only if patternIsComplete() returns
* @c true. Otherwise, it returns a partially build pattern.
*/
ShPtr<Pattern> APICallSeqData::getPattern() const {
	return pattern;
}

/**
* @brief Returns @c true if all the API call information passed to the
*        constructor have been matched, @c false otherwise.
*/
bool APICallSeqData::atEnd() const {
	return currInfoIter == allInfos.end();
}

/**
* @brief Checks that the function called in @a calledExpr is the one we expect.
*/
bool APICallSeqData::funcNameMatches(ShPtr<Expression> calledExpr) const {
	ShPtr<Variable> calledVar(cast<Variable>(calledExpr));
	return calledVar && calledVar->getName() == currInfo->getFuncName();
}

/**
* @brief Checks that all the bound parameters from the API call info match the
*        values in @a call.
*/
bool APICallSeqData::argsMatch(ShPtr<CallExpr> call) const {
	for (auto i = currInfo->param_bind_begin(), e = currInfo->param_bind_end();
			i != e; ++i) {
		if (!call->hasArg(i->first)) {
			return false;
		}

		auto valueIter = boundValues.find(i->second);
		if (valueIter == boundValues.end()) {
			// There is a bind for which we don't have a value. This means that
			// this bind is for some functions that follow the current function
			// in the sequence. We can safely skip this bind.
			continue;
		}

		if (!valueIter->second) {
			// TODO Replace with the NullExpr concept?
			return false;
		}

		if (!valuesMatch(valueIter->second,
				skipIrrelevantParts(call->getArg(i->first)))) {
			return false;
		}
	}
	return true;
}

/**
* @brief Checks whether @a value1 is structurally equal to @a value2.
*
* Structurally equal means that they may have different addresses, but they
* hold the same data.
*/
bool APICallSeqData::valuesMatch(ShPtr<Value> value1, ShPtr<Value> value2) const {
	return value1->isEqualTo(value2);
}

/**
* @brief Adds a new piece of information into the currently built pattern.
*/
void APICallSeqData::addToPattern(ShPtr<Statement> stmt, ShPtr<CallExpr> call) {
	pattern->addStmt(stmt);
}

/**
* @brief Advances to the next information in @c allInfos.
*/
void APICallSeqData::advanceToNextInfo() {
	PRECONDITION(currInfoIter != allInfos.end(),
		"cannot advance since we are at the end");

	++currInfoIter;
	currInfo = &*currInfoIter;
}

/**
* @brief Binds values from @a call that appear in @a stmt.
*/
void APICallSeqData::bindValues(ShPtr<Statement> stmt, ShPtr<CallExpr> call) {
	if (currInfo->hasBoundReturnValue()) {
		bindValueFromReturnValue(stmt, call);
	}
	bindValuesFromArgs(call);
}

/**
* @brief Binds the value returned from @a call (if any).
*/
void APICallSeqData::bindValueFromReturnValue(ShPtr<Statement> stmt,
		ShPtr<CallExpr> call) {
	const std::string &bindId(currInfo->getReturnValueBind());

	if (!isVarDefOrAssignStmt(stmt)) {
		// TODO Replace with the NullExpr concept?
		addToMap(bindId, ShPtr<Expression>(), boundValues);
		return;
	}

	ShPtr<Expression> rhs(getRhs(stmt));
	if (skipIrrelevantParts(rhs) != call) {
		// TODO Replace with the NullExpr concept?
		addToMap(bindId, ShPtr<Expression>(), boundValues);
		return;
	}

	addToMap(bindId, skipIrrelevantParts(getLhs(stmt)), boundValues);
}

/**
* @brief Binds the values from the arguments of @a call.
*/
void APICallSeqData::bindValuesFromArgs(ShPtr<CallExpr> call) {
	for (auto i = currInfo->param_bind_begin(), e = currInfo->param_bind_end();
			i != e; ++i) {
		addToMap(i->second, skipIrrelevantParts(call->getArg(i->first)),
			boundValues);
	}
}

} // namespace llvmir2hll
} // namespace retdec
