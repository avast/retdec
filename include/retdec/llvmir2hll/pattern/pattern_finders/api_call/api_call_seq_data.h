/**
* @file include/retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_seq_data.h
* @brief A storage of intermediate data when finding sequences of API calls.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_API_CALL_SEQ_DATA_H
#define RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_API_CALL_SEQ_DATA_H

#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info_seq.h"

namespace retdec {
namespace llvmir2hll {

class Pattern;
class Statement;
class StmtsPattern;

/**
* @brief A storage of intermediate data when finding sequences of API calls.
*/
class APICallSeqData {
public:
	APICallSeqData(const APICallInfoSeq &info);

	// The compiler-generated destructor is just fine, so we don't have to
	// create our own one.

	APICallSeqData(const APICallSeqData &data);
	APICallSeqData &operator=(const APICallSeqData &data);

	bool operator==(const APICallSeqData &other) const;
	bool operator!=(const APICallSeqData &other) const;

	bool matches(CallExpr* call) const;
	void apply(Statement* stmt, CallExpr* call);
	bool patternIsComplete() const;
	Pattern* getPattern() const;
	bool atEnd() const;

private:
	/// Mapping of a bind ID into the bound value.
	using BindIdValueMap = std::map<std::string, Expression*>;

private:
	bool funcNameMatches(Expression* calledExpr) const;
	bool argsMatch(CallExpr* call) const;
	bool valuesMatch(Value* value1, Value* value2) const;
	void addToPattern(Statement* stmt, CallExpr* call);
	void advanceToNextInfo();
	void bindValues(Statement* stmt, CallExpr* call);
	void bindValueFromReturnValue(Statement* stmt, CallExpr* call);
	void bindValuesFromArgs(CallExpr* call);

private:
	/// Sequence of API call information that we are looking for.
	const APICallInfoSeq &allInfos;

	/// Pointer to the current information from @c allInfos.
	const APICallInfo *currInfo = nullptr;

	/// Iterator to the current information in @c allInfos.
	APICallInfoSeq::iterator currInfoIter;

	/// Mapping of a bind ID into the bound value.
	BindIdValueMap boundValues;

	/// Pattern that is being built.
	StmtsPattern* pattern = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
