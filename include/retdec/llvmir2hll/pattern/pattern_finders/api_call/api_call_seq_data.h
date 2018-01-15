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

	bool matches(ShPtr<CallExpr> call) const;
	void apply(ShPtr<Statement> stmt, ShPtr<CallExpr> call);
	bool patternIsComplete() const;
	ShPtr<Pattern> getPattern() const;
	bool atEnd() const;

private:
	/// Mapping of a bind ID into the bound value.
	using BindIdValueMap = std::map<std::string, ShPtr<Expression>>;

private:
	bool funcNameMatches(ShPtr<Expression> calledExpr) const;
	bool argsMatch(ShPtr<CallExpr> call) const;
	bool valuesMatch(ShPtr<Value> value1, ShPtr<Value> value2) const;
	void addToPattern(ShPtr<Statement> stmt, ShPtr<CallExpr> call);
	void advanceToNextInfo();
	void bindValues(ShPtr<Statement> stmt, ShPtr<CallExpr> call);
	void bindValueFromReturnValue(ShPtr<Statement> stmt, ShPtr<CallExpr> call);
	void bindValuesFromArgs(ShPtr<CallExpr> call);

private:
	/// Sequence of API call information that we are looking for.
	const APICallInfoSeq &allInfos;

	/// Pointer to the current information from @c allInfos.
	const APICallInfo *currInfo;

	/// Iterator to the current information in @c allInfos.
	APICallInfoSeq::iterator currInfoIter;

	/// Mapping of a bind ID into the bound value.
	BindIdValueMap boundValues;

	/// Pattern that is being built.
	ShPtr<StmtsPattern> pattern;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
