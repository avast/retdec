/**
* @file include/retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info_seq.h
* @brief A sequence of information about API calls.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_API_CALL_INFO_SEQ_H
#define RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_API_CALL_INFO_SEQ_H

#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A sequence of information about API calls.
*
* Use APICallInfoSeqParser to construct instances of this class from a text
* representation (i.e. from a string).
*/
class APICallInfoSeq {
public:
	/// List of APICallInfo.
	using APICallInfos = std::vector<APICallInfo>;

	/// Iterator over API call information.
	using iterator = APICallInfos::const_iterator;

public:
	APICallInfoSeq();

	// The compiler-generated destructor, copy constructor and assignment
	// operator are just fine, so we don't have to create our own ones.

	bool operator==(const APICallInfoSeq &other) const;
	bool operator!=(const APICallInfoSeq &other) const;

	APICallInfoSeq &add(APICallInfo info);
	APICallInfos::size_type size() const;
	bool empty() const;
	const APICallInfo &front() const;
	const APICallInfo &back() const;
	iterator begin() const;
	iterator end() const;

private:
	APICallInfos apiCallInfos;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
