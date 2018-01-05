/**
* @file src/llvmir2hll/pattern/pattern_finders/api_call/api_call_info_seq.cpp
* @brief Implementation of APICallInfoSeq.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info_seq.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs an empty sequence.
*/
APICallInfoSeq::APICallInfoSeq() {}

/**
* @brief Returns @c true if this sequence is equal to @a other, @c false otherwise.
*/
bool APICallInfoSeq::operator==(const APICallInfoSeq &other) const {
	return apiCallInfos == other.apiCallInfos;
}

/**
* @brief Returns @c true if this sequence is not equal to @a other, @c false
*        otherwise.
*/
bool APICallInfoSeq::operator!=(const APICallInfoSeq &other) const {
	return !(*this == other);
}

/**
* @brief Adds @a info into the sequence.
*
* More precisely, it appends it after the last information (if any).
*
* @return A reference to the modified sequence. This allows to chain add()
*         calls, like this:
*         @code
*         APICallInfoSeq()
*             .add(APICallInfo("func1"))
*             .add(APICallInfo("func2"))
*             .add(APICallInfo("func3"))
*         @endcode
*/
APICallInfoSeq &APICallInfoSeq::add(APICallInfo info) {
	apiCallInfos.push_back(info);
	return *this;
}

/**
* @brief Returns the number of information in the sequence.
*/
APICallInfoSeq::APICallInfos::size_type APICallInfoSeq::size() const {
	return apiCallInfos.size();
}

/**
* @brief Returns @c true if there are no information in the sequence, @c false
*        otherwise.
*/
bool APICallInfoSeq::empty() const {
	return apiCallInfos.empty();
}

/**
* @brief Returns a constant reference to the first information in the sequence.
*
* @par Preconditions
*  - there is at least one information in the sequence
*/
const APICallInfo &APICallInfoSeq::front() const {
	PRECONDITION(!apiCallInfos.empty(), "called front() on an empty sequence");

	return apiCallInfos.front();
}

/**
* @brief Returns a constant reference to the last information in the sequence.
*
* @par Preconditions
*  - there is at least one information in the sequence
*/
const APICallInfo &APICallInfoSeq::back() const {
	PRECONDITION(!apiCallInfos.empty(), "called back() on an empty sequence");

	return apiCallInfos.back();
}

/**
* @brief Returns an iterator to the first information.
*/
APICallInfoSeq::iterator APICallInfoSeq::begin() const {
	return apiCallInfos.begin();
}

/**
* @brief Returns an iterator past the last information.
*/
APICallInfoSeq::iterator APICallInfoSeq::end() const {
	return apiCallInfos.end();
}

} // namespace llvmir2hll
} // namespace retdec
