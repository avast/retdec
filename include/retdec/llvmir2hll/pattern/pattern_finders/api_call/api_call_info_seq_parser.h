/**
* @file include/retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info_seq_parser.h
* @brief A parser of textual representation of API call sequences.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_API_CALL_INFO_SEQ_PARSER_H
#define RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_API_CALL_INFO_SEQ_PARSER_H

#include <string>

#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info_seq.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A parser of textual representation of API call sequences.
*
* The textual representation of an API call sequence has to be of the form
* @code
* info1
* info2
* info3
* ...
* @endcode
* where every @c infoX is of the form
* @code
* [X = ] func([args])[;]
* @endcode
* where
*  - <tt>X = </tt> is an optional bind to an identifier @c X;
*  - @c func is the name of the function;
*  - @c args is an optional list of arguments, specified later;
*  - @c ; is an optional semicolon to end the info.
*
* An identifier (ID for short) has to be of the form @c [_a-zA-Z0-9]+. Every
* argument has to be an ID. If the ID is @c _, then such an argument is
* irrelevant. This means that values are not bound to this argument or checked
* that they match with it. Arguments are separated by commas. Whitespace is
* irrelevant and it is skipped.
*
* Example:
* @code
* URLDownloadToFile(_, _, X)
* Y = fopen(X)
* fwrite(_, _, _, Y)
* fclose(Y)
* @endcode
* (Recall that the semicolons at the end of every info are only optional.)
*
* For more examples, see the unit tests for this class, located in
* APICallInfoSeqParserTest.cpp.
*
* Instances of this class have reference object semantics. Use create() to
* create instances.
*/
class APICallInfoSeqParser: private retdec::utils::NonCopyable {
public:
	static ShPtr<APICallInfoSeqParser> create();

	Maybe<APICallInfoSeq> parse(const std::string &text) const;

private:
	APICallInfoSeqParser();
};

} // namespace llvmir2hll
} // namespace retdec

#endif
