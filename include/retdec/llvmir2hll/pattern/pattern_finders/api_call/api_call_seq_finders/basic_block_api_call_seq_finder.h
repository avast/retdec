/**
* @file include/retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_seq_finders/basic_block_api_call_seq_finder.h
* @brief API call finder which searches only in a basic block.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_API_CALL_SEQ_FINDERS_BASIC_BLOCK_API_CALL_SEQ_FINDER_H
#define RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_API_CALL_SEQ_FINDERS_BASIC_BLOCK_API_CALL_SEQ_FINDER_H

#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info_seq.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_seq_finder.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief API call finder which searches only in a basic block.
*
* This finder searches only within the same basic block in which the first
* statement of a possible pattern appears. For example, consider the following
* code
* @code
* char input[100];
* FILE *f = fopen("file.txt", "r");
* fread(input, 1, 99, f);
* input[99] = '\0';
* if (input[0] != 'X') {
*     fclose(f);
* }
* @endcode
* and suppose that the pattern is
* @code
* id = fopen();
* fread(id);
* fclose(id);
* @endcode
* Then, the present finder does not recognize this pattern because in the code,
* it spans over multiple basic blocks.
*
* Instances of this class have reference object semantics. Use create() to
* create instances.
*/
class BasicBlockAPICallSeqFinder: public APICallSeqFinder {
public:
	BasicBlockAPICallSeqFinder(ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio);
	virtual Patterns findPatterns(const APICallInfoSeq &info,
		ShPtr<CallExpr> call, ShPtr<Statement> stmt, ShPtr<Function> func,
		ShPtr<Module> module) override;

	static ShPtr<BasicBlockAPICallSeqFinder> create(ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio);

private:
};

} // namespace llvmir2hll
} // namespace retdec

#endif
