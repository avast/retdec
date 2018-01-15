/**
* @file src/llvmir2hll/pattern/pattern_finders/api_call/api_call_seq_finders/basic_block_api_call_seq_finder.cpp
* @brief Implementation of BasicBlockAPICallSeqFinder.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_seq_data.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_seq_finders/basic_block_api_call_seq_finder.h"
#include "retdec/llvmir2hll/pattern/patterns/stmts_pattern.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a BasicBlockAPICallSeqFinder object.
*
* @param[in] va The used analysis of values.
* @param[in] cio The used call info obtainer.
*
* @par Preconditions
*  - @a va and @a cio are non-null
*  - @a va is in a valid state
*  - @a cio has been initialized
*/
BasicBlockAPICallSeqFinder::BasicBlockAPICallSeqFinder(ShPtr<ValueAnalysis> va,
	ShPtr<CallInfoObtainer> cio): APICallSeqFinder(va, cio) {}

BasicBlockAPICallSeqFinder::Patterns BasicBlockAPICallSeqFinder::findPatterns(
		const APICallInfoSeq &info, ShPtr<CallExpr> call, ShPtr<Statement> stmt,
		ShPtr<Function> func, ShPtr<Module> module) {
	PRECONDITION_NON_NULL(call);
	PRECONDITION_NON_NULL(stmt);
	PRECONDITION_NON_NULL(func);

	// Use a CFG to find the block in which the statement appears.
	ShPtr<CFG> cfg(cio->getCFGForFunc(func));
	CFG::StmtInNode stmtInNode(cfg->getNodeForStmt(stmt));
	ShPtr<CFG::Node> nodeForStmt(stmtInNode.first);
	ASSERT_MSG(nodeForStmt, "statement `" << stmt << "` does not exist in the CFG");
	auto stmtIter = stmtInNode.second;

	// Try to find a pattern matching the given sequence of information.
	APICallSeqData data(info);
	data.apply(*stmtIter, call);
	while (++stmtIter != nodeForStmt->stmt_end() && !data.atEnd()) {
		ShPtr<ValueData> stmtData(va->getValueData(*stmtIter));
		for (auto i = stmtData->call_begin(), e = stmtData->call_end();
				i != e; ++i) {
			if (data.matches(*i)) {
				data.apply(*stmtIter, *i);
			}
		}
	}
	return data.patternIsComplete() ?
		Patterns(1, data.getPattern()) : Patterns();
}

} // namespace llvmir2hll
} // namespace retdec
