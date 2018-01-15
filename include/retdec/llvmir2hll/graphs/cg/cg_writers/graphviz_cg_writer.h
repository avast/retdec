/**
* @file include/retdec/llvmir2hll/graphs/cg/cg_writers/graphviz_cg_writer.h
* @brief A CG writer in the @c dot format (@c graphviz).
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CG_CG_WRITERS_GRAPHVIZ_CG_WRITER_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CG_CG_WRITERS_GRAPHVIZ_CG_WRITER_H

#include <ostream>
#include <string>

#include "retdec/llvmir2hll/graphs/cg/cg.h"
#include "retdec/llvmir2hll/graphs/cg/cg_writer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A CG writer in the @c dot format (@c graphviz).
*
* For more information on the @c dot format, see http://www.graphviz.org/.
*
* Use create() to create instances. Instances of this class have
* reference object semantics.
*/
class GraphvizCGWriter: public CGWriter {
public:
	static ShPtr<CGWriter> create(ShPtr<CG> cg, std::ostream &out);

	virtual std::string getId() const override;
	virtual bool emitCG() override;

private:
	/// Mapping between a node and its label.
	using NodeLabelMapping = std::map<ShPtr<Function>, std::string>;

private:
	GraphvizCGWriter(ShPtr<CG> cg, std::ostream &out);

	void emitNode(ShPtr<Function> caller, ShPtr<CG::CalledFuncs> callees);
	std::string getNodeLabelForFunc(ShPtr<Function> func);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
