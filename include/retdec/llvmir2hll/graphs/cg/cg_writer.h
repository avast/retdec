/**
* @file include/retdec/llvmir2hll/graphs/cg/cg_writer.h
* @brief A base class of all call graph (CG) writers.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CG_CG_WRITER_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CG_CG_WRITER_H

#include <ostream>
#include <string>

#include "retdec/llvmir2hll/graphs/cg/cg.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A base class of all call graph (CG) writers.
*
* Every CG writer should subclass this class and override emitCG().
*
* Instances of this class have reference object semantics.
*/
class CGWriter: private retdec::utils::NonCopyable {
public:
	virtual ~CGWriter() = 0;

	/**
	* @brief Returns the ID of the writer.
	*/
	virtual std::string getId() const = 0;

	/**
	* @brief Emits the given CG into the given output stream.
	*
	* The format of the written data depends on the subclass of this class.
	*
	* @return @c true if some code has been emitted, @c false otherwise.
	*/
	virtual bool emitCG() = 0;

protected:
	CGWriter(ShPtr<CG> cg, std::ostream &out);

protected:
	/// CG to be emitted.
	ShPtr<CG> cg;

	/// Stream, where the resulting CG will be emitted.
	std::ostream &out;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
