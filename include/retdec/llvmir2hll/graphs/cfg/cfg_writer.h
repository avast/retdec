/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_writer.h
* @brief A base class of all control-flow graph (CFG) writers.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_WRITER_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_WRITER_H

#include <map>
#include <ostream>
#include <string>

#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A base class of all control-flow graph (CFG) writers.
*
* Every CFG writer should subclass this class and override emitCFG().
*
* Instances of this class have reference object semantics.
*/
class CFGWriter: private retdec::utils::NonCopyable {
public:
	virtual ~CFGWriter() = 0;

	/**
	* @brief Returns the ID of the writer.
	*/
	virtual std::string getId() const = 0;

	/**
	* @brief Emits the given CFG into the given output stream.
	*
	* The format of the written data depends on the subclass of this class.
	*
	* @return @c true if some code has been emitted, @c false otherwise.
	*/
	virtual bool emitCFG() = 0;

protected:
	/// Mapping between a node and its label.
	using NodeLabelMapping = std::map<ShPtr<CFG::Node>, std::string>;

protected:
	CFGWriter(ShPtr<CFG> cfg, std::ostream &out);

protected:
	/// CFG to be emitted.
	ShPtr<CFG> cfg;

	/// Stream, where the resulting CFG will be emitted.
	std::ostream &out;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
