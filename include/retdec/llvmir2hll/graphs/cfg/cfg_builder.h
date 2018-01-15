/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_builder.h
* @brief A base class for creators of control-flow graphs (CFGs) from
*        functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_BUILDER_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_BUILDER_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class CFG;
class Function;

/**
* @brief A base class for creators of control-flow graphs (CFGs) from
*        functions.
*
* A subclass should:
* - implement the @c buildCFG() function,
* - provide a static @c create() function to ease the creation of the builder.
*
* Instances of this class have reference object semantics. The class implements
* the NVI ("non-virtual interface") pattern.
*/
class CFGBuilder: private retdec::utils::NonCopyable {
public:
	virtual ~CFGBuilder();

	ShPtr<CFG> getCFG(ShPtr<Function> func);

protected:
	CFGBuilder();

protected:
	/// A CFG that is currently being built.
	ShPtr<CFG> cfg;

	/// A function from which the CFG is being built.
	ShPtr<Function> func;

private:
	void initializeNewCFG(ShPtr<Function> func);

	/**
	* @brief Builds @c cfg.
	*
	* When this function is called, @c cfg and @c func are correctly
	* initialized.
	*/
	virtual void buildCFG() = 0;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
