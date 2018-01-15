/**
* @file include/retdec/llvmir2hll/var_renamer/var_renamers/simple_var_renamer.h
* @brief A renamer of variable names which names them simply by using the
*        given variable name generator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_VAR_RENAMER_VAR_RENAMERS_SIMPLE_VAR_RENAMER_H
#define RETDEC_LLVMIR2HLL_VAR_RENAMER_VAR_RENAMERS_SIMPLE_VAR_RENAMER_H

#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/var_renamer/var_renamer.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A renamer of variable names which names them simply by using the
*        given variable name generator.
*
* Use create() to create instances.
*/
class SimpleVarRenamer: public VarRenamer {
public:
	static ShPtr<VarRenamer> create(ShPtr<VarNameGen> varNameGen,
		bool useDebugNames = true);

	virtual std::string getId() const override;

private:
	SimpleVarRenamer(ShPtr<VarNameGen> varNameGen, bool useDebugNames);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
