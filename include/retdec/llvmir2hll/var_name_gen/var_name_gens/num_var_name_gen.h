/**
* @file include/retdec/llvmir2hll/var_name_gen/var_name_gens/num_var_name_gen.h
* @brief A generator of variable names of the form "prefixN", where N is a
*        number.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_VAR_NAME_GEN_VAR_NAME_GENS_NUM_VAR_NAME_GEN_H
#define RETDEC_LLVMIR2HLL_VAR_NAME_GEN_VAR_NAME_GENS_NUM_VAR_NAME_GEN_H

#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gen.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A generator of variable names of the form @c prefixN, where @c N is a
*        number.
*
* Use create() to create instances.
*/
class NumVarNameGen: public VarNameGen {
public:
	// TODO Refactor "var" into a named constant.
	static UPtr<VarNameGen> create(std::string prefix = "var");

	virtual std::string getId() const override;
	virtual void restart() override;
	virtual std::string getNextVarName() override;

private:
	NumVarNameGen(std::string prefix);

private:
	/// Next variable number to be used.
	unsigned nextVarNum;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
