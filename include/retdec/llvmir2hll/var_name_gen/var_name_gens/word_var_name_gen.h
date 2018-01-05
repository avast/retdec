/**
* @file include/retdec/llvmir2hll/var_name_gen/var_name_gens/word_var_name_gen.h
* @brief A generator of English words as variable names.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_VAR_NAME_GEN_VAR_NAME_GENS_WORD_VAR_NAME_GEN_H
#define RETDEC_LLVMIR2HLL_VAR_NAME_GEN_VAR_NAME_GENS_WORD_VAR_NAME_GEN_H

#include <cstddef>
#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gen.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A generator of words as variable names.
*
* Use create() to create instances.
*
* At each call of getNextVarName(), a new English word is returned. Each
* returned variable name is prefixed with @c prefix, where @c prefix is the
* parameter of create(). When there are no available names to be returned,
* getNextVarName() starts returning the names from the beginning.
*/
class WordVarNameGen: public VarNameGen {
public:
	static UPtr<VarNameGen> create(std::string prefix = "");

	virtual std::string getId() const override;
	virtual void restart() override;
	virtual std::string getNextVarName() override;

private:
	WordVarNameGen(std::string prefix);

private:
	/// Index to the next word.
	std::size_t nextWordIndex;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
