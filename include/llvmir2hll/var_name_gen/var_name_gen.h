/**
* @file include/llvmir2hll/var_name_gen/var_name_gen.h
* @brief A base class for all generators of variable names.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_VAR_NAME_GEN_VAR_NAME_GEN_H
#define LLVMIR2HLL_VAR_NAME_GEN_VAR_NAME_GEN_H

#include <string>

#include "tl-cpputils/non_copyable.h"

namespace llvmir2hll {

/**
* @brief A base class for all generators of variable names.
*
* This class should be used as a base class for all generators of variable
* names. These are classes which can generate names of anonymous local
* variables.
*
* Instances of this class have reference object semantics.
*/
class VarNameGen: private tl_cpputils::NonCopyable {
public:
	virtual ~VarNameGen();

	/**
	* @brief Returns the ID of the generator.
	*/
	virtual std::string getId() const = 0;

	/**
	* @brief Restarts the generator to start returning variable names from the
	*        beginning.
	*
	* Note that there is no requirement for this class to return variable names
	* in the same order between consecutive calls to this function.
	*/
	virtual void restart() = 0;

	/**
	* @brief Returns a next variable name.
	*
	* If there is no next variable name available, the generator starts
	* generating names from the beginning.
	*/
	virtual std::string getNextVarName() = 0;

	const std::string &getPrefix() const;

protected:
	VarNameGen(std::string prefix = "");

protected:
	/// The prefix of all returned variable names.
	const std::string prefix;
};

} // namespace llvmir2hll

#endif
