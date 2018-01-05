/**
* @file include/retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info.h
* @brief A representation of information about an API call.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_API_CALL_INFO_H
#define RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_API_CALL_INFO_H

#include <map>
#include <string>

#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A representation of information about an API call.
*
* Use APICallInfoSeq to join serveral information into a sequence.
*/
class APICallInfo {
public:
	/// Parameter number (the first parameter has number 1, the second has
	/// number 2 etc.)
	using ParamNum = unsigned;

	/// Mapping of a parameter number into a bind ID.
	using ParamBindMap = std::map<ParamNum, std::string>;

	/// Iterator for iterating over ParamBindMap.
	/// Attributes (@c i is an iterator):
	///  - @c i->first is the parameter's number,
	///  - @c i->second is the parameter's bind ID.
	using param_bind_iterator = ParamBindMap::const_iterator;

public:
	APICallInfo(std::string funcName);

	// The compiler-generated destructor, copy constructor and assignment
	// operator are just fine, so we don't have to create our own ones.

	bool operator==(const APICallInfo &other) const;
	bool operator!=(const APICallInfo &other) const;

	/// @name Function Name Accessors
	/// @{
	const std::string getFuncName() const;
	/// @}

	/// @name Return Value Binding
	/// @{
	APICallInfo &bindReturnValue(const std::string &bindId);
	bool hasBoundReturnValue() const;
	std::string getReturnValueBind() const;
	/// @}

	/// @name Parameter Binding
	/// @{
	APICallInfo &bindParam(ParamNum n, const std::string &bindId);
	bool hasBoundParam(ParamNum n) const;
	std::string getParamBind(ParamNum n) const;

	param_bind_iterator param_bind_begin() const;
	param_bind_iterator param_bind_end() const;
	/// @}

private:
	/// Name of the function.
	std::string funcName;

	/// ID of the bind to the return value. If there is no bind, it is empty.
	std::string returnValueBind;

	/// ID of the binds to parameters (if any). If there are no binds, it is
	/// empty.
	ParamBindMap paramBinds;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
