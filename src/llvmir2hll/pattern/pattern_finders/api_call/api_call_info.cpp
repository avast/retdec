/**
* @file src/llvmir2hll/pattern/pattern_finders/api_call/api_call_info.cpp
* @brief Implementation of APICallInfo.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::addToMap;
using retdec::utils::mapGetValueOrDefault;
using retdec::utils::mapHasKey;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs an API call information for a function named @a funcName.
*
* @par Preconditions
*  - @a funcName is nonempty
*/
APICallInfo::APICallInfo(std::string funcName): funcName(funcName) {
	PRECONDITION(!funcName.empty(), "the function's name cannot be empty");
}

/**
* @brief Returns @c true if this info is equal to @a other, @c false otherwise.
*/
bool APICallInfo::operator==(const APICallInfo &other) const {
	return funcName == other.funcName &&
		returnValueBind == other.returnValueBind &&
		paramBinds == other.paramBinds;
}

/**
* @brief Returns @c true if this info is not equal to @a other, @c false
*        otherwise.
*/
bool APICallInfo::operator!=(const APICallInfo &other) const {
	return !(*this == other);
}

/**
* @brief Returns the name of the function that this API call information
*        describes.
*/
const std::string APICallInfo::getFuncName() const {
	return funcName;
}

/**
* @brief Binds @a bindId to the return value.
*
* @return A reference to the modified info. This allows the bind calls to be
*         chained, like this:
*         @code
*         APICallInfo("fopen")
*             .bindRetVal("X")
*             .bindParam(1, "Y")
*         @endcode
*
* If this function is called several times, the last bind is stored.
*
* @par Preconditions
*  - @a bindId is nonempty
*/
APICallInfo &APICallInfo::bindReturnValue(const std::string &bindId) {
	PRECONDITION(!bindId.empty(), "bindId has to be nonempty");

	returnValueBind = bindId;
	return *this;
}

/**
* @brief Returns @c true if the return value has been bound to some ID, @c
*        false otherwise.
*/
bool APICallInfo::hasBoundReturnValue() const {
	return !returnValueBind.empty();
}

/**
* @brief Returns the ID of the bind to the return value.
*
* @par Preconditions
*  - the return value is bound
*/
std::string APICallInfo::getReturnValueBind() const {
	PRECONDITION(!returnValueBind.empty(), "the return value is not bound");

	return returnValueBind;
}

/**
* @brief Binds @a bindId to the given parameter.
*
* @param[in] n Parameter's number (the first parameter has number 1, the second
*              has number 2 etc.)
* @param[in] bindId ID to be bound to the parameter number @a n.
*
* @return A reference to the modified info. This allows the bind calls to be
*         chained, like this:
*         @code
*         APICallInfo("fopen")
*             .bindRetVal("X")
*             .bindParam(1, "Y")
*         @endcode
*
* If this function is called several times, the last bind is stored.
*
* @par Preconditions
*  - <tt>n > 0</tt>
*  - @a bindId is nonempty
*/
APICallInfo &APICallInfo::bindParam(ParamNum n, const std::string &bindId) {
	PRECONDITION(n > 0, "parameter's number has to be nonzero");
	PRECONDITION(!bindId.empty(), "bindId has to be nonempty");

	addToMap(n, bindId, paramBinds);
	return *this;
}

/**
* @brief Returns @c true if parameter number @a n has been bound to some ID, @c
*        false otherwise.
*
* @param[in] n Parameter's number (the first parameter has number 1, the second
*              has number 2 etc.)
*
* @par Preconditions
*  - <tt>n > 0</tt>
*/
bool APICallInfo::hasBoundParam(ParamNum n) const {
	PRECONDITION(n > 0, "parameter's number has to be nonzero");

	return mapHasKey(paramBinds, n);
}

/**
* @brief Returns the ID of the bind to the given parameter.
*
* @param[in] n Parameter's number (the first parameter has number 1, the second
*              has number 2 etc.)

* If the parameter has not been bound to anything, this function returns the
* empty string.
*
* @par Preconditions
*  - <tt>n > 0</tt>
*  - the parameter is bound
*/
std::string APICallInfo::getParamBind(ParamNum n) const {
	PRECONDITION(n > 0, "parameter's number has to be nonzero");
	PRECONDITION(hasBoundParam(n), "parameter " << n << " is not bound");

	return mapGetValueOrDefault(paramBinds, n);
}

/**
* @brief Returns an iterator to the first parameter bind.
*/
APICallInfo::param_bind_iterator APICallInfo::param_bind_begin() const {
	return paramBinds.begin();
}

/**
* @brief Returns an iterator past the last parameter bind.
*/
APICallInfo::param_bind_iterator APICallInfo::param_bind_end() const {
	return paramBinds.end();
}

} // namespace llvmir2hll
} // namespace retdec
