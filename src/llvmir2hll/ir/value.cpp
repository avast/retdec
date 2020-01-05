/**
* @file src/llvmir2hll/ir/value.cpp
* @brief Implementation of Value.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/value.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/value_text_repr_visitor.h"

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Returns the textual representation of the given value.
*
* @tparam ValuePtr A pointer to Value.
*
* This function should be used in the overloads of operator<<().
*/
template<typename ValuePtr>
std::string getTextRepr(ValuePtr value) {
	return value ? value->getTextRepr() : "(null)";
}

} // anonymous namespace

Value* Value::getSelf() {
	return this;
}

/**
* @brief Returns a textual representation of the value.
*
* See the description of ValueTextReprVisitor::getTextRepr() for more
* information.
*/
std::string Value::getTextRepr() {
	return ValueTextReprVisitor::getTextRepr(this);
}

/**
* @brief Emits @a value into @a os.
*/
llvm::raw_ostream &operator<<(llvm::raw_ostream &os, Value* value) {
	return os << getTextRepr(value);
}

/**
* @brief Emits @a value into @a os.
*/
std::ostream &operator<<(std::ostream &os, Value *value) {
	return os << getTextRepr(value);
}

} // namespace llvmir2hll
} // namespace retdec
