/**
* @file src/ctypes/enum_type.cpp
* @brief Implementation of EnumType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <limits>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/enum_type.h"
#include "retdec/ctypes/visitor.h"
#include "retdec/utils/container.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new enum type.
*/
EnumType::EnumType(const std::string &name, const Values &values) :
	Type(name, 0), values(values) {}

/**
* @brief Constructs a new enum value.
*/
EnumType::Value::Value(const std::string &name, ValueType value) :
	name(name), value(value) {}

/// Sets default enum value.
const EnumType::Value::ValueType EnumType::DEFAULT_VALUE =
	std::numeric_limits<Value::ValueType>::min();

/**
* @brief Returns enum value's name.
*/
const std::string &EnumType::Value::getName() const
{
	return name;
}

/**
* @brief Returns enum value's value.
*/
EnumType::Value::ValueType EnumType::Value::getValue() const
{
	return value;
}

bool EnumType::Value::operator==(const Value &other) const
{
	return name == other.name && value == other.value;
}

bool EnumType::Value::operator!=(const Value &other) const
{
	return !(*this == other);
}

/**
* @brief Returns an iterator to the enum value.
*/
EnumType::iterator EnumType::value_begin()
{
	return values.begin();
}

/**
* @brief Returns a constant iterator to the enum value.
*/
EnumType::const_iterator EnumType::value_begin() const
{
	return values.begin();
}

/**
* @brief Returns an iterator past the last enum value.
*/
EnumType::iterator EnumType::value_end()
{
	return values.end();
}

/**
* @brief Returns a constant iterator past the last enum value.
*/
EnumType::const_iterator EnumType::value_end() const
{
	return values.end();
}

/**
* @brief Returns number of enum's values.
*/
EnumType::Values::size_type EnumType::getValueCount() const
{
	return values.size();
}

/**
* @brief Returns n-th value.
*
* @par Preconditions
*  - <tt>0 < n <= ValueCount</tt>
*/
const EnumType::Value &EnumType::getValue(Values::size_type n) const
{
	return retdec::utils::getNthItem(values, n);
}

/**
* @brief Creates enum type.
*
* @param context Storage for already created functions, types.
* @param name Name of new enum type.
* @param values Enum values.
*
* @par Preconditions
*  - @a context is not null
*
* Does not create new enum type, if one
* has already been created and stored in @c context.
*/
std::shared_ptr<EnumType> EnumType::create(const std::shared_ptr<Context> &context,
	const std::string &name, const Values &values)
{
	assert(context && "violated precondition - context cannot be null");

	auto type = context->getNamedType(name);
	if (type && type->isEnum())
	{
		return std::static_pointer_cast<EnumType>(type);
	}

	std::shared_ptr<EnumType> newType(new EnumType(name, values));
	context->addNamedType(newType);

	return newType;
}

/**
* Returns @c true when Type is enum, @c false otherwise.
*/
bool EnumType::isEnum() const
{
	return true;
}

void EnumType::accept(Visitor *v) {
	v->visit(std::static_pointer_cast<EnumType>(shared_from_this()));
}

} // namespace ctypes
} // namespace retdec
