/**
* @file include/retdec/ctypes/enum_type.h
* @brief A representation of enum types.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_ENUM_TYPE_H
#define RETDEC_CTYPES_ENUM_TYPE_H

#include <memory>
#include <string>
#include <vector>

#include "retdec/ctypes/type.h"

namespace retdec {
namespace ctypes {

class Context;

/**
* @brief A representation of enum type.
*/
class EnumType: public Type
{
	public:
		/**
		* @brief A representation of enum value.
		*/
		class Value {
			public:
				/// Type of enum value.
				using ValueType = std::int64_t;

			public:
				Value(const std::string &name, ValueType value);

				const std::string &getName() const;
				ValueType getValue() const;

				bool operator==(const Value &other) const;
				bool operator!=(const Value &other) const;

			private:
				std::string name;
				ValueType value;
		};

	public:
		/// Value used for unknown values.
		static const Value::ValueType DEFAULT_VALUE;

	public:
		using Values = std::vector<Value>;
		using iterator = Values::iterator;
		using const_iterator = Values::const_iterator;

	public:
		static std::shared_ptr<EnumType> create(const std::shared_ptr<Context> &context,
			const std::string &name, const Values &values);

		/// @name Enum type values.
		/// @{
		iterator value_begin();
		const_iterator value_begin() const;
		iterator value_end();
		const_iterator value_end() const;
		Values::size_type getValueCount() const;
		const Value &getValue(Values::size_type index) const;
		/// @}

		virtual bool isEnum() const override;

		/// @name Visitor interface.
		/// @{
		virtual void accept(Visitor *v) override;
		/// @}

	private:
		EnumType(const std::string &name, const Values &values);

	private:
		Values values;
};

} // namespace ctypes
} // namespace retdec

#endif
