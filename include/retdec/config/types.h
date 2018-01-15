/**
 * @file include/retdec/config/types.h
 * @brief Decompilation configuration manipulation: types.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_TYPES_H
#define RETDEC_CONFIG_TYPES_H

#include <string>

#include "retdec/config/base.h"

namespace retdec {
namespace config {

/**
 * Represents data type.
 *
 * Type's LLVM IR representation is its unique ID.
 */
class Type
{
	public:
		Type();
		explicit Type(const std::string& llvmIrRepre);
		static Type fromJsonValue(const Json::Value& val);

		Json::Value getJsonValue() const;
		void readJsonValue(const Json::Value& val);

		/// @name Type query methods.
		/// @{
		bool isDefined() const;
		bool isWideString() const;
		/// @}

		/// @name Type set methods.
		/// @{
		void setLlvmIr(const std::string& t);
		void setIsWideString(bool b);
		/// @}

		/// @name Type get methods.
		/// @{
		std::string getId() const;
		std::string getLlvmIr() const;
		/// @}

		bool operator<(const Type& val) const;
		bool operator==(const Type& val) const;

	private:
		/// LLVM IR string representation.
		/// Unique ID.
		std::string _llvmIr = "i32";
		/// Wide strings are in LLVM IR represented as int arrays.
		/// This flag can be use to distinguish them from ordinary int arrays.
		bool _wideString = false;
};

/**
 * Set container for data types.
 * Data types' LLVM IR strings are set's keys.
 */
using TypeContainer = BaseSetContainer<Type>;

} // namespace config
} // namespace retdec

#endif
