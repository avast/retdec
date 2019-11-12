/**
 * @file include/retdec/common/type.h
 * @brief Common data type representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_COMMON_TYPE_H
#define RETDEC_COMMON_TYPE_H

#include <set>
#include <string>

namespace retdec {
namespace common {

/**
 * Represents data type.
 *
 * Type's LLVM IR representation is its unique ID.
 */
class Type
{
	public:
		Type();
		Type(const std::string& llvmIrRepre);

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

using TypeContainer = std::set<Type>;

} // namespace common
} // namespace retdec

#endif
