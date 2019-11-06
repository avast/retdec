/**
 * @file include/retdec/config/vtables.h
 * @brief Decompilation configuration manipulation: vtables.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_VTABLES_H
#define RETDEC_CONFIG_VTABLES_H

#include <string>

#include "retdec/config/base.h"

namespace retdec {
namespace config {

/**
 * Represents C++ virtual table.
 * Table address is its unique ID.
 */
class VtableItem
{
	public:
		explicit VtableItem(const retdec::common::Address& a);
		static VtableItem fromJsonValue(const Json::Value& val);

		Json::Value getJsonValue() const;

		/// @name VtableItem set methods.
		/// @{
		void setTargetFunctionAddress(const retdec::common::Address& a);
		void setTargetFunctionName(const std::string& n);
		/// @}

		/// @name VtableItem get methods.
		/// @{
		retdec::common::Address getId() const;
		retdec::common::Address getAddress() const;
		retdec::common::Address getTargetFunctionAddress() const;
		std::string getTargetFunctionName() const;
		/// @}

		bool operator<(const VtableItem& o) const;
		bool operator==(const VtableItem& o) const;

	private:
		/// Virtual table item's address in binary file.
		retdec::common::Address _address;
		/// Virtual function address for this item.
		retdec::common::Address _targetAddress;
		/// Name (unique ID) of function on target address.
		std::string _targetFunctionName;
};

/**
 * Represents virtual table.
 * Table's address in binary file is its unique ID.
 */
class Vtable
{
	public:
		explicit Vtable(const retdec::common::Address& a);
		static Vtable fromJsonValue(const Json::Value& val);

		Json::Value getJsonValue() const;

		/// @name Vtable set methods.
		/// @{
		void setName(const std::string& n);
		/// @}

		/// @name Vtable get methods.
		/// @{
		retdec::common::Address getId() const;
		retdec::common::Address getAddress() const;
		std::string getName() const;
		/// @}

		bool operator<(const Vtable& o) const;
		bool operator==(const Vtable& o) const;

	private:
		using VtableItemContainer = BaseAssociativeContainer<retdec::common::Address, VtableItem>;

	public:
		VtableItemContainer items;

	private:
		std::string _name;
		/// Virtual table's address in binary file.
		retdec::common::Address _address;
};

/**
 * An associative container with virtual function tables' addresses as the key.
 * See Vtable class for details.
 */
class VtableContainer : public BaseAssociativeContainer<retdec::common::Address, Vtable>
{

};

} // namespace config
} // namespace retdec

#endif
