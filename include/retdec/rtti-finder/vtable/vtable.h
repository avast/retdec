/**
 * @file include/retdec/rtti-finder/vtable/vtable.h
 * @brief General C++ virtual table structures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_CPP_VTABLE_VTABLE_H
#define RETDEC_FILEFORMAT_TYPES_CPP_VTABLE_VTABLE_H

#include <cstdint>
#include <vector>

#include "retdec/utils/address.h"

namespace retdec {
namespace rtti_finder {

/**
 * One item in virtual table.
 * Item must have at least address set.
 * If there is a function on this address, it can be also set.
 * However, it is possible that function on address was not yet detected.
 * In such a case, we can use this virtual table entry to detect function.
 */
class VtableItem
{
	public:
		VtableItem(retdec::utils::Address a, bool thumb = false) :
			address(a),
			isThumb(thumb)
		{}

	public:
		retdec::utils::Address address;
		bool isThumb = false;
};

/**
 * Virtual table comes in two flavors: 1) gcc&clang, 2) MSVC.
 * This is a base class for both of them.
 */
class Vtable
{
	public:
		Vtable(retdec::utils::Address a) : vtableAddress(a) {}
		virtual ~Vtable() {}

	public:
		retdec::utils::Address vtableAddress;
		std::vector<VtableItem> virtualFncAddresses;
};

} // namespace rtti_finder
} // namespace retdec

#endif
