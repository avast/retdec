/**
 * @file include/retdec/rtti-finder/vtable/vtable_gcc.h
 * @brief MSVC C++ virtual table structures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_RTTI_FINDER_VTABLE_VTABLE_MSVC_H
#define RETDEC_RTTI_FINDER_VTABLE_VTABLE_MSVC_H

#include <cstdint>
#include <map>
#include <vector>

#include "retdec/rtti-finder/rtti/rtti_msvc.h"
#include "retdec/common/address.h"
#include "retdec/common/vtable.h"

namespace retdec {
namespace rtti_finder {

/**
 * MSVC virtual table sturcture ( [] means array of entries ):
 *
 *   complete object locator address
 *   [virtual function pointers] <- vtable address in instances points here
 *
 */
class VtableMsvc : public retdec::common::Vtable
{
	public:
		VtableMsvc(retdec::common::Address a) : Vtable(a) {}

	public:
		retdec::common::Address objLocatorAddress;
		RTTICompleteObjectLocator* rtti = nullptr;
};

using VtablesMsvc = std::map<retdec::common::Address, VtableMsvc>;

} // namespace rtti_finder
} // namespace retdec

#endif
