/**
 * @file include/retdec/rtti-finder/vtable/vtable_finder.h
 * @brief Find vtable structures in @c Image.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_RTTI_FINDER_VTABLE_VTABLE_FINDER_H
#define RETDEC_RTTI_FINDER_VTABLE_VTABLE_FINDER_H

#include <cstdint>
#include <vector>

#include "retdec/rtti-finder/rtti/rtti_gcc.h"
#include "retdec/rtti-finder/rtti/rtti_msvc.h"
#include "retdec/rtti-finder/vtable/vtable_gcc.h"
#include "retdec/rtti-finder/vtable/vtable_msvc.h"
#include "retdec/utils/address.h"

namespace retdec {
namespace rtti_finder {

namespace loader {
	class Image;
} // namespace loader

void findGccVtables(
		const retdec::loader::Image* img,
		VtablesGcc& vtables,
		RttiGcc& rttis);

void findMsvcVtables(
		const retdec::loader::Image* img,
		VtablesMsvc& vtables,
		RttiMsvc& rttis);

} // namespace rtti_finder
} // namespace retdec

#endif
