/**
 * @file include/retdec/rtti-finder/rtti_finder.h
 * @brief Find C++ RTTI structures in @c Image.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_RTTI_FINDER_RTTI_FINDER_H
#define RETDEC_RTTI_FINDER_RTTI_FINDER_H

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

class RttiFinder
{
	public:
		void findGcc(const retdec::loader::Image* img);
		void findMsvc(const retdec::loader::Image* img);

		const VtablesGcc& getVtablesGcc() const;
		const VtablesMsvc& getVtablesMsvc() const;
		const RttiGcc& getRttiGcc() const;
		const RttiMsvc& getRttiMsvc() const;

		const Vtable* getVtable(retdec::utils::Address a) const;

	private:
		/// C++ GCC/Clang vtables, including RTTIs.
		VtablesGcc _vtablesGcc;
		/// C++ MSVC vtables, including RTTIs.
		VtablesMsvc _vtablesMsvc;
		/// C++ GCC/Clang RTTI;
		RttiGcc _rttiGcc;
		/// C++ MSVC RTTI;
		RttiMsvc _rttiMsvc;
};

} // namespace rtti_finder
} // namespace retdec

#endif
