/**
 * @file src/rtti-finder/rtti_finder.cpp
 * @brief Find C++ RTTI structures in @c Image.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/loader/loader/image.h"
#include "retdec/rtti-finder/rtti_finder.h"
#include "retdec/rtti-finder/vtable/vtable_finder.h"

namespace retdec {
namespace rtti_finder {

/**
 * Find GCC/Clang C++ vtables and RTTI from file.
 * Fill @c _vtablesGcc and @c __rttiGcc;
 */
void RttiFinder::findGcc(const retdec::loader::Image* img)
{
	findGccVtables(img, _vtablesGcc, _rttiGcc);
}

/**
 * Find MSVC C++ vtables and RTTI from file.
 * Fill @c vtablesMsvc and @c _rttiMsvc.
 */
void RttiFinder::findMsvc(const retdec::loader::Image* img)
{
	findMsvcVtables(img, _vtablesMsvc, _rttiMsvc);
}

/**
 * @return C++ GCC/Clang virtual tables, including RTTI information.
 *
 * These information are not parsed by default, @c FileFormat user must
 * initialize it by calling @c loadVtableGcc() method first.
 */
const VtablesGcc& RttiFinder::getVtablesGcc() const
{
	return _vtablesGcc;
}

/**
 * @return C++ MSVC virtual tables, including RTTI information.
 *
 * These information are not parsed by default, @c FileFormat user must
 * initialize it by calling @c loadVtableMsvc() method first.
 */
const VtablesMsvc& RttiFinder::getVtablesMsvc() const
{
	return _vtablesMsvc;
}

/**
 * @return C++ GCC/Clang RTTI information.
 *
 * These information are not parsed by default, @c FileFormat user must
 * initialize it by calling @c loadVtableGcc() method first.
 */
const RttiGcc& RttiFinder::getRttiGcc() const
{
	return _rttiGcc;
}

/**
 * @return C++ MSVC RTTI information.
 *
 * These information are not parsed by default, @c FileFormat user must
 * initialize it by calling @c loadVtableMsvc() method first.
 */
const RttiMsvc& RttiFinder::getRttiMsvc() const
{
	return _rttiMsvc;
}

/**
 * Get vtable on address @a address.
 * This tries to get vtable from both GCC and MSVC vtable containers
 * and expect that only one of them was loaded -> there should not be a vtable
 * at the address in both of them.
 */
const Vtable* RttiFinder::getVtable(retdec::utils::Address a) const
{
	auto gccIt = _vtablesGcc.find(a);
	if (gccIt != _vtablesGcc.end())
	{
		return &gccIt->second;
	}

	auto msvcIt = _vtablesMsvc.find(a);
	if (msvcIt != _vtablesMsvc.end())
	{
		return &msvcIt->second;
	}

	return nullptr;
}

} // namespace rtti_finder
} // namespace retdec
