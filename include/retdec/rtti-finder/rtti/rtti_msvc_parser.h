/**
 * @file include/retdec/rtti-finder/rtti/rtti_msvc_parser.h
 * @brief Parse C++ MSVC RTTI structures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_RTTI_FINDER_RTTI_RTTI_MSVC_PARSER_H
#define RETDEC_RTTI_FINDER_RTTI_RTTI_MSVC_PARSER_H

#include "retdec/rtti-finder/rtti/rtti_msvc.h"
#include "retdec/utils/address.h"

namespace retdec {
namespace rtti_finder {

namespace loader {
	class Image;
} // namespace loader

RTTICompleteObjectLocator* parseMsvcRtti(
		const retdec::loader::Image* img,
		RttiMsvc& rttis,
		retdec::utils::Address rttiAddr);

} // namespace rtti_finder
} // namespace retdec

#endif
