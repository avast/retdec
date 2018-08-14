/**
 * @file include/retdec/rtti-finder/rtti/rtti_gcc_parser.h
 * @brief Parse C++ GCC/Clang RTTI structures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_RTTI_FINDER_RTTI_RTTI_GCC_PARSER_H
#define RETDEC_RTTI_FINDER_RTTI_RTTI_GCC_PARSER_H

#include "retdec/rtti-finder/rtti/rtti_gcc.h"
#include "retdec/utils/address.h"

namespace retdec {
namespace rtti_finder {

namespace loader {
	class Image;
} // namespace loader

std::shared_ptr<ClassTypeInfo> parseGccRtti(
		const retdec::loader::Image* img,
		RttiGcc& rttis,
		retdec::utils::Address rttiAddr);

void finalizeGccRtti(RttiGcc& rttis);

} // namespace rtti_finder
} // namespace retdec

#endif
