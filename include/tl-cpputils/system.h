/**
* @file include/tl-cpputils/system.h
* @brief Portable system utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef TL_CPPUTILS_SYSTEM_H
#define TL_CPPUTILS_SYSTEM_H

namespace tl_cpputils {

void sleep(unsigned seconds);

bool isLittleEndian();

bool systemHasLongDouble();

} // namespace tl_cpputils

#endif
