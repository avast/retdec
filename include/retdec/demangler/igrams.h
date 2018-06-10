/**
 * @file include/retdec/demangler/igrams.h
 * @brief Internal grammar list.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_DEMANGLER_IGRAMS_H
#define RETDEC_DEMANGLER_IGRAMS_H

//[igram] add internal grammar headers here
#include "retdec/demangler/stgrammars/borlandll.h"
#include "retdec/demangler/stgrammars/gccll.h"
#include "retdec/demangler/stgrammars/msll.h"

namespace retdec {
namespace demangler {

bool initIgram(const std::string& gname, cGram* gParser);

void deleteIgrams(cGram* gParser);

} // namespace demangler
} // namespace retdec

#endif
