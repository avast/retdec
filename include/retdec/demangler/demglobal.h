/**
 * @file include/retdec/demangler/demglobal.h
 * @brief Global variables in demangler namespace.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_DEMANGLER_DEMGLOBAL_H
#define RETDEC_DEMANGLER_DEMGLOBAL_H

#include "retdec/demangler/igrams.h"

namespace retdec {
namespace demangler {

extern cGram::igram_t internalGrammarStruct;
extern cIgram_msll* igram_msll;
extern cIgram_gccll* igram_gccll;

} // namespace demangler
} // namespace retdec

#endif
