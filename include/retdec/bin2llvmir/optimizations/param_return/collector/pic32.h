/**
* @file include/retdec/bin2llvmir/optimizations/param_return/collector/pic32.h
* @brief Pic32 specific collection algorithms.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PARAM_RETURN_COLLECTOR_PIC32_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PARAM_RETURN_COLLECTOR_PIC32_H

#include "retdec/bin2llvmir/optimizations/param_return/collector/collector.h"

namespace retdec {
namespace bin2llvmir {

class CollectorPic32 : public Collector
{
	public:
		using Collector::Collector;

	public:
		virtual void collectCallSpecificTypes(CallEntry* ce) const override;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
