/**
* @file include/retdec/bin2llvmir/optimizations/param_return/filter/ms_x64.h
* @brief Microsoft x64 specific filtration of registers.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PARAM_RETURN_FILTER_MS_X64_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PARAM_RETURN_FILTER_MS_X64_H

#include "retdec/bin2llvmir/optimizations/param_return/filter/filter.h"

namespace retdec {
namespace bin2llvmir {

class MSX64Filter : public Filter
{
	public:
		using Filter::Filter;

		virtual void filterDefinitionArgs(
				FilterableLayout& args,
				bool isVoidarg) const override;

		virtual void filterCallArgs(
				FilterableLayout& args,
				bool isVoidarg) const override;

		virtual void filterArgsByKnownTypes(FilterableLayout& lay) const override;

	private:
		void leaveOnlyAlternatingArgRegisters(FilterableLayout& lay) const;
};

}
}

#endif
