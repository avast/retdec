/**
 * \file include/retdec/retdec/retdec.h
 * \brief RetDec library.
 * \copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_RETDEC_RETDEC_H
#define RETDEC_RETDEC_RETDEC_H

#include "retdec/common/architecture.h"
#include "retdec/common/file_format.h"

namespace retdec {

/**
 * \param[in] inputPath
 * \param[in] a
 * \param[in] ff
 */
void disassemble(
		const std::string& inputPath,
		const retdec::common::Architecture& a = retdec::common::Architecture(),
		const retdec::common::FileFormat& ff = retdec::common::FileFormat());

} // namespace retdec

#endif
