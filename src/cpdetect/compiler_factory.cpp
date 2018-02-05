/**
 * @file src/cpdetect/compiler_factory.cpp
 * @brief Factory for creating compiler detectors.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/cpdetect/compiler_detector/coff_compiler.h"
#include "retdec/cpdetect/compiler_detector/elf_compiler.h"
#include "retdec/cpdetect/compiler_detector/intel_hex_compiler.h"
#include "retdec/cpdetect/compiler_detector/macho_compiler.h"
#include "retdec/cpdetect/compiler_detector/pe_compiler.h"

using namespace retdec::fileformat;

namespace retdec {
namespace cpdetect {

/**
 * Create instance of CompilerDetector class
 * @param parser Parser of input file
 * @param params Parameters for compiler detection
 * @param toolInfo Into this parameter are stored detected tools
 * @return Pointer to instance of CompilerDetector class or @c nullptr if any error
 *
 * If format of input file is not supported, function will return @c nullptr.
 */
std::unique_ptr<CompilerDetector> createCompilerDetector(
		retdec::fileformat::FileFormat &parser, DetectParams &params, ToolInformation &toolInfo)
{
	CoffFormat *coff = dynamic_cast<CoffFormat*>(&parser);
	ElfFormat *elf = dynamic_cast<ElfFormat*>(&parser);
	PeFormat *pe = dynamic_cast<PeFormat*>(&parser);
	MachOFormat *macho = dynamic_cast<MachOFormat*>(&parser);
	IntelHexFormat *intelHex = dynamic_cast<IntelHexFormat*>(&parser);

	switch(parser.getFileFormat())
	{
		case Format::COFF:
			return std::make_unique<CoffCompiler>(*coff, params, toolInfo);
		case Format::ELF:
			return std::make_unique<ElfCompiler>(*elf, params, toolInfo);
		case Format::PE:
			return std::make_unique<PeCompiler>(*pe, params, toolInfo);
		case Format::MACHO:
			return std::make_unique<MachOCompiler>(*macho, params, toolInfo);
		case Format::INTEL_HEX:
			return std::make_unique<IntelHexCompiler>(*intelHex, params, toolInfo);
		default:
			return nullptr;
	}
}

} // namespace cpdetect
} // namespace retdec
