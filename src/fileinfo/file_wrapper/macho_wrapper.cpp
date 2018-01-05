/**
 * @file src/fileinfo/file_wrapper/macho_wrapper.cpp
 * @brief Methods of MachOWrapper class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/Support/MachO.h>

#include "fileinfo/file_wrapper/macho_wrapper.h"

using namespace llvm::MachO;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param pathToFile Path to MachO binary file
 * @param loadFlags Load flags
 */
MachOWrapper::MachOWrapper(std::string pathToFile, retdec::fileformat::LoadFlags loadFlags) : MachOFormat(pathToFile, loadFlags)
{

}

/**
 * Destructor
 */
MachOWrapper::~MachOWrapper()
{

}

/**
 * Get LLVM COFF parser
 * @return LLVM COFF parser
 */
const llvm::object::MachOObjectFile* MachOWrapper::getMachOParser() const
{
	return file.get();
}

/**
 * Get type of binary file
 * @return Type of binary file (e.g. DLL)
 */
std::string MachOWrapper::getTypeOfFile() const
{
	switch(getFileType())
	{
		case MH_OBJECT:
			return "Relocatable file";
		case MH_EXECUTE:
			return "Executable file";
		case MH_PRELOAD:
			return "Preload executable file";
		case MH_DYLIB:
			return "Dynamic library";
		case MH_BUNDLE:
			return "Bundle";
		case MH_CORE:
			return "Core dump";
		case MH_DYLINKER:
			return "Dynamic linker shared library";
		case MH_KEXT_BUNDLE:
			return "Kernel extensions";
		case MH_FVMLIB:
			return "Fixed VM shared library";
		case MH_DYLIB_STUB:
			return "Shared library stub";
		case MH_DSYM:
			return "Debug file";
		default:
			return "Unknown";
	}

	return "Unknown";
}

} // namespace fileinfo
