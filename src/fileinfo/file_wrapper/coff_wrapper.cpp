/**
 * @file src/fileinfo/file_wrapper/coff_wrapper.cpp
 * @brief Methods of CoffWrapper class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_wrapper/coff_wrapper.h"

using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param pathToFile Path to COFF binary file
 * @param loadFlags Load flags
 */
CoffWrapper::CoffWrapper(std::string pathToFile, retdec::fileformat::LoadFlags loadFlags) : CoffFormat(pathToFile, loadFlags)
{

}

/**
 * Destructor
 */
CoffWrapper::~CoffWrapper()
{

}

/**
 * Get LLVM COFF parser
 * @return LLVM COFF parser
 */
const llvm::object::COFFObjectFile* CoffWrapper::getCoffParser() const
{
	return file;
}

/**
 * Get type of binary file
 * @return Type of binary file (e.g. DLL)
 */
std::string CoffWrapper::getTypeOfFile() const
{
	if(isDll())
	{
		return "DLL";
	}
	else if(isExecutable())
	{
		return "Executable file";
	}
	else if(isObjectFile())
	{
		return "Relocatable file";
	}

	return "";
}

} // namespace fileinfo
