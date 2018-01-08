/**
 * @file include/retdec/unpacker/unpacking_stub.h
 * @brief Base class for unpacking stubs that can be subclassed in unpacker plugins.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UNPACKER_UNPACKING_STUB_H
#define RETDEC_UNPACKER_UNPACKING_STUB_H

#include <string>

namespace retdec {

// Forward declarations
namespace loader { class Image; }
namespace unpacker { class DynamicBuffer; }

namespace unpacker {

/**
 * Base class for unpacking stubs that can be subclassed in unpacker plugins that work on unpacking
 * stub simulation basis.
 */
class UnpackingStub
{
public:
	/**
	 * Constructs the unpacking stub object operating on provided file.
	 *
	 * @param file File to operate on.
	 */
	UnpackingStub(loader::Image* file) : _file(file) {}

	/**
	 * Destructor.
	 */
	virtual ~UnpackingStub() {}

	/**
	 * Pure virtual method that should implement unpacking process in its subclasses.
	 *
	 * @param outputFile Path to the output unpacked file.
	 */
	virtual void unpack(const std::string& outputFile) = 0;

	/**
	 * Pure virtual method that should free all owned resources.
	 */
	virtual void cleanup() = 0;

	/**
	 * Returns the file the unpacking stub is operating on.
	 *
	 * @return The input file.
	 */
	loader::Image* getFile() { return _file; }

protected:
	void setFile(loader::Image* file) { _file = file; }

	loader::Image* _file;
};

} // namespace unpacker
} // namespace retdec

#endif
