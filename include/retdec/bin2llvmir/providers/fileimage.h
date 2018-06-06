/**
 * @file include/retdec/bin2llvmir/providers/fileimage.h
 * @brief File image provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_FILEIMAGE_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_FILEIMAGE_H

#include <llvm/IR/Constants.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>

#include "retdec/utils/address.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/debugformat.h"
#include "retdec/loader/loader/image.h"
#include "retdec/rtti-finder/rtti_finder.h"

namespace retdec {
namespace bin2llvmir {

class DebugFormat;

class FileImage
{
	// Ctors.
	//
	public:
		FileImage(
				llvm::Module* m,
				const std::string& path,
				Config* config);
		FileImage(
				llvm::Module* m,
				const std::shared_ptr<retdec::fileformat::FileFormat>& ff,
				Config* config);
		FileImage(
				llvm::Module* m,
				std::unique_ptr<retdec::loader::Image> img,
				Config* config);

	// Constant getters - get LLVM constant from the given address.
	//
	public:
		llvm::ConstantInt* getConstantInt(
				llvm::IntegerType* t,
				retdec::utils::Address addr);
		llvm::ConstantInt* getConstantDefault(retdec::utils::Address addr);
		llvm::Constant* getConstantHalf(retdec::utils::Address addr);
		llvm::Constant* getConstantFloat(retdec::utils::Address addr);
		llvm::Constant* getConstantDouble(retdec::utils::Address addr);
		llvm::Constant* getConstantLongDouble(retdec::utils::Address addr);
		llvm::Constant* getConstantCharPointer(retdec::utils::Address addr);
		llvm::Constant* getConstantCharArrayNice(retdec::utils::Address addr);
		llvm::Constant* getConstantPointer(
				llvm::PointerType* type,
				retdec::utils::Address addr);
		llvm::Constant* getConstantStruct(
				llvm::StructType* type,
				retdec::utils::Address addr);
		llvm::Constant* getConstantArray(
				llvm::ArrayType* type,
				retdec::utils::Address addr);
		llvm::Constant* getConstant(
				llvm::Type* type,
				retdec::utils::Address addr = retdec::utils::Address::getUndef,
				bool wideString = false);
		llvm::Constant* getConstant(
				Config* config,
				DebugFormat* dbgf = nullptr,
				retdec::utils::Address addr = retdec::utils::Address::getUndef);

	// Miscellaneous
	//
	public:
		bool isImportTerminating(
				const fileformat::ImportTable* impTbl,
				const fileformat::Import* imp) const;

	// Image getters.
	//
	public:
		retdec::loader::Image* getImage() const;
		auto& getSegments() const { return _image->getSegments(); }

	// FileFormat getters.
	//
	public:
		retdec::fileformat::FileFormat* getFileFormat() const;

	// Other getters.
	//
	public:
		const retdec::rtti_finder::RttiFinder& getRtti() const;

	// Private data.
	//
	private:
		llvm::Module* _module = nullptr;
		std::unique_ptr<retdec::loader::Image> _image;
		retdec::rtti_finder::RttiFinder _rtti;
};

/**
 * Completely static object -- all members and methods are static -> it can be
 * used by anywhere in bin2llvmirl. It provides mapping of modules to file
 * images associated with them.
 *
 * @attention Even though this is accessible anywhere in bin2llvmirl, use it only
 * in LLVM passes' prologs to initialize pass-local file image object. All
 * analyses, utils and other modules *MUST NOT* use it. If they need to work
 * with a file image, they should accept it in parameter.
 */
class FileImageProvider
{
	public:
		static FileImage* addFileImage(
				llvm::Module* m,
				const std::string& path,
				Config* config);
		static FileImage* addFileImage(
				llvm::Module* m,
				const std::shared_ptr<retdec::fileformat::FileFormat>& ff,
				Config* config);

		static FileImage* getFileImage(
				llvm::Module* m);
		static bool getFileImage(
				llvm::Module* m,
				FileImage*& img);

		static void clear();

	private:
		static FileImage* addFileImage(
				llvm::Module* m,
				FileImage img);

	private:
		/// Mapping of modules to file images associated with them.
		static std::map<llvm::Module*, FileImage> _module2image;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
