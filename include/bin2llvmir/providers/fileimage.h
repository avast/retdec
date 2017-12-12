/**
 * @file include/bin2llvmir/providers/fileimage.h
 * @brief File image provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef BIN2LLVMIR_PROVIDERS_FILEIMAGE_H
#define BIN2LLVMIR_PROVIDERS_FILEIMAGE_H

#include <llvm/IR/Constants.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>

#include "tl-cpputils/address.h"
#include "bin2llvmir/providers/config.h"
#include "bin2llvmir/providers/debugformat.h"
#include "loader/loader/image.h"

namespace bin2llvmir {

class DebugFormat;

class FileImage
{
	public:
		FileImage(
				llvm::Module* m,
				const std::string& path,
				Config* config);
		FileImage(
				llvm::Module* m,
				const std::shared_ptr<fileformat::FileFormat>& ff,
				Config* config);
		FileImage(
				llvm::Module* m,
				std::unique_ptr<loader::Image> img,
				Config* config);

		bool isOk() const;

		loader::Image* getImage();
		fileformat::FileFormat* getFileFormat();

	public:
		llvm::ConstantInt* getConstantInt(
				llvm::IntegerType* t,
				tl_cpputils::Address addr);
		llvm::ConstantInt* getConstantDefault(tl_cpputils::Address addr);
		llvm::Constant* getConstantHalf(tl_cpputils::Address addr);
		llvm::Constant* getConstantFloat(tl_cpputils::Address addr);
		llvm::Constant* getConstantDouble(tl_cpputils::Address addr);
		llvm::Constant* getConstantLongDouble(tl_cpputils::Address addr);
		llvm::Constant* getConstantCharPointer(tl_cpputils::Address addr);
		llvm::Constant* getConstantCharArrayNice(tl_cpputils::Address addr);
		llvm::Constant* getConstantPointer(
				llvm::PointerType* type,
				tl_cpputils::Address addr);
		llvm::Constant* getConstantStruct(
				llvm::StructType* type,
				tl_cpputils::Address addr);
		llvm::Constant* getConstantArray(
				llvm::ArrayType* type,
				tl_cpputils::Address addr);
		llvm::Constant* getConstant(
				llvm::Type* type,
				tl_cpputils::Address addr = tl_cpputils::Address::getUndef,
				bool wideString = false);
		llvm::Constant* getConstant(
				Config* config,
				DebugFormat* dbgf = nullptr,
				tl_cpputils::Address addr = tl_cpputils::Address::getUndef);

	public:
		const fileformat::Symbol* getPreferredSymbol(
				tl_cpputils::Address addr);

	public:
		auto& getSegments() const { return _image->getSegments(); }

	private:
		llvm::Module* _module = nullptr;
		std::unique_ptr<loader::Image> _image;
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
				const std::shared_ptr<fileformat::FileFormat>& ff,
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

#endif
