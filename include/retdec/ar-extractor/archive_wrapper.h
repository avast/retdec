/**
 * @file include/retdec/ar-extractor/archive_wrapper.h
 * @brief Definition of ArchiveWrapper class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_AR_EXTRACTOR_ARCHIVE_WRAPPER_H
#define RETDEC_AR_EXTRACTOR_ARCHIVE_WRAPPER_H

#include <memory>
#include <string>
#include <vector>

#include <llvm/Object/Archive.h>
#include <llvm/Support/Error.h>

#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace ar_extractor {

/**
 * Class for reading archives using llvm::Archive.
 */
class ArchiveWrapper : private retdec::utils::NonCopyable
{
	public:
		ArchiveWrapper(const std::string &archivePath, bool &succes,
			std::string &errorMessage);

		/// @brief Getters.
		/// @{
		std::size_t getNumberOfObjects() const;
		/// @}

		/// @brief Query methods.
		/// @{
		bool isThinArchive() const;
		bool isEmptyArchive() const;
		/// @}

		/// @brief Display methods.
		/// @{
		bool getPlainTextList(std::string &result, std::string &errorMessage,
			bool niceNames = false, bool numbers = true) const;
		bool getJsonList(std::string &result, std::string &errorMessage,
			bool niceNames = false, bool numbers = true) const;
		/// @}

		/// @brief Extraction methods.
		/// @{
		bool extract(std::string &errorMessage,
			const std::string &directory = "") const;
		bool extractByName(const std::string &name, std::string &errorMessage,
			const std::string &outputPath = "") const;
		bool extractByIndex(const std::size_t index, std::string &errorMessage,
			const std::string &outputPath = "") const;
		/// @}

	private:
		/// LLVM archive parser.
		std::unique_ptr<llvm::object::Archive> archive;
		/// Buffer storing content of whole archive.
		llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> buffer;

		/// @brief Auxiliary methods.
		/// @{
		bool getNames(std::vector<std::string> &result,
			std::string &errorMessage) const;
		bool getCount(std::size_t &count, std::string &errorMessage) const;
		/// @}

		std::size_t objectCount = 0; ///< Number of object files in archive.
};

} // namespace ar_extractor
} // namespace retdec

#endif
