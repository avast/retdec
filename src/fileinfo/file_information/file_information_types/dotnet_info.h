/**
 * @file src/fileinfo/file_information/file_information_types/dotnet_info.h
 * @brief Information about .NET.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_DOTNET_INFO_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_DOTNET_INFO_H

#include <memory>
#include <string>
#include <vector>

#include "retdec/fileformat/types/dotnet_types/dotnet_class.h"

namespace fileinfo {

struct StreamInfo
{
	std::uint64_t offset;
	std::uint64_t size;
};

/**
 * Class for information about .NET
 */
class DotnetInfo
{
	private:
		bool used;
		std::string runtimeVersion;
		std::uint64_t metadataHeaderAddress;
		StreamInfo metadataStream;
		StreamInfo stringStream;
		StreamInfo blobStream;
		StreamInfo guidStream;
		StreamInfo userStringStream;
		std::string moduleVersionId;
		std::string typeLibId;
		std::vector<std::shared_ptr<retdec::fileformat::DotnetClass>> definedClassList;
		std::vector<std::shared_ptr<retdec::fileformat::DotnetClass>> importedClassList;
	public:
		DotnetInfo();

		/// @name Getters
		/// @{
		const std::string& getRuntimeVersion() const;
		std::string getMetadataHeaderAddressStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getMetadataStreamOffsetStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getMetadataStreamSizeStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getStringStreamOffsetStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getStringStreamSizeStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getBlobStreamOffsetStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getBlobStreamSizeStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getGuidStreamOffsetStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getGuidStreamSizeStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getUserStringStreamOffsetStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getUserStringStreamSizeStr(std::ios_base &(* format)(std::ios_base &)) const;
		const std::string& getModuleVersionId() const;
		const std::string& getTypeLibId() const;
		const std::vector<std::shared_ptr<retdec::fileformat::DotnetClass>>& getDefinedClassList() const;
		const std::vector<std::shared_ptr<retdec::fileformat::DotnetClass>>& getImportedClassList() const;
		/// @}

		/// @name Setters
		/// @{
		void setUsed(bool set);
		void setRuntimeVersion(std::uint64_t majorVersion, std::uint64_t minorVersion);
		void setMetadataHeaderAddress(std::uint64_t address);
		void setMetadataStreamInfo(std::uint64_t offset, std::uint64_t size);
		void setStringStreamInfo(std::uint64_t offset, std::uint64_t size);
		void setBlobStreamInfo(std::uint64_t offset, std::uint64_t size);
		void setGuidStreamInfo(std::uint64_t offset, std::uint64_t size);
		void setUserStringStreamInfo(std::uint64_t offset, std::uint64_t size);
		void setModuleVersionId(const std::string& id);
		void setTypeLibId(const std::string& id);
		void setDefinedClassList(const std::vector<std::shared_ptr<retdec::fileformat::DotnetClass>>& dotnetClassList);
		void setImportedClassList(const std::vector<std::shared_ptr<retdec::fileformat::DotnetClass>>& dotnetClassList);
		/// @}

		/// @name Detection
		/// @{
		bool isUsed() const;
		bool hasMetadataStream() const;
		bool hasStringStream() const;
		bool hasBlobStream() const;
		bool hasGuidStream() const;
		bool hasUserStringStream() const;
		bool hasTypeLibId() const;
		/// @}
};

} // namespace fileinfo

#endif
