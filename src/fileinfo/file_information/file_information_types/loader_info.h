/**
 * @file src/fileinfo/file_information/file_information_types/loader_info.h
 * @brief Class for loader info.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_LOADER_INFO_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_LOADER_INFO_H

#include <string>
#include <vector>

namespace fileinfo {

class LoadedSegment
{
	private:
		unsigned long long _index;
		std::string _name;
		unsigned long long _address;
		unsigned long long _size;
	public:
		LoadedSegment(unsigned long long index, std::string name, unsigned long long address, unsigned long long size);
		LoadedSegment(const LoadedSegment&);
		LoadedSegment(LoadedSegment&&);
		~LoadedSegment();

		std::string getIndexStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getName() const;
		std::string getAddressStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getSizeStr(std::ios_base &(* format)(std::ios_base &)) const;
};

class LoaderInfo
{
	private:
		unsigned long long _baseAddress;
		std::vector<LoadedSegment> _loadedSegments;
		std::string _statusMessage;
		retdec::fileformat::LoaderErrorInfo _ldrErrInfo;

	public:
		LoaderInfo();
		~LoaderInfo();

		/// @name Getters
		/// @{
		std::string getBaseAddressStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getNumberOfLoadedSegmentsStr(std::ios_base &(* format)(std::ios_base &)) const;
		unsigned long long getNumberOfLoadedSegments() const;
		const LoadedSegment& getLoadedSegment(unsigned long long index) const;
		const std::string& getStatusMessage() const;
		const retdec::fileformat::LoaderErrorInfo & getLoaderErrorInfo() const;
		/// @}

		/// @name Setters
		/// @{
		void setBaseAddress(unsigned long long baseAddress);
		void setStatusMessage(const std::string& statusMessage);
		void setLoaderErrorInfo(const retdec::fileformat::LoaderErrorInfo & ldrErrInfo);
		/// @}

		/// @name Other methods
		/// @{
		void addLoadedSegment(const LoadedSegment& segment);
		/// @}
};

} // namespace fileinfo

#endif
