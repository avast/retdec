/**
 * @file include/retdec/fileformat/types/pdb_info/pdb_info.h
 * @brief Class for information about PDB debug file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_PDB_INFO_PDB_INFO_H
#define RETDEC_FILEFORMAT_TYPES_PDB_INFO_PDB_INFO_H

#include <string>

namespace retdec {
namespace fileformat {

/**
 * Information about PDB file
 */
class PdbInfo
{
	private:
		std::string type;      ///< type of PDB file
		std::string path;      ///< original path to PDB debug file
		std::string guid;      ///< GUID of PDB file
		std::size_t age;       ///< age of PDB file
		std::size_t timeStamp; ///< time and date that PDB file was created
	public:
		PdbInfo();
		~PdbInfo();

		/// @name Getters
		/// @{
		std::string getType() const;
		std::string getPath() const;
		std::string getGuid() const;
		std::size_t getAge() const;
		std::size_t getTimeStamp() const;
		/// @}

		/// @name Setters
		/// @{
		void setType(std::string sType);
		void setPath(std::string sPath);
		void setGuid(std::string sGuid);
		void setAge(std::size_t sAge);
		void setTimeStamp(std::size_t sTimeStamp);
		/// @}

		/// @name Other methods
		/// @{
		void dump(std::string &dumpInfo) const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
