/**
 * @file  include/retdec/fileformat-libdwarf-interface/bin_interface.h
 * @brief Definition of binary interface working with input files.
 *        Based on declarations of interface in libdwarf.h
 *        and definition of ELF interface in dwarf_elf_access.cpp.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef BININT_H_
#define BININT_H_

#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

#include "retdec/fileformat/format_factory.h"
#include "retdec/fileformat/file_format/file_format.h"

/**
 * @class BinInt.
 * @brief This class creates binary interface to access input files.
 */
class BinInt
{
	//
	// Public class methods.
	//
	public:
		/**
		 * @brief Initialize class and dwarf object access method structure.
		 * @param fileName Name of input file to load.
		 * @param fileParser Parser of input file (optional).
		 * @note Function which relocate a section is not used at the moment.
		 */
		BinInt(std::string fileName, retdec::fileformat::FileFormat *fileParser = nullptr) :
			m_fileName(fileName),
			m_fileParser(fileParser),
			m_parserInsteadOfPath(m_fileParser && m_fileParser->isInValidState()),
			m_success(true),
			m_binInt(nullptr),
			dwarf_binint_object_access_methods()
		{
			dwarf_binint_object_access_init();

			struct Dwarf_Obj_Access_Methods_s p = {
				dwarf_binint_object_access_get_section_info,
				dwarf_binint_object_access_get_byte_order,
				dwarf_binint_object_access_get_length_size,
				dwarf_binint_object_access_get_pointer_size,
				dwarf_binint_object_access_get_section_count,
				dwarf_binint_object_access_load_section,
				nullptr  //dwarf_binint_object_relocate_a_section
			};

			dwarf_binint_object_access_methods = p;
		}

		/**
		 * @brief Clean up input file object access interface.
		 */
		~BinInt()
		{
			delete m_binInt;
		}

		/**
		 * @brief Return input file binary interface.
		 * @return Input file binary interface.
		 */
		Dwarf_Obj_Access_Interface *getInt()
		{
			return m_binInt;
		}

		/**
		 * @brief Tells caller if input file file was loaded successfully or not.
		 * @return True if success, false otherwise.
		 */
		bool success()
		{
			return m_success;
		}

	//
	// TODO: maybe relocate this to ctor.
	//
	private:
		/**
		 * @brief Initialize input file binary interface.
		 */
		void dwarf_binint_object_access_init()
		{
			// Open input object file.
			retdec::fileformat::FileFormat *objFile = nullptr;
			if(m_parserInsteadOfPath)
			{
				objFile = m_fileParser;
			}
			else
			{
				m_newParserPtr = retdec::fileformat::createFileFormat(m_fileName);
				if(m_newParserPtr)
				{
					objFile = m_newParserPtr.get();
				}
			}

			// Alloc interface descriptor.
			m_binInt = new Dwarf_Obj_Access_Interface;
			if (!m_binInt || !objFile)
			{
				m_success = false;
				return;
			}

			// Initialize the interface struct.
			m_binInt->object = objFile;
			m_binInt->methods = &dwarf_binint_object_access_methods;
			m_success = objFile->isInValidState();
			return;
		}

	//
	// Access functions as defined in libdwarf.h.
	//
	private:
		/**
		 * @brief Get address, size, and name info about a section.
		 * @param obj_in        Object file structure.
		 * @param section_index Section index.
		 * @param ret_scn       Structure where section info will be placed.
		 * @param error         A pointer to an integer in which an error code may be stored.
		 * @return Return code.
		 */
		static int dwarf_binint_object_access_get_section_info(
				void* obj_in,
				Dwarf_Half section_index,
				Dwarf_Obj_Access_Section* ret_scn,
				int* error)
		{
			auto *obj = static_cast<retdec::fileformat::FileFormat*>(obj_in);

			const auto *sec = obj->getSection(section_index);
			if (!sec)
			{
				*error = DW_DLE_MDE;
				return DW_DLV_ERROR;
			}

			ret_scn->size = sec->getSizeInFile();
			ret_scn->addr = sec->getAddress();
			ret_scn->name = sec->getNameAsCStr();
			ret_scn->link = 0;  // TODO: meaningless?

			return DW_DLV_OK;
		}

		/**
		 * @brief Find out if file is big-endian or little endian.
		 * @param obj_in Object file structure.
		 * @return Endianness of object.
		 */
		static Dwarf_Endianness dwarf_binint_object_access_get_byte_order(
				void* obj_in)
		{
			auto *obj = static_cast<retdec::fileformat::FileFormat*>(obj_in);

			if (obj->isLittleEndian())
			{
				return DW_OBJECT_LSB;
			}
			else if (obj->isBigEndian())
			{
				return DW_OBJECT_MSB;
			}
			else
			{
				// This may happen in input file (undefined) but there is no
				// dwarflib option for it.
				return DW_OBJECT_LSB;
			}
		}

		/**
		 * @brief Get the size of a length field in the underlying object file.
		 * @param obj_in Object file structure.
		 * @return Size of length.
		 *
		 * TODO: what is length size??? is it same as word length???
		 */
		static Dwarf_Small dwarf_binint_object_access_get_length_size(
				void* obj_in)
		{
			auto *obj = static_cast<retdec::fileformat::FileFormat*>(obj_in);
			return static_cast<Dwarf_Small>(obj->getBytesPerWord());
		}

		/**
		 * @brief Get the size of a pointer field in the underlying object file.
		 * @param obj_in Object file structure.
		 * @return Size of pointer.
		 */
		static Dwarf_Small dwarf_binint_object_access_get_pointer_size(
				void* obj_in)
		{
			auto *obj = static_cast<retdec::fileformat::FileFormat*>(obj_in);
			return static_cast<Dwarf_Small>(obj->getBytesPerWord());
		}

		/**
		 * @brief Get the number of sections in the object file.
		 * @param obj_in Object file structure.
		 * @return Number of sections.
		 */
		static Dwarf_Unsigned dwarf_binint_object_access_get_section_count(
				void * obj_in)
		{
			auto *obj = static_cast<retdec::fileformat::FileFormat*>(obj_in);
			return obj->getNumberOfSections();
		}

		/**
		 * @brief Get a pointer to an array of bytes that represent the section.
		 * @param obj_in        Object file structure.
		 * @param section_index Index of section which data to get.
		 * @param section_data  The address of a pointer where sec data will be placed.
		 * @param error         Pointer to integer for returning libdwarf-defined error numbers.
		 * @return Return code.
		 */
		static int dwarf_binint_object_access_load_section(
				void* obj_in,
				Dwarf_Half section_index,
				Dwarf_Small** section_data,
				int* error)
		{
			std::map<Dwarf_Half, std::vector<unsigned char>>::iterator fIt = BinInt::secBytes().find(section_index);
			if (fIt != BinInt::secBytes().end())
			{
				*section_data = fIt->second.data();
				return DW_DLV_OK;
			}
			else
			{
				auto *obj = static_cast<retdec::fileformat::FileFormat*>(obj_in);
				if (!obj || !section_data)
				{
					*error = DW_DLE_MDE;
					return DW_DLV_ERROR;
				}

				const auto *fSec = obj->getSection(section_index);
				std::vector<unsigned char> bytes;
				if (!fSec || !fSec->getBytes(bytes))
				{
					*error = DW_DLE_MDE;
					return DW_DLV_ERROR;
				}

				BinInt::secBytes()[section_index] = bytes;

				*section_data = BinInt::secBytes()[section_index].data();

				if (*section_data == NULL)
				{
					*error = DW_DLE_MDE;
					return DW_DLV_ERROR;
				}

				return DW_DLV_OK;
			}
		}

		/**
		 * @brief Relocate a section.
		 * @param obj_in        Object file structure.
		 * @param section_index Index of section to relocate.
		 * @param dbg           Libdwarf representation of file.
		 * @param error         Pointer to integer for returning libdwarf-defined error numbers.
		 * @return Return code.
		 */
		static int dwarf_binint_object_relocate_a_section(
				void* obj_in,
				Dwarf_Half section_index,
				Dwarf_Debug dbg,
				int* error)
		{
			return DW_DLV_OK;
		}

	//
	// When this module had both header and source file, we declared static variable
	// secBytes here in header and defined it in source.
	// However, it is easier to use this module when it is header only.
	// The problem is that static member variables can not be defined in header files.
	// Therefore, we hack it by using static member getter method which contains
	// static local variable in its body.
	//
	// Matula: I have no idea why there is (must be?) a static member variable in the
	// first place, but it seems to work, so be it.
	//
	private:
		static std::map<Dwarf_Half, std::vector<unsigned char>>& secBytes()
		{
			static std::map<Dwarf_Half, std::vector<unsigned char>> secBytes;
			return secBytes;
		}

	//
	// Class data.
	//
	private:
		std::string m_fileName;
		std::unique_ptr<retdec::fileformat::FileFormat> m_newParserPtr;
		retdec::fileformat::FileFormat *m_fileParser;
		bool m_parserInsteadOfPath;
		bool m_success;
		Dwarf_Obj_Access_Interface *m_binInt;
		struct Dwarf_Obj_Access_Methods_s dwarf_binint_object_access_methods;
};

#endif
