/**
 * @file src/dwarfparser/dwarf_cu.cpp
 * @brief Implementaion of classes representing Compilation Units.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

#include "retdec/dwarfparser/dwarf_cu.h"
#include "retdec/dwarfparser/dwarf_file.h"

using namespace std;

namespace retdec {
namespace dwarfparser {

/**
 * @brief ctor.
 * @param file Pointer to dwarfparser representation of DWARF file which owns this container.
 * @param elem Pointer to parent element that owns this container.
 */
DwarfCUContainer::DwarfCUContainer(DwarfFile *file, DwarfBaseElement *elem) :
		DwarfBaseContainer<DwarfCU>(file, elem)
{

}

/**
 * @brief Get all data from compilation unit DIE.
 * @param cuDie Compilation unit DIE.
 * @param lvl   Level (depth) of this die.
 * @return Pointer to newly created CU object or nullptr if failed.
 */
DwarfCU *DwarfCUContainer::loadAndGetDie(Dwarf_Die cuDie, unsigned)
{
	// Get source files.
	char **srcFiles;
	Dwarf_Signed fileCnt;
	m_res = dwarf_srcfiles(cuDie, &srcFiles, &fileCnt, &m_error);

	if (m_res == DW_DLV_ERROR)
	{
		DWARF_WARNING("dwarf_srcfiles() in loadDie() failed.\n"
		            "Libdwarf error: " << getDwarfError(m_error));
	}

	AttrProcessor ap(m_parentFile->m_dbg, cuDie, m_parentFile);

	DwarfCU *newCU = new DwarfCU(this, ap.getDieOff());

	// Copy source files to new CU.
	if (m_res == DW_DLV_OK)
	{
		for (int i=0; i<fileCnt; i++)
		{
			newCU->addSrcFile(srcFiles[i]);
			dwarf_dealloc(m_parentFile->m_dbg, srcFiles[i], DW_DLA_STRING);
		}

		dwarf_dealloc(m_parentFile->m_dbg, srcFiles, DW_DLA_LIST);
	}

	// Use special class to get attributes that we want.
	ap.get(DW_AT_comp_dir, newCU->compDir);
	ap.get(DW_AT_name, newCU->name);
	ap.get(DW_AT_producer, newCU->producer);
	ap.get(DW_AT_low_pc, newCU->lowAddr);
	ap.get(DW_AT_high_pc, newCU->highAddr);
	ap.get(DW_AT_language, newCU->language);

	// Add new CU to container and set as active.
	m_data.push_back(newCU);
	m_parentFile->m_activeCU = newCU;

	return newCU;
}

/**
 * @brief Print contents of this container.
 */
void DwarfCUContainer::dump() const
{
	cout << endl;
	cout << "==================== CUs ====================" << endl;

	DwarfBaseContainer<DwarfCU>::dump();

	cout << endl;
}

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfCU::DwarfCU(DwarfCUContainer *prnt, Dwarf_Off o) :
		DwarfBaseElement(DwarfBaseElement::CU, reinterpret_cast<DwarfBaseContainer<DwarfBaseElement>*>(prnt), o),
		lowAddr(0),
		highAddr(0),
		language(0)
{

}

/**
 * @brief Get number of source file of this compilation unit.
 * @return Number of source files.
 */
std::size_t DwarfCU::srcFilesCount()
{
	return m_srcFiles.size();
}

/**
 * @brief Add source file to compilation unit.
 * @param f Name of source file.
 */
void DwarfCU::addSrcFile(string f)
{
	m_srcFiles.push_back(f);
}

/**
 * @brief Get source file by its index.
 * @param idx Index of source file to get.
 * @return Pointer to source file name or nullptr if index out of range.
 */
string *DwarfCU::getSrcFile(unsigned idx)
{
	if (idx < srcFilesCount())
	{
		list<string>::iterator srcFileIt = m_srcFiles.begin();
		advance(srcFileIt, idx);
		return &(*srcFileIt);
	}
	else
	{
		DWARF_ERROR("getSrcFile(idx): index out of range.");
		return nullptr;
	}
}

/**
 * @brief This method finds record in list of source files with
 *        the same name as parameter and returns pointer to it.
 * @param f   Name of source file to find.
 * @param ret Address of pointer where result will be saved.
 * @return DW_DLV_OK if record was found, DW_DLV_NO_ENTRY if not.
 */
int DwarfCU::findSrcFile(string f, const string **ret)
{
	list<string>::const_iterator srcFileIt = m_srcFiles.begin();
	while (srcFileIt != m_srcFiles.end())
	{
		if (*srcFileIt == f)
		{
			*ret = &(*srcFileIt);
			return DW_DLV_OK;
		}

		++srcFileIt;
	}

	// If it gets here, no record was found.
	return DW_DLV_NO_ENTRY;
}

bool DwarfCU::IsLanguageC() const
{
	return
		language == DW_LANG_C89 ||
		language == DW_LANG_C ||
		language == DW_LANG_C99;
}

bool DwarfCU::IsLanguageCpp() const
{
	return
		language == DW_LANG_C_plus_plus;
}

/**
 * @brief Print contents of this class.
 */
void DwarfCU::dump() const
{
	cout << "CU        :  " << name << endl;
	cout << "CU DIR    :  " << compDir << endl;
	cout << "CU lowpc  :  " << hex << lowAddr << endl;
	cout << "CU highpc :  " << hex << highAddr << endl;

	list<string>::const_iterator srcFileIt = m_srcFiles.begin();
	while (srcFileIt != m_srcFiles.end())
	{
		cout << "\t" << *(srcFileIt) << endl;
		++srcFileIt;
	}

	cout << endl;
}

} // namespace dwarfparser
} // namespace retdec
