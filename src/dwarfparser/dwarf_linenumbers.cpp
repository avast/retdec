/**
 * @file src/dwarfparser/dwarf_linenumbers.cpp
 * @brief Implementation of classes representing linenumbers.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>
#include <iostream>
#include <sstream>

#include "retdec/dwarfparser/dwarf_file.h"
#include "retdec/dwarfparser/dwarf_linenumbers.h"

using namespace std;

namespace retdec {
namespace dwarfparser {

/**
 * @brief ctor.
 * @param file Pointer to dwarfparser representation of DWARF file which owns this container.
 * @param elem Pointer to parent element that owns this container.
 */
DwarfLineContainer::DwarfLineContainer(DwarfFile *file, DwarfBaseElement *elem) :
		DwarfBaseContainer<DwarfLine>(file, elem)
{
	m_srcFiles.push_back(EMPTY_STR);
}

/**
 * @brief Get line number information from compilation unit DIE.
 * @param cu_die Compilation unit DIE.
 * @param lvl    Level (depth) of this die.
 * @return Loaded line element pointer or nullptr if some problem.
 */
DwarfLine *DwarfLineContainer::loadAndGetDie(Dwarf_Die cu_die, unsigned)
{
	// Get all lines to buffer.
	Dwarf_Signed lineCnt = 0;
	Dwarf_Line *lineBuf = nullptr;

	m_res = dwarf_srclines(cu_die, &lineBuf, &lineCnt, &m_error);

	if (m_res == DW_DLV_NO_ENTRY)
	{
		return nullptr;
	}
	else if (m_res != DW_DLV_OK)
	{
		DWARF_ERROR(getDwarfError(m_error));
		return nullptr;
	}

	// Iterate through lines and load each one of them.
	for (int i=0; i<lineCnt; i++)
	{
		loadLine(lineBuf[i]);
	}

	dwarf_srclines_dealloc(m_parentFile->m_dbg, lineBuf, lineCnt);
	return nullptr;
}

/**
 * @brief Process one line number record.
 * @param line Line to process.
 */
void DwarfLineContainer::loadLine(Dwarf_Line line)
{
	// Address associated with line.
	Dwarf_Addr addr = 0;
	m_res = dwarf_lineaddr(line, &addr, &m_error);

	if (m_res == DW_DLV_ERROR)
	{
		DWARF_ERROR(getDwarfError(m_error));
		return;
	}
	if (m_res == DW_DLV_NO_ENTRY)
	{
		addr = EMPTY_ADDR;
	}

	// Source statement line number.
	Dwarf_Unsigned lineno;
	m_res = dwarf_lineno(line, &lineno, &m_error);

	if (m_res == DW_DLV_ERROR)
	{
		DWARF_ERROR(getDwarfError(m_error));
		return;
	}
	if (m_res == DW_DLV_NO_ENTRY)
	{
		lineno = EMPTY_UNSIGNED;
	}

	// Column number at which statement represented by line begins.
	Dwarf_Unsigned column;
	m_res = dwarf_lineoff_b(line, &column, &m_error);

	if (m_res == DW_DLV_ERROR)
	{
		DWARF_ERROR(getDwarfError(m_error));
		return;
	}
	if (m_res == DW_DLV_NO_ENTRY)
	{
		column = EMPTY_UNSIGNED;
	}

	// Name of src file where line occurs.
	char *s = nullptr;
	string f;
	m_res = dwarf_linesrc(line, &s, &m_error);

	if (m_res == DW_DLV_ERROR)
	{
		DWARF_ERROR(getDwarfError(m_error));
		return;
	}

	if (m_res == DW_DLV_NO_ENTRY || s==nullptr)
		f = EMPTY_STR;
	else
		f = s;

	dwarf_dealloc(m_parentFile->m_dbg, s, DW_DLA_STRING);

	// Is line marked as beginning of the statement?
	Dwarf_Bool statBeg;
	m_res = dwarf_linebeginstatement(line, &statBeg, &m_error);

	if (m_res != DW_DLV_OK)
	{
		DWARF_ERROR(getDwarfError(m_error));
		return;
	}

	// Is line marked as ending a text sequence?
	Dwarf_Bool seqEnd;
	m_res = dwarf_lineendsequence(line, &seqEnd, &m_error);

	if (m_res != DW_DLV_OK)
	{
		DWARF_ERROR(getDwarfError(m_error));
		return;
	}

	// Is line marked as not beginning basic block?
	Dwarf_Bool basicBlockBeg;
	m_res = dwarf_lineblock(line, &basicBlockBeg, &m_error);

	if (m_res != DW_DLV_OK)
	{
		DWARF_ERROR(getDwarfError(m_error));
		return;
	}

	Dwarf_Bool prologueEnd, epilogueBegin;
	Dwarf_Unsigned isa, discriminator;
	m_res = dwarf_prologue_end_etc(line, &prologueEnd, &epilogueBegin,
		&isa, &discriminator, &m_error);

	if (m_res != DW_DLV_OK)
	{
		DWARF_ERROR(getDwarfError(m_error));
		return;
	}

	// Create line record.
	DwarfLine *l = new DwarfLine(this, *findSrcFile(f));

	l->lineNum = lineno;
	l->addr = addr;
	l->col = column;

	if (statBeg) l->flags += DwarfLine::STAT_BEG;
	if (seqEnd) l->flags += DwarfLine::SEQ_END;
	if (basicBlockBeg) l->flags += DwarfLine::BASE_BLOCK_BEG;
	if (prologueEnd) l->flags += DwarfLine::PROLOGUE_END;
	if (epilogueBegin) l->flags += DwarfLine::EPILOGUE_BEGIN;

	m_data.push_back(l);
}

/**
 * @brief Find source file name and return pointer to it.
 *        If specified name is not in list yet, add it.
 * @param f Source file name to find.
 * @return Pointer to file name in list.
 */
string *DwarfLineContainer::findSrcFile(string f)
{
	list<string>::iterator srcFilesIter = m_srcFiles.begin();
	while (srcFilesIter != m_srcFiles.end())
	{
		if (*srcFilesIter == f)
		{
			return &(*srcFilesIter);
		}

		++srcFilesIter;
	}

	// If it gets here, no record was found.
	m_srcFiles.push_back(f);
	return &(m_srcFiles.back());
}

/**
 * @brief Gets all addresses associated with particular line.
 * @param file Name of source file where line occurs.
 * @param line Source statement line number.
 * @return Vector of addresses.
 */
vector <Dwarf_Addr> DwarfLineContainer::getAddrByLine(string file, Dwarf_Unsigned line)
{
	vector <Dwarf_Addr> ret;

	for (iterator it=begin(); it!=end(); ++it)
	{
		if (((*it)->name == file) &&
			((*it)->lineNum == line))
		{
			ret.push_back((*it)->addr);
		}
	}

	return ret;
}

/**
 * @brief Gets line associated with particular addresses.
 * @return Dwarfparser representation of line.
 */
DwarfLine *DwarfLineContainer::getLineByAddr(Dwarf_Addr addr)
{
	for (iterator it=begin(); it!=end(); ++it)
	{
		if ((*it)->addr == addr)
			return (*it);
	}

	return nullptr;
}

/**
 * @brief Prints content of line number container.
 * @note Debugging purposes.
 */
void DwarfLineContainer::dump() const
{
	cout << endl;
	cout << "==================== Lines ====================" << endl;

	// Is empty?
	if (m_data.empty())
	{
		cout << "NO line number information." << endl;
		return;
	}

	// Header.
	cout << setw(10) << right << "Line num";
	cout << setw(12) << right << "Address";
	cout << setw(10) << right << "Column";
	cout << setw(8) << right << "Marks";
	cout << "   " << "Filename" << endl;

	// Lines.
	DwarfBaseContainer<DwarfLine>::dump();

	// Explanation of marks meaning.
	cout << endl << "Marks meaning:" << endl;
	cout << "\tB - Line is marked as beginning of the statement." << endl;
	cout << "\tE - Line is marked as ending a text sequence." << endl;
	cout << "\tK - Line is marked as not beginning basic block." << endl;
	cout << endl;
}

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param n    Reference to bame of source file where line occurs.
 * @note There is no DIE offset for lines, this value is set to zero.
 */
DwarfLine::DwarfLine(DwarfLineContainer *prnt, const string &n) :
	DwarfBaseElement(DwarfBaseElement::LINE, reinterpret_cast<DwarfBaseContainer<DwarfBaseElement>*>(prnt), 0),
	lineNum(0),
	addr(0),
	col(0),
	flags(EMPTY),
	name(n)
{

}

/**
 * @brief Print contents of this class.
 */
void DwarfLine::dump() const
{
	string marks = "   ";
	if (isStatmentBeg())
		marks[0] = 'B';
	if (isSequenceEnd())
		marks[1] = 'E';
	if (isBasicBlockBeg())
		marks[2] = 'K';

	cout << setw(10) << right << dec << lineNum;
	cout << setw(12) << right << hex << addr;
	cout << setw(10) << right << dec << col;
	cout << setw(8) << right << marks;
	cout << "   " << name << endl;
}

/**
 * @brief Test if line is beginning a statment.
 * @return True if line is beginning a statment, false otherwise.
 */
bool DwarfLine::isStatmentBeg() const
{
	return (flags & STAT_BEG);
}

/**
 * @brief Test if line is ending a text sequence.
 * @return True if line is ending a text sequence, false otherwise.
 */
bool DwarfLine::isSequenceEnd() const
{
	return (flags & SEQ_END);
}

/**
 * @brief Test if line is beginning a basic block.
 * @return True if line is beginning a basic block, false otherwise.
 */
bool DwarfLine::isBasicBlockBeg() const
{
	return (flags & BASE_BLOCK_BEG); // TODO - reverse ?
}

} // namespace dwarfparser
} // namespace retdec
