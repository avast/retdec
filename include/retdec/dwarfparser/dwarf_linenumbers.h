/**
 * @file include/retdec/dwarfparser/dwarf_linenumbers.h
 * @brief Declaration of classes representing linenumbers.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_DWARFPARSER_DWARF_LINENUMBERS_H
#define RETDEC_DWARFPARSER_DWARF_LINENUMBERS_H

#include <cstdlib>
#include <list>
#include <vector>

#include "retdec/dwarfparser/dwarf_base.h"

namespace retdec {
namespace dwarfparser {

// Extern forward declarations.
class DwarfFile;

// Locale forward declarations.
class DwarfLine;
class DwarfLineContainer;

/**
 * @class DwarfLine
 * @brief Line number object.
 */
class DwarfLine : public DwarfBaseElement
{
	public:
		/**
		 * @brief Flags of line number.
		 */
		enum eFlags
		{
			EMPTY          = 0,      ///< Empty.
			STAT_BEG       = 1 << 1, ///< Line number entry marked as beginning a statment.
			SEQ_END        = 1 << 2, ///< Line number entry marked as ending a text sequence.
			BASE_BLOCK_BEG = 1 << 3, ///< Line number entry marked as beginning a basic block.
			PROLOGUE_END   = 1 << 4, ///< Line number entry marked as end of prologue.
			EPILOGUE_BEGIN = 1 << 5  ///< Line number entry marked as begin of epilogue.
		};

	public:
		DwarfLine(DwarfLineContainer *prnt, const std::string &n);
		virtual void dump() const override;

		virtual const std::string& getName() const override {return name;}
		bool isStatmentBeg() const;
		bool isSequenceEnd() const;
		bool isBasicBlockBeg() const;

	public:
		Dwarf_Unsigned lineNum;  ///< Source statement line number.
		Dwarf_Addr addr;         ///< Address associated with line.
		Dwarf_Unsigned col;      ///< Column number at which statement represented by line begins.
		int flags;               ///< Line number record flags.
		const std::string &name; ///< Name of source file where line occurs.
};

/**
 * @class DwarfLineContainer
 * @brief Line number container.
 */
class DwarfLineContainer : public DwarfBaseContainer<DwarfLine>
{
	public:
		DwarfLineContainer(DwarfFile *file, DwarfBaseElement *elem = nullptr);
		virtual DwarfLine *loadAndGetDie(Dwarf_Die cu_die, unsigned lvl) override;
		virtual void dump() const override;

		std::vector<Dwarf_Addr> getAddrByLine(std::string file, Dwarf_Unsigned line);
		DwarfLine *getLineByAddr(Dwarf_Addr addr);

	private:
		void loadLine(Dwarf_Line line);
		std::string *findSrcFile(std::string f);

	private:
		std::list<std::string> m_srcFiles; ///< List of all source file names used in lines.
};

} // namespace dwarfparser
} // namespace retdec

#endif
