/**
 * @file src/patterngen/pattern_extractor/pattern_extractor.cpp
 * @brief Binary pattern extractor.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/patterngen/pattern_extractor/pattern_extractor.h"
#include "retdec/fileformat/file_format/elf/elf_format.h"
#include "retdec/fileformat/file_format/macho/macho_format.h"
#include "retdec/fileformat/file_format/file_format.h"
#include "retdec/fileformat/format_factory.h"
#include "retdec/fileformat/types/symbol_table/elf_symbol.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

constexpr LoadFlags loadFlags =
	static_cast<LoadFlags>(NO_FILE_HASHES | NO_VERBOSE_HASHES);

namespace
{

/**
 * Check if symbol is PIC32 label.
 *
 * @param symbol input symbol
 *
 * @return @c true if symbol is PIC32 label, @c false otherwise
 */
bool isPic32Label(
	const ElfSymbol* symbol)
{
	// Size must be invalid (returns false) or zero.
	unsigned long long symbolSize = 0;
	if (symbol->getSize(symbolSize) && symbolSize != 0) {
		return false;
	}

	// Must be global data object with name.
	return symbol->isObject() && !symbol->hasEmptyName()
		&& symbol->getElfBind() == STB_GLOBAL;
}

}

namespace retdec {
namespace patterngen {

/**
 * Check if input is strange PIC32 object with DATA OBJECT functions.
 *
 * @return @c true if object has no common functions, @c false otherwise
 */
bool PatternExtractor::isPic32DataObjectOnlyFile()
{
	// PIC32 is 32-bit MIPS.
	if (!inputFile->isMips() || inputFile->getBytesPerWord() != 4) {
		return false;
	}

	// Get first (only) symbol table.
	const auto* symbolTable = inputFile->getSymbolTable(0);
	if (!symbolTable) {
		return false;
	}

	// Check for functions.
	for (std::size_t i = 0; i < symbolTable->getNumberOfSymbols(); ++i) {
		if (symbolTable->getSymbol(i)->isFunction()) {
			// Function found - not data object only.
			return false;
		}
	}

	return true;
}

/**
 * Process PIC32 DATA OBJECT only file.
 */
void PatternExtractor::processPic32DataObjectOnly()
{
	// Get first (only) symbol table.
	const auto* symTab = inputFile->getSymbolTable(0);
	if (!symTab) {
		return;
	}

	// Get the code section.
	const auto* codeSec = inputFile->getSection(".text");
	if (!codeSec) {
		return;
	}

	// Collect symbols that are labels.
	std::vector<const Symbol*> functionLabels;
	for (std::size_t i = 0, e = symTab->getNumberOfSymbols(); i < e; ++i) {
		auto *symbol = static_cast<const ElfSymbol*>(symTab->getSymbol(i));

		unsigned long long link = 0;
		if (symbol->getLinkToSection(link) && link == codeSec->getIndex()) {
			if (isPic32Label(symbol)) {
				functionLabels.push_back(symbol);
			}
		}
	}

	// Filter symbols on same address.
	auto newEnd = std::unique(functionLabels.begin(), functionLabels.end(),
		[](auto* f, auto* o) {
			unsigned long long fAddress = 0;
			f->getAddress(fAddress);
			unsigned long long oAddress = 0;
			o->getAddress(oAddress);
			return fAddress == oAddress;
		});
	functionLabels.erase(newEnd, functionLabels.end());

	std::sort(functionLabels.begin(), functionLabels.end(),
		[](auto* f, auto* o) {
			unsigned long long fAddress = 0;
			f->getAddress(fAddress);
			unsigned long long oAddress = 0;
			o->getAddress(oAddress);
			return fAddress < oAddress;
		});

	// Add patterns.
	addSectionPatterns(codeSec, functionLabels);
}

/**
 * Process loaded file.
 */
bool PatternExtractor::processFile()
{
	if (!inputFile) {
		errorMessage = "not supported file format or damaged input file";
		return false;
	}

	if (auto* macho = dynamic_cast<MachOFormat*>(inputFile.get())) {
		if (macho->isFatBinary()) {
			errorMessage = "fat Mach-O binary - use retdec-macho-extractor";
			return false;
		}
	}

	if (!inputFile->isObjectFile()) {
		errorMessage = "not relocatable file";
		return false;
	}

	if (!inputFile->getNumberOfSymbolTables()) {
		errorMessage = "no symbol tables";
		return false;
	}

	for (const auto &unknownReloc : inputFile->getUnknownRelocations()) {
		warnings.push_back(
			"unknown relocation code " + std::to_string(unknownReloc));
	}

	if (inputFile->isCoff() || inputFile->isMacho()) {
		// COFF and Mach-O files are processed by sections.
		for (const auto *section : inputFile->getSections()) {
			processSection(section);
		}
	}
	else if (inputFile->isElf()) {
		if (inputFile->isPowerPc() && inputFile->getBytesPerWord() == 8) {
			if (!checkPPC64Sections()) {
				errorMessage = "multiple code sections with .opd section";
				return false;
			}
		}
		if (isPic32DataObjectOnlyFile()) {
			processPic32DataObjectOnly();
			return true;
		}

		// ELF files are processed by symbols.
		for (const auto* func : filterSymbols()) {
			processSymbol(func);
		}

	}
	else {
		// Should not happen unless new format that can be objet file is added.
		errorMessage = "unsupported file format";
		return false;
	}

	return true;
}

/**
 * Check if we can use this 64-bit PowerPC file.
 *
 * Problem is there is only one '.opd' section common for all code sections.
 * This is problem if multiple code sections are present because we do not know
 * to which section symbol belongs so we have to work with only standard '.text'
 * section and ignore files with multiple code sections.
 *
 * @return @c true if file can be processed, @c false otherwise
 */
bool PatternExtractor::checkPPC64Sections()
{
	// Check if there is a '.opd' section and multiple code sections.
	if (inputFile->getSection(".opd")) {
		std::size_t counter = 0;
		for (const Section *section : inputFile->getSections()) {
			if (section->isCode()) {
				counter++;
			}
		}

		// There can be only one code section if '.opd' is used.
		return counter == 1;
	}

	// No '.opd' section.
	return true;
}

/**
 * Filter symbols so that only first symbol for given address is used.
 *
 * @return vector with filtered symbols
 */
std::vector<const Symbol*> PatternExtractor::filterSymbols()
{
	// Create map with function symbols divided by their sections.
	std::map<unsigned, std::vector<const Symbol*>> functionSymbols;
	for (const auto *symTab : inputFile->getSymbolTables()) {
		for (std::size_t i = 0; i < symTab->getNumberOfSymbols(); ++i) {
			const Symbol* sym = symTab->getSymbol(i);
			if (!sym || !sym->isFunction() || sym->hasEmptyName()) {
				// Ignore symbols that are not functions or lack a name.
				continue;
			}

			unsigned long long sectionLink;
			if(!sym->getLinkToSection(sectionLink)) {
				continue;
			}

			functionSymbols[sectionLink].push_back(sym);
		}
	}

	// There are often multiple symbols pointing to single function.
	std::vector<const Symbol*> toProcess;
	for (const auto &item : functionSymbols) {
		const auto &functions = item.second;

		// Check if there are multiple symbols or not.
		if (functions.size() == 1) {
			toProcess.push_back(functions.front());
			continue;
		}

		// Pick first function and get its address.
		unsigned long long firstAddress;
		const Symbol* first = functions.front();
		if (!first->getAddress(firstAddress)) {
			continue;
		}

		// Iterate over other symbols for this section.
		for (const auto* tmp : functions) {
			unsigned long long tmpAddress;
			if (!tmp->getAddress(tmpAddress)) {
				continue;
			}

			if (tmpAddress == firstAddress) {
				// Same address - we will use first symbol.
				continue;
			}
			else {
				// Different function found.
				toProcess.push_back(first);
				firstAddress = tmpAddress;
				first = tmp;
			}
		}

		// Push last shortest function.
		toProcess.push_back(first);
	}

	return toProcess;
}

/**
 * Process single symbol.
 *
 * @param symbol pointer to symbol to process
 */
void PatternExtractor::processSymbol(const Symbol *symbol)
{
	// Get symbol's section index.
	unsigned long long symbolSectionIndex;
	if (!symbol->getLinkToSection(symbolSectionIndex)) {
		return;
	}

	unsigned long long size;
	unsigned long long address;

	// Get section and verify its type (must have CODE type).
	const Section* section = inputFile->getSection(symbolSectionIndex);
	if (!section || !section->isCode())
	{
		// PowerPC 64-bit function descriptors magic fix. Link to section
		// points to '.opd' section and not to '.text' section.
		if (inputFile->isPowerPc() && section->getName() == ".opd") {
			if (!symbol->getAddress(address) || !symbol->getSize(size)) {
				return;
			}

			// Get '.opd' entry file offset.
			std::size_t entryOffset = section->getOffset() + address;

			// Reload true symbol address from .opd section.
			std::uint64_t newAddress;
			auto bo = inputFile->getEndianness();
			if (!inputFile->get8ByteOffset(entryOffset, newAddress, bo)) {
				return;
			}

			// Reload '.text' section.
			section = inputFile->getSection(".text");
			if (section && section->isCode()) {
				addPattern(section, symbol->getName(), newAddress, size);
			}
		}

		// Cannot process.
		return;
	}

	if (symbol->getAddress(address) && symbol->getSize(size)) {
		if (symbol->isThumbSymbol()) {
			// Thumb symbol addresses as incremented by one.
			address -= 1;
		}
		addPattern(section, symbol->getName(), address, size);
	}
}

/**
 * Process single section.
 *
 * @param section pointer to section to process
 */
void PatternExtractor::processSection(const Section *section)
{
	// Section must have CODE type.
	if (!section || !section->isCode()) {
		return;
	}

	// Get all function symbols for section.
	std::vector<const Symbol*> symbols;
	for (auto* symTab : inputFile->getSymbolTables()) {
		for (std::size_t i = 0; i < symTab->getNumberOfSymbols(); ++i) {
			// Get symbol and check if it is function.
			const Symbol* symbol = symTab->getSymbol(i);
			if(!symbol || !symbol->isFunction()) {
				continue;
			}

			// Check section index.
			unsigned long long sectionLink;
			if(symbol->getLinkToSection(sectionLink)
				&& section->getIndex() == sectionLink) {
				symbols.push_back(symbol);
			}
		}
	}

	std::sort(symbols.begin(), symbols.end(), [](auto* f, auto* o) {
		unsigned long long fAddress = 0;
		unsigned long long oAddress = 0;
		f->getAddress(fAddress);
		o->getAddress(oAddress);
		return fAddress < oAddress;
	});

	addSectionPatterns(section, symbols);
}

/**
 * Add new patterns.
 *
 * @param section section to which symbols belong
 * @param symbols input symbols
 */
void PatternExtractor::addSectionPatterns(
	const Section *section,
	std::vector<const Symbol*> &symbols)
{
	// Turn symbols into patterns.
	for (std::size_t i = 0; i < symbols.size(); ++i) {
		// Check name and get symbol offset.
		const auto* symbol = symbols[i];
		unsigned long long startAddress;
		if (symbol->hasEmptyName() || !symbol->getAddress(startAddress)) {
			continue;
		}

		// End is either end of the section or start of the next symbol.
		unsigned long long endAddress;
		if (i + 1 < symbols.size()) {
			if (!symbols[i + 1]->getAddress(endAddress)) {
				continue;
			}
		}
		else {
			endAddress = section->getEndOffset();
		}

		if (endAddress < startAddress) {
			// First method of computing symbol end does not work with some
			// symbols so we will have to check symbol address range validity.
			continue;
		}

		// Create pattern.
		addPattern(section, symbol->getName(), startAddress,
			endAddress - startAddress);
	}
}

/**
 * Creates and stores one pattern from given symbol information.
 *
 * @param section pointer to symbol associated section
 * @param name name of the symbol
 * @param offset symbol offset from start of the section
 * @param size size of symbol
 */
void PatternExtractor::addPattern(
	const Section *section,
	const std::string &name,
	const unsigned long long offset,
	const unsigned long long size)
{
	std::vector<unsigned char> symbolData;
	if (size && section->getBytes(symbolData, offset, size))
	{
		SymbolPattern pattern(inputFile->isLittleEndian(),
			inputFile->getWordLength());
		pattern.setName(name);
		pattern.setArchitectureName(getArchAsString());
		pattern.setSourcePath(inputFile->getPathToFile());
		pattern.setRuleName(groupName + "_" + std::to_string(patterns.size()));

		// Add relocations.
		for (const auto *relTab : inputFile->getRelocationTables()) {
			for (std::size_t i = 0; i < relTab->getNumberOfRelocations(); ++i) {
				// Get relocation's section link and compare with section index.
				unsigned long long sectionLink;
				auto reloc = relTab->getRelocation(i);
				if (!reloc || !reloc->getLinkToSection(sectionLink)
						|| sectionLink != section->getIndex()) {
					continue;
				}

				auto relocOffset = reloc->getSectionOffset();
				if (relocOffset >= offset && relocOffset < offset + size) {
					const auto mask = reloc->getMask();
					pattern.addReference(reloc->getName(),
						relocOffset - offset, mask);
				}
			}
		}
		pattern.loadData(std::move(symbolData));
		patterns.push_back(pattern);
	}
}

/**
 * Get architecture info as string.
 *
 * This function should be replaced with unified way of interpreting
 * architecture names when available.
 *
 * @return string describing architecture
 */
std::string PatternExtractor::getArchAsString()
{
	switch (inputFile->getTargetArchitecture()) {
		case Architecture::X86:
			return "x86";

		case Architecture::X86_64:
			return "x64";

		case Architecture::MIPS:
			return "MIPS";
			break;

		case Architecture::POWERPC:
			return "PowerPC";
			break;

		case Architecture::ARM:
			return "ARM";

		default:
			return "unknown architecture";
	}
}

/**
 * Constructor.
 *
 * @param filePath path to file to process
 * @param groupName optional prefix for rule names (default: 'unknown_group')
 */
PatternExtractor::PatternExtractor(
	const std::string &filePath,
	const std::string &groupName)
	: inputFile(createFileFormat(filePath, nullptr, loadFlags)),
	groupName(groupName)
{
	stateValid = processFile();
}

/**
 * Destructor.
 */
PatternExtractor::~PatternExtractor()
{
}

/**
 * Check state of extractor.
 *
 * @return @c true if extractor is in valid state, @c false otherwise
 */
bool PatternExtractor::isValid() const
{
	return stateValid;
}

/**
 * Get error message in case of invalid state.
 *
 * @return error message
 */
std::string PatternExtractor::getErrorMessage() const
{
	return errorMessage;
}

/**
 * Get warning messages.
 *
 * @return vector with warning messages
 */
std::vector<std::string> PatternExtractor::getWarnings() const
{
	return warnings;
}

/**
 * Print rules to output stream.
 *
 * @param outputStream stream to print rules to
 * @param withNote optional note that will be added to all rules
 */
void PatternExtractor::printRules(
	std::ostream &outputStream,
	const std::string &withNote) const
{
	for (const auto &pattern : patterns) {
		pattern.printYaraRule(outputStream, withNote);
	}
}

/**
 * Add rules to YaraFileBuilder.
 *
 * @param builder YaraFileBuilder reference
 * @param withNote optional note that will be added to all rules
 */
void PatternExtractor::addRulesToBuilder(
	yaramod::YaraFileBuilder &builder,
	const std::string &withNote) const
{
	for (const auto &pattern : patterns) {
		pattern.addRuleToBuilder(builder, withNote);
	}
}

} // namespace patterngen
} // namespace retdec
