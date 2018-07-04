/**
 * @file src/fileformat/file_format/pe/pe_format.cpp
 * @brief Methods of PeFormat class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cassert>
#include <map>
#include <regex>
#include <tuple>
#include <unordered_map>

#include <openssl/asn1.h>
#include <openssl/x509.h>

#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/scope_exit.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/file_format/pe/pe_format.h"
#include "retdec/fileformat/file_format/pe/pe_format_parser/pe_format_parser32.h"
#include "retdec/fileformat/file_format/pe/pe_format_parser/pe_format_parser64.h"
#include "retdec/fileformat/types/dotnet_headers/metadata_tables.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_type_reconstructor.h"
#include "retdec/fileformat/utils/asn1.h"
#include "retdec/fileformat/utils/conversions.h"
#include "retdec/fileformat/utils/file_io.h"

using namespace retdec::utils;
using namespace PeLib;

namespace retdec {
namespace fileformat {

namespace
{

const std::size_t PE_IMAGE_SYM_CLASS_EXTERNAL = 2;
const std::size_t PE_IMAGE_SYM_CLASS_STATIC = 3;
const std::size_t PE_IMAGE_SYM_CLASS_FILE = 103;

const std::size_t STANDARD_RICH_HEADER_OFFSET = 0x80;
const std::size_t MINIMAL_PDB_NB10_INFO_LENGTH = 17;
const std::size_t MINIMAL_PDB_RSDS_INFO_LENGTH = 25;

const std::vector<std::string> stubDatabase =
{
	"This program cannot be run in DOS mode",
	"This program must be run under Win32",
	"This program requires Microsoft Windows",
	"Win32 only"
};

const std::map<std::string, std::size_t> visualBasicLibrariesMap =
{
	{"msvbvm10.dll", 1},
	{"msvbvm20.dll", 2},
	{"msvbvm30.dll", 3},
	{"msvbvm40.dll", 4},
	{"msvbvm50.dll", 5},
	{"msvbvm60.dll", 6},
	{"vb40032.dll", 4}
};

const std::map<std::size_t, std::string> resourceTypeMap
{
	{PELIB_RT_CURSOR, "Cursor"},
	{PELIB_RT_BITMAP, "Bitmap"},
	{PELIB_RT_ICON, "Icon"},
	{PELIB_RT_MENU, "Menu"},
	{PELIB_RT_DIALOG, "Dialog box"},
	{PELIB_RT_STRING, "String-table entry"},
	{PELIB_RT_FONTDIR, "Font directory"},
	{PELIB_RT_FONT, "Font"},
	{PELIB_RT_ACCELERATOR, "Accelerator table"},
	{PELIB_RT_RCDATA, "Raw data"},
	{PELIB_RT_MESSAGETABLE, "Message-table entry"},
	{PELIB_RT_GROUP_CURSOR, "Cursor Group"},
	{PELIB_RT_GROUP_ICON, "Icon Group"},
	{PELIB_RT_VERSION, "Version"},
	{PELIB_RT_DLGINCLUDE, "Include"},
	{PELIB_RT_PLUGPLAY, "Plug and Play"},
	{PELIB_RT_VXD, "VXD"},
	{PELIB_RT_ANICURSOR, "Animated cursor"},
	{PELIB_RT_ANIICON, "Animated icon"},
	{PELIB_RT_HTML, "HTML"},
	{PELIB_RT_MANIFEST, "Manifest"},
	{PELIB_RT_DLGINIT, "Dialog box init"},
	{PELIB_RT_TOOLBAR, "Toolbar"}
};

const std::map<std::size_t, std::string> resourceLanguageMap
{
	{PELIB_LANG_NEUTRAL, "Neutral"},
	{PELIB_LANG_ARABIC, "Arabic"},
	{PELIB_LANG_BULGARIAN, "Bulgarian"},
	{PELIB_LANG_CATALAN, "Catalan"},
	{PELIB_LANG_CHINESE, "Chinese"},
	{PELIB_LANG_CZECH, "Czech"},
	{PELIB_LANG_DANISH, "Danish"},
	{PELIB_LANG_GERMAN, "German"},
	{PELIB_LANG_GREEK, "Greek"},
	{PELIB_LANG_ENGLISH, "English"},
	{PELIB_LANG_SPANISH, "Spanish"},
	{PELIB_LANG_FINNISH, "Finnish"},
	{PELIB_LANG_FRENCH, "French"},
	{PELIB_LANG_HEBREW, "Hebrew"},
	{PELIB_LANG_HUNGARIAN, "Hungarian"},
	{PELIB_LANG_ICELANDIC, "Icelandic"},
	{PELIB_LANG_ITALIAN, "Italian"},
	{PELIB_LANG_JAPANESE, "Japanese"},
	{PELIB_LANG_KOREAN, "Korean"},
	{PELIB_LANG_DUTCH, "Dutch"},
	{PELIB_LANG_NORWEGIAN, "Norwegian"},
	{PELIB_LANG_POLISH, "Polish"},
	{PELIB_LANG_PORTUGUESE, "Portuguese"},
	{PELIB_LANG_ROMANIAN, "Romanian"},
	{PELIB_LANG_RUSSIAN, "Russian"},
	{PELIB_LANG_CROATIAN, "Croatian"},
	{PELIB_LANG_SERBIAN_NEUTRAL, "Serbian"},
	{PELIB_LANG_BOSNIAN_NEUTRAL, "Bosnian"},
	{PELIB_LANG_SLOVAK, "Slovak"},
	{PELIB_LANG_ALBANIAN, "Albanian"},
	{PELIB_LANG_SWEDISH, "Swedish"},
	{PELIB_LANG_THAI, "Thai"},
	{PELIB_LANG_TURKISH, "Turkish"},
	{PELIB_LANG_URDU, "Urdu"},
	{PELIB_LANG_INDONESIAN, "Indonesian"},
	{PELIB_LANG_UKRAINIAN, "Ukrainian"},
	{PELIB_LANG_BELARUSIAN, "Belarusian"},
	{PELIB_LANG_SLOVENIAN, "Slovenian"},
	{PELIB_LANG_ESTONIAN, "Estonian"},
	{PELIB_LANG_LATVIAN, "Latvian"},
	{PELIB_LANG_LITHUANIAN, "Lithuanian"},
	{PELIB_LANG_PERSIAN, "Persian"},
	{PELIB_LANG_VIETNAMESE, "Vietnamese"},
	{PELIB_LANG_ARMENIAN, "Armenian"},
	{PELIB_LANG_AZERI, "Azeri"},
	{PELIB_LANG_BASQUE, "Basque"},
	{PELIB_LANG_SORBIAN, "Sorbian"},
	{PELIB_LANG_MACEDONIAN, "Macedonian"},
	{PELIB_LANG_TSWANA, "Tswana"},
	{PELIB_LANG_XHOSA, "Xhosa"},
	{PELIB_LANG_ZULU, "Zulu"},
	{PELIB_LANG_AFRIKAANS, "Afrikaans"},
	{PELIB_LANG_GEORGIAN, "Georgian"},
	{PELIB_LANG_FAEROESE, "Faeroese"},
	{PELIB_LANG_HINDI, "Hindi"},
	{PELIB_LANG_MALTESE, "Maltese"},
	{PELIB_LANG_SAMI, "Sami"},
	{PELIB_LANG_IRISH, "Irish"},
	{PELIB_LANG_MALAY, "Malay"},
	{PELIB_LANG_KAZAK, "Kazak"},
	{PELIB_LANG_KYRGYZ, "Kyrgyz"},
	{PELIB_LANG_SWAHILI, "Swahili"},
	{PELIB_LANG_UZBEK, "Uzbek"},
	{PELIB_LANG_TATAR, "Tatar"},
	{PELIB_LANG_BENGALI, "Bengali"},
	{PELIB_LANG_PUNJABI, "Punjabi"},
	{PELIB_LANG_GUJARATI, "Gujarati"},
	{PELIB_LANG_ORIYA, "Oriya"},
	{PELIB_LANG_TAMIL, "Tamil"},
	{PELIB_LANG_TELUGU, "Telugu"},
	{PELIB_LANG_KANNADA, "Kannada"},
	{PELIB_LANG_MALAYALAM, "Malayalam"},
	{PELIB_LANG_ASSAMESE, "Assamese"},
	{PELIB_LANG_MARATHI, "Marathi"},
	{PELIB_LANG_SANSKRIT, "Sanskrit"},
	{PELIB_LANG_MONGOLIAN, "Mongolian"},
	{PELIB_LANG_TIBETAN, "Tibetan"},
	{PELIB_LANG_WELSH, "Welsh"},
	{PELIB_LANG_KHMER, "Khmer"},
	{PELIB_LANG_LAO, "Lao"},
	{PELIB_LANG_GALICIAN, "Galician"},
	{PELIB_LANG_KONKANI, "Konkani"},
	{PELIB_LANG_MANIPURI, "Manipuri"},
	{PELIB_LANG_SINDHI, "Sindhi"},
	{PELIB_LANG_SYRIAC, "Syriac"},
	{PELIB_LANG_SINHALESE, "Sinhalese"},
	{PELIB_LANG_INUKTITUT, "Inuktitut"},
	{PELIB_LANG_AMHARIC, "Amharic"},
	{PELIB_LANG_TAMAZIGHT, "Tamazight"},
	{PELIB_LANG_KASHMIRI, "Kashmiri"},
	{PELIB_LANG_NEPALI, "Nepali"},
	{PELIB_LANG_FRISIAN, "Frisian"},
	{PELIB_LANG_PASHTO, "Pashto"},
	{PELIB_LANG_FILIPINO, "Filipino"},
	{PELIB_LANG_DIVEHI, "Divehi"},
	{PELIB_LANG_HAUSA, "Hausa"},
	{PELIB_LANG_YORUBA, "Yoruba"},
	{PELIB_LANG_QUECHUA, "Quechua"},
	{PELIB_LANG_SOTHO, "Sotho"},
	{PELIB_LANG_BASHKIR, "Bashkir"},
	{PELIB_LANG_LUXEMBOURGISH, "Luxembourgish"},
	{PELIB_LANG_GREENLANDIC, "Greenlandic"},
	{PELIB_LANG_IGBO, "Igbo"},
	{PELIB_LANG_TIGRIGNA, "Tigrigna"},
	{PELIB_LANG_YI, "Yi"},
	{PELIB_LANG_MAPUDUNGUN, "Mapudungun"},
	{PELIB_LANG_MOHAWK, "Mohawk"},
	{PELIB_LANG_BRETON, "Breton"},
	{PELIB_LANG_INVARIANT, "Invariant"},
	{PELIB_LANG_UIGHUR, "Uighur"},
	{PELIB_LANG_MAORI, "Maori"},
	{PELIB_LANG_OCCITAN, "Occitan"},
	{PELIB_LANG_CORSICAN, "Corsican"},
	{PELIB_LANG_ALSATIAN, "Alsatian"},
	{PELIB_LANG_YAKUT, "Yakut"},
	{PELIB_LANG_KICHE, "Kiche"},
	{PELIB_LANG_KINYARWANDA, "Kinyarwanda"},
	{PELIB_LANG_WOLOF, "Wolof"},
	{PELIB_LANG_DARI, "Dari"},
	{PELIB_LANG_MALAGASY, "Malagasy"}
};

/**
 * Try to find offset of DOS stub
 * @param plainFile Content of input file from space after MZ header to offset
 *    of PE signature
 * @return Offset of DOS stub in @a plainFile or @c string::npos if DOS stub
 *    is not found
 */
std::size_t findDosStub(const std::string &plainFile)
{
	for(const auto &item : stubDatabase)
	{
		const auto offset = plainFile.find(item);
		if(offset != std::string::npos)
		{
			return offset;
		}
	}

	return std::string::npos;
}

/**
 * Get type of symbol
 * @param link Link to PE section
 * @param value PE symbol value
 * @param storageClass PE symbol storage class
 * @return Type of symbol
 */
Symbol::Type getSymbolType(word link, dword value, byte storageClass)
{
	if(!link)
	{
		return value ? Symbol::Type::COMMON : Symbol::Type::EXTERN;
	}
	else if(link == std::numeric_limits<word>::max() || link == std::numeric_limits<word>::max() - 1)
	{
		return Symbol::Type::ABSOLUTE_SYM;
	}
	else if(storageClass == PE_IMAGE_SYM_CLASS_EXTERNAL)
	{
		return Symbol::Type::PUBLIC;
	}
	else if(storageClass == PE_IMAGE_SYM_CLASS_STATIC)
	{
		return Symbol::Type::PRIVATE;
	}

	return Symbol::Type::UNDEFINED_SYM;
}

/**
 * Get usage type of symbol
 * @param storageClass PE symbol storage class
 * @param complexType PE symbol type
 * @return Usage type of symbol
 */
Symbol::UsageType getSymbolUsageType(byte storageClass, byte complexType)
{
	if(complexType >= 0x20 && complexType < 0x30)
	{
		return Symbol::UsageType::FUNCTION;
	}
	else if(storageClass == PE_IMAGE_SYM_CLASS_FILE)
	{
		return Symbol::UsageType::FILE;
	}

	return Symbol::UsageType::UNKNOWN;
}

} // anonymous namespace

/**
 * Constructor
 * @param pathToFile Path to input file
 * @param loadFlags Load flags
 */
PeFormat::PeFormat(std::string pathToFile, LoadFlags loadFlags) : FileFormat(pathToFile, loadFlags)
{
	initStructures();
}

/**
 * Destructor
 */
PeFormat::~PeFormat()
{
	delete file;
	delete formatParser;
}

/**
* Init information from PE loader
*/
void PeFormat::initLoaderErrorInfo()
{
	PeLib::LoaderError ldrError = file->loaderError();

	_ldrErrInfo.loaderErrorCode = static_cast<std::uint32_t>(ldrError);
	_ldrErrInfo.loaderError = getLoaderErrorString(ldrError, false);
	_ldrErrInfo.loaderErrorUserFriendly = getLoaderErrorString(ldrError, true);
}

/**
 * Init internal structures
 */
void PeFormat::initStructures()
{
	formatParser = nullptr;
	peHeader32 = nullptr;
	peHeader64 = nullptr;
	peClass = PEFILE_UNKNOWN;
	file = openPeFile(filePath);
	if(file)
	{
		stateIsValid = true;
		try
		{
			file->readMzHeader();
			file->readPeHeader();
			file->readCoffSymbolTable();
			file->readImportDirectory();
			file->readIatDirectory();
			file->readBoundImportDirectory();
			file->readDelayImportDirectory();
			file->readExportDirectory();
			file->readDebugDirectory();
			file->readResourceDirectory();
			file->readSecurityDirectory();
			file->readComHeaderDirectory();

			// Fill-in the loader error info from PE file
			initLoaderErrorInfo();

			mzHeader = file->mzHeader();
			switch((peClass = getFileType(filePath)))
			{
				case PEFILE32:
				{
					auto *f32 = dynamic_cast<PeFileT<32>*>(file);
					if(f32)
					{
						peHeader32 = &(f32->peHeader());
						formatParser = new PeFormatParser32(this, static_cast<PeFileT<32>*>(file));
					}
					stateIsValid = f32 && peHeader32;
					break;
				}
				case PEFILE64:
				{
					auto *f64 = dynamic_cast<PeFileT<64>*>(file);
					if(f64)
					{
						peHeader64 = &(f64->peHeader());
						formatParser = new PeFormatParser64(this, static_cast<PeFileT<64>*>(file));
					}
					stateIsValid = f64 && peHeader64;
					break;
				}
				default:
				{
					stateIsValid = false;
				}
			}
		} catch(...)
		{
			stateIsValid = false;
		}
	}
	else
	{
		stateIsValid = false;
	}

	if(stateIsValid)
	{
		fileFormat = Format::PE;
		loadRichHeader();
		loadSections();
		loadSymbols();
		loadImports();
		loadExports();
		loadPdbInfo();
		loadResources();
		loadCertificates();
		loadDotnetHeaders();
		computeSectionTableHashes();
		loadStrings();
	}
}

std::size_t PeFormat::initSectionTableHashOffsets()
{
	secHashInfo.emplace_back(20, 4);
	secHashInfo.emplace_back(16, 4);
	secHashInfo.emplace_back(36, 4);
	return secHashInfo.size();
}

/**
 * Calculate offset of rich header
 * @param plainFile Content of input file from space after MZ header to offset
 *    of PE signature
 *
 * Method returns default value (0x80) if detection of offset fails or rich
 * header is not present in input file.
 */
std::size_t PeFormat::getRichHeaderOffset(const std::string &plainFile)
{
	std::size_t richOffset = 0, prev = findDosStub(plainFile);

	if(prev != std::string::npos)
	{
		for(std::size_t i = 0, next = 0; (next = plainFile.find('\0', prev)) != std::string::npos; ++i)
		{
			if(i)
			{
				if(next != prev)
				{
					break;
				}
				richOffset = ++prev;
			}
			else
			{
				richOffset = prev = ++next;
			}
		}
	}

	return richOffset ? richOffset + getMzHeaderSize() : STANDARD_RICH_HEADER_OFFSET;
}

/**
 * Get nodes of resource tree except root
 * @param nodes Into this parameter nodes are stored (except root node)
 * @param levels Into this parameter is stored number of nodes in each level
 *    of tree (except root level)
 * @return @c true if nodes was successfully loaded, @c false otherwise
 */
bool PeFormat::getResourceNodes(std::vector<const PeLib::ResourceChild*> &nodes, std::vector<std::size_t> &levels)
{
	nodes.clear();
	levels.clear();
	auto root = formatParser->getResourceTreeRoot();
	if(!root || !root->getNumberOfChildren())
	{
		return false;
	}
	resourceTree = new ResourceTree();
	resourceTree->addNode(0, root->getNumberOfChildren());
	levels.push_back(root->getNumberOfChildren());

	for(std::size_t i = 0, e = root->getNumberOfChildren(); i < e; ++i)
	{
		nodes.push_back(root->getChild(i));
	}

	for(std::size_t i = 0, e = nodes.size(); i < e; ++i)
	{
		auto *actual = nodes[i];
		if(actual)
		{
			resourceTree->addNode(levels.size(), actual->getNumberOfChildren());

			for(std::size_t j = 0, f = actual->getNumberOfChildren(); j < f; ++j)
			{
				nodes.push_back(actual->getChildOfThisChild(j));
			}
		}

		// end of actual level
		if(i + 1 == e && nodes.size() > e)
		{
			levels.push_back(nodes.size() - e);
			e = nodes.size();
		}
	}

	if(!resourceTree->isValidTree())
	{
		assert(false && "Incorrect structure of resources");
	}

	return true;
}

/**
 * Load Rich header
 */
void PeFormat::loadRichHeader()
{
	if(getPeHeaderOffset() <= getMzHeaderSize())
	{
		return;
	}

	std::string plainText;
	bytesToString(bytes, plainText, getMzHeaderSize(), getPeHeaderOffset() - getMzHeaderSize());
	auto offset = getRichHeaderOffset(plainText);
	auto standardOffset = (offset == STANDARD_RICH_HEADER_OFFSET);
	if(offset >= getPeHeaderOffset())
	{
		return;
	}

	file->readRichHeader(offset, getPeHeaderOffset() - offset);
	auto &header = file->richHeader();
	std::vector<std::size_t> validStructOffsets;
	if(header.isStructureValid())
	{
		validStructOffsets.push_back(offset);
	}
	// try space immediately after DOS (MZ) header
	if(!header.isHeaderValid() && offset > getMzHeaderSize() && getPeHeaderOffset() > getMzHeaderSize())
	{
		offset = getMzHeaderSize();
		standardOffset |= (offset == STANDARD_RICH_HEADER_OFFSET);
		file->readRichHeader(offset, getPeHeaderOffset() - offset);
		if(header.isStructureValid())
		{
			validStructOffsets.push_back(offset);
		}
	}
	// try standard offset of rich header
	if(!header.isHeaderValid() && !standardOffset && STANDARD_RICH_HEADER_OFFSET < getPeHeaderOffset())
	{
		offset = STANDARD_RICH_HEADER_OFFSET;
		file->readRichHeader(offset, getPeHeaderOffset() - offset);
		if(header.isStructureValid())
		{
			validStructOffsets.push_back(offset);
		}
	}
	if(!header.isHeaderValid() && validStructOffsets.empty())
	{
		return;
	}

	std::string signature;
	richHeader = new RichHeader();
	richHeader->setOffset(offset);
	richHeader->setSuspicious(header.getNumberOfIterations() > 1);
	richHeader->setValidStructure(true);
	if(!header.isHeaderValid())
	{
		const auto nonStandardOffset = std::any_of(validStructOffsets.begin(), validStructOffsets.end(),
			[&] (const auto &off)
			{
				return off != STANDARD_RICH_HEADER_OFFSET && off != this->getMzHeaderSize();
			});
		std::size_t maxOffset = 0;

		for(const auto off : validStructOffsets)
		{
			if(off > maxOffset && (!nonStandardOffset || (off != STANDARD_RICH_HEADER_OFFSET && off != getMzHeaderSize())))
			{
				maxOffset = off;
			}
		}

		file->readRichHeader(maxOffset, getPeHeaderOffset() - maxOffset, true);
		richHeader->setOffset(maxOffset);
		richHeader->setSuspicious(header.getNumberOfIterations() > 1);
		signature = header.getDecryptedHeaderItemsSignature({0, 1, 2, 3});
	}

	for(const auto &item : header)
	{
		LinkerInfo info;
		info.setMajorVersion(item.MajorVersion);
		info.setMinorVersion(item.MinorVersion);
		info.setBuildVersion(item.Build);
		info.setNumberOfUses(item.Count);
		signature += item.Signature;
		richHeader->addRecord(info);
	}

	richHeader->setKey(header.getKey());
	richHeader->setSignature(signature);
	richHeader->setBytes(header.getDecryptedHeaderBytes());
}

/**
 * Load information about sections
 */
void PeFormat::loadSections()
{
	for(std::size_t i = 0, e = formatParser->getStoredNumberOfSections(); i < e; ++i)
	{
		auto *section = new PeCoffSection();
		if(!formatParser->getSection(i, *section))
		{
			delete section;
			continue;
		}
		sections.push_back(section);
	}
}

/**
 * Load information about symbols
 *
 * Instance method @a loadSections() must be invoked before invocation of this method
 */
void PeFormat::loadSymbols()
{
	const auto symTab = file->coffSymTab();
	auto *table = new SymbolTable();

	for(std::size_t i = 0, e = symTab.getNumberOfStoredSymbols(); i < e; ++i)
	{
		auto symbol = std::make_shared<Symbol>();
		const word link = symTab.getSymbolSectionNumber(i);
		if(!link || link == std::numeric_limits<word>::max() || link == std::numeric_limits<word>::max() - 1)
		{
			symbol->invalidateLinkToSection();
			symbol->invalidateAddress();
		}
		else
		{
			symbol->setLinkToSection(link - 1);
			if(link <= getNumberOfSections() && sections[link - 1])
			{
				const auto a = sections[link - 1]->getAddress() + symTab.getSymbolValue(i);
				symbol->setAddress(a);
				symbol->setIsThumbSymbol(isArm() && a % 2);
			}
			else
			{
				symbol->invalidateAddress();
			}
		}
		symbol->setOriginalName(symTab.getSymbolName(i));
		symbol->setName(symTab.getSymbolName(i));
		symbol->setIndex(symTab.getSymbolIndex(i));
		symbol->setType(getSymbolType(link, symTab.getSymbolValue(i), symTab.getSymbolStorageClass(i)));
		symbol->setUsageType(getSymbolUsageType(symTab.getSymbolStorageClass(i), symTab.getSymbolTypeComplex(i)));
		table->addSymbol(symbol);
	}

	if(table->hasSymbols())
	{
		symbolTables.push_back(table);
	}
	else
	{
		delete table;
	}
}

/**
 * Load information about imports
 */
void PeFormat::loadImports()
{
	std::string libname;

	for(std::size_t i = 0; formatParser->getImportedLibraryFileName(i, libname); ++i)
	{
		if(!importTable)
		{
			importTable = new ImportTable();
		}
		importTable->addLibrary(libname);

		std::size_t index = 0;
		while (auto import = formatParser->getImport(i, index))
		{
			importTable->addImport(std::move(import));
			index++;
		}
	}

	for(std::size_t i = 0; formatParser->getDelayImportedLibraryFileName(i, libname); ++i)
	{
		if(!importTable)
		{
			importTable = new ImportTable();
		}
		importTable->addLibrary(libname);

		std::size_t index = 0;
		while (auto import = formatParser->getDelayImport(i, index))
		{
			import->setLibraryIndex(importTable->getNumberOfLibraries() - 1);
			importTable->addImport(std::move(import));
			index++;
		}
	}

	loadImpHash();

	for(auto&& addressRange : formatParser->getImportDirectoryOccupiedAddresses())
	{
		nonDecodableRanges.addRange(std::move(addressRange));
	}
}

/**
 * Load informations about exports
 */
void PeFormat::loadExports()
{
	Export newExport;
	exportTable = new ExportTable();

	for(std::size_t i = 0, e = formatParser->getNumberOfExportedFunctions(); i < e; ++i)
	{
		if (!formatParser->getExportedFunction(i, newExport))
			break;

		if(hasNonprintableChars(newExport.getName()))
		{
			newExport.setName("exported_function_" + numToStr(newExport.getAddress(), std::hex));
		}
		exportTable->addExport(newExport);
	}

	loadExpHash();

	for(auto&& addressRange : formatParser->getExportDirectoryOccupiedAddresses())
	{
		nonDecodableRanges.addRange(std::move(addressRange));
	}
}

/**
 * Load information about related PDB file
 */
void PeFormat::loadPdbInfo()
{
	for(std::size_t i = 0, e = formatParser->getNumberOfDebugEntries(); i < e; ++i)
	{
		std::vector<std::uint8_t> data;
		if (!formatParser->getDebugEntryData(i, data))
		{
			continue;
		}

		std::string dataString;
		bytesToString(data, dataString);
		const auto size = std::min(data.size(), dataString.length());
		if(size < 4)
		{
			continue;
		}
		const auto prefix = dataString.substr(0, 4);
		if((prefix != "RSDS" && prefix != "NB10") || (prefix == "RSDS" && size < MINIMAL_PDB_RSDS_INFO_LENGTH) ||
			(prefix == "NB10" && size < MINIMAL_PDB_NB10_INFO_LENGTH))
		{
			continue;
		}

		unsigned long long timestamp;
		if (!formatParser->getDebugEntryTimeDateStamp(i, timestamp))
		{
			continue;
		}

		unsigned long long pointerToRawData;
		if (!formatParser->getDebugEntryPointerToRawData(i, pointerToRawData))
		{
			continue;
		}

		const auto isRsds = (prefix == "RSDS");
		pdbInfo = new PdbInfo();
		pdbInfo->setType(prefix);
		pdbInfo->setTimeStamp(timestamp);
		const auto guidOffset = pointerToRawData + prefix.length() + (isRsds ? 0 : 4);
		std::uint64_t res1;
		if(isRsds)
		{
			std::uint64_t res2, res3, res4, res5;
			if(get4ByteOffset(guidOffset, res1) && get2ByteOffset(guidOffset + 4, res2) &&
				get2ByteOffset(guidOffset + 6, res3) && get2ByteOffset(guidOffset + 8, res4, getInverseEndianness()) &&
				getXByteOffset(guidOffset + 10, 6, res5, getInverseEndianness()))
			{
				pdbInfo->setGuid(toUpper(numToStr(res1, std::hex) + "-" + numToStr(res2, std::hex) + "-" +
					numToStr(res3, std::hex) + "-" + numToStr(res4, std::hex) + "-" + numToStr(res5, std::hex)));
			}
		}
		else if(get4ByteOffset(guidOffset, res1))
		{
			pdbInfo->setGuid(toUpper(numToStr(res1, std::hex)));
		}

		const auto ageOffset = guidOffset + (isRsds ? 16 : 4);
		if(get4ByteOffset(ageOffset, res1))
		{
			pdbInfo->setAge(res1);
		}
		if(getNTBSOffset(ageOffset + 4, dataString))
		{
			pdbInfo->setPath(dataString);
		}
		break;
	}

	for (auto&& addressRange : formatParser->getDebugDirectoryOccupiedAddresses())
	{
		nonDecodableRanges.addRange(std::move(addressRange));
	}
}

/**
 * Load only resource nodes
 * @param nodes Nodes of tree (except root node)
 * @param levels Number of nodes in each level of tree (except root level)
 */
void PeFormat::loadResourceNodes(std::vector<const PeLib::ResourceChild*> &nodes, const std::vector<std::size_t> &levels)
{
	unsigned long long rva = 0, size = 0;
	if(levels.empty() || !getDataDirectoryRelative(PELIB_IMAGE_DIRECTORY_ENTRY_RESOURCE, rva, size))
	{
		return;
	}

	Resource resource;
	resourceTable = new ResourceTable();
	std::size_t firstLeafIndex = 0;

	for(std::size_t i = 0, e = levels.size() - 1; i < e; ++i)
	{
		firstLeafIndex += levels[i];
	}

	for(std::size_t i = 0, e = resourceTree->getNumberOfLeafs(); i < e; ++i)
	{
		auto *leafChild = nodes[firstLeafIndex + i];
		if(!leafChild)
		{
			continue;
		}
		auto *leafChildNode = leafChild->getNode();
		auto *leaf = dynamic_cast<const ResourceLeaf*>(leafChildNode);
		if(!leafChildNode || !leafChildNode->isLeaf() || !leaf)
		{
			continue;
		}
		resource.setOffset(leaf->getOffsetToData() - rva + formatParser->getResourceDirectoryOffset());
		resource.setSizeInFile(leaf->getSize());
		resource.load(this);
		resourceTable->addResource(resource);
	}
}

/**
 * Load resources
 */
void PeFormat::loadResources()
{
	unsigned long long rva = 0, size = 0;
	if(!getDataDirectoryRelative(PELIB_IMAGE_DIRECTORY_ENTRY_RESOURCE, rva, size))
	{
		return;
	}

	std::vector<const ResourceChild*> nodes;
	std::vector<std::size_t> levels;
	if(!getResourceNodes(nodes, levels))
	{
		return;
	}
	else if(resourceTree->getNumberOfLevelsWithoutRoot() != 3)
	{
		loadResourceNodes(nodes, levels);
		return;
	}

	Resource resource;
	resourceTable = new ResourceTable();

	for(std::size_t i = 0, e = levels[0], nSft = 0, lSft = 0; i < e; ++i)
	{
		auto *typeChild = nodes[i];
		if(!typeChild)
		{
			continue;
		}
		resource.setType(typeChild->getName());
		resource.invalidateTypeId();
		if(resource.hasEmptyType())
		{
			resource.setTypeId(typeChild->getOffsetToName());
			resource.setType(mapGetValueOrDefault(resourceTypeMap, typeChild->getOffsetToName(), ""));
		}
		nSft += typeChild->getNumberOfChildren();

		for(std::size_t j = 0, f = typeChild->getNumberOfChildren(); j < f; ++j)
		{
			auto *nameChild = nodes[e + j + nSft - f];
			if(!nameChild)
			{
				continue;
			}
			resource.setName(nameChild->getName());
			resource.invalidateNameId();
			if(resource.hasEmptyName())
			{
				resource.setNameId(nameChild->getOffsetToName());
			}
			lSft += nameChild->getNumberOfChildren();

			for(std::size_t k = 0, g = nameChild->getNumberOfChildren(); k < g; ++k)
			{
				auto *lanChild = nodes[e + levels[1] + k + lSft - g];
				if(!lanChild)
				{
					continue;
				}
				auto *lanChildNode = lanChild->getNode();
				auto *lanLeaf = dynamic_cast<const ResourceLeaf*>(lanChildNode);
				if(!lanChildNode || !lanChildNode->isLeaf() || !lanLeaf)
				{
					continue;
				}
				resource.setOffset(lanLeaf->getOffsetToData() - rva + formatParser->getResourceDirectoryOffset());
				resource.setSizeInFile(lanLeaf->getSize());
				resource.setLanguage(lanChild->getName());
				resource.invalidateLanguageId();
				resource.invalidateSublanguageId();
				if(resource.hasEmptyLanguage())
				{
					const auto lIdAll = lanChild->getOffsetToName();
					const auto lId = lIdAll & 0x3FF;
					resource.setLanguageId(lId);
					resource.setSublanguageId((lIdAll & 0xFC00) >> 10);
					resource.setLanguage(mapGetValueOrDefault(resourceLanguageMap, lId, ""));
				}
				resource.load(this);
				resourceTable->addResource(resource);
			}
		}
	}

	for (auto&& addressRange : formatParser->getResourceDirectoryOccupiedAddresses())
	{
		nonDecodableRanges.addRange(std::move(addressRange));
	}
}

/**
 * Load certificates.
 */
void PeFormat::loadCertificates()
{
	const auto &securityDir = file->securityDir();
	if(securityDir.calcNumberOfCertificates() == 0)
	{
		return;
	}

	// We always take the first one, there are no additional certificate tables in PE
	auto certBytes = securityDir.getCertificate(0);

	BIO *bio = BIO_new(BIO_s_mem());
	if(!bio)
	{
		return;
	}

	if(BIO_reset(bio) != 1)
	{
		BIO_free(bio);
		return;
	}

	if(BIO_write(bio, certBytes.data(), static_cast<int>(certBytes.size())) != static_cast<std::int64_t>(certBytes.size()))
	{
		BIO_free(bio);
		return;
	}

	PKCS7 *p7 = d2i_PKCS7_bio(bio, nullptr);
	if(!p7)
	{
		BIO_free(bio);
		return;
	}

	// Find signer of the application and store its serial number.
	X509 *signerCert = nullptr;
	X509 *counterSignerCert = nullptr;
	STACK_OF(X509) *certs = p7->d.sign->cert;
	STACK_OF(X509) *signers = PKCS7_get0_signers(p7, certs, 0);

	SCOPE_EXIT {
		if (signers != nullptr)
			sk_X509_free(signers);
	};

	if(sk_X509_num(signers) > 0)
	{
		signerCert = sk_X509_value(signers, 0);
	}

	// Try to find countersigner if it exists and store its serial number.
	STACK_OF(PKCS7_SIGNER_INFO) *sinfos = PKCS7_get_signer_info(p7);
	if(sk_PKCS7_SIGNER_INFO_num(sinfos) > 0)
	{
		PKCS7_SIGNER_INFO *sinfo = sk_PKCS7_SIGNER_INFO_value(sinfos, 0);

		// Counter-signer is stored as unsigned attribute and there is no other way to get it but manual parsing
		ASN1_TYPE *counterSig = PKCS7_get_attribute(sinfo, NID_pkcs9_countersignature);
		if(counterSig)
		{
			auto bio = std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new_mem_buf(counterSig->value.sequence->data, counterSig->value.sequence->length), &BIO_free);
			PKCS7_SIGNER_INFO *counterSinfo = reinterpret_cast<PKCS7_SIGNER_INFO*>(ASN1_item_d2i_bio(ASN1_ITEM_rptr(PKCS7_SIGNER_INFO), bio.get(), nullptr));
			if(counterSinfo)
			{
				// From SignerInfo, we get only issuer, but we can lookup by issuer in all certificates and get original counter-signer
				counterSignerCert = X509_find_by_issuer_and_serial(certs, counterSinfo->issuer_and_serial->issuer, counterSinfo->issuer_and_serial->serial);
			}
			ASN1_item_free(reinterpret_cast<ASN1_VALUE*>(counterSinfo), ASN1_ITEM_rptr(PKCS7_SIGNER_INFO));
		}
	}

	// If we have no signer and countersigner, there must be something really bad
	if(!signerCert && !counterSignerCert)
	{
		BIO_free(bio);
		return;
	}

	// Now that we know there is at least a signer or counter-signer, we can
	// verify the signature. Do not try to verify the signature before
	// verifying that there is at least a signer or counter-signer as 'p7' is
	// empty in that case (#87).
	signatureVerified = verifySignature(p7);

	// Create hash table with key-value pair as subject-X509 certificate so we can easily lookup certificates by their subject name
	std::unordered_map<std::string, X509*> subjectToCert;
	for(int j = 0; j < sk_X509_num(certs); ++j)
	{
		X509 *xcert = sk_X509_value(certs, j);
		auto subjectPtr = X509_NAME_oneline(X509_get_subject_name(xcert), nullptr, 0);
		std::string subject = subjectPtr;
		subjectToCert[subject] = xcert;
		OPENSSL_free(subjectPtr);
	}

	// Start with signer certificate which will be always first and continue with its issuer name and use previously constructed hash table to
	// reconstruct chain of certificates
	// When we hit the last certificate in the chain and there is counter-signer, try to reconstruct its chain
	X509* xcert = nullptr;
	bool counterChain = false;
	std::string nextIssuer;
	if(signerCert)
	{
		auto nextIssuerPtr = X509_NAME_oneline(X509_get_subject_name(signerCert), nullptr, 0);
		nextIssuer = nextIssuerPtr;
		OPENSSL_free(nextIssuerPtr);
	}

	// Continue while we have next issuer to process, or there is counter-signer certificate and we haven't processed him yet
	while(!nextIssuer.empty() || (!counterChain && counterSignerCert))
	{
		// Find next issuer in the hash table
		auto itr = subjectToCert.find(nextIssuer);
		if(itr == subjectToCert.end())
		{
			// If we haven't processed counter-signer chain yet and there is counter-signer certificate
			if(!counterChain && counterSignerCert)
			{
				auto nextIssuerPtr = X509_NAME_oneline(X509_get_subject_name(counterSignerCert), nullptr, 0);
				nextIssuer = nextIssuerPtr;
				counterChain = true;
				OPENSSL_free(nextIssuerPtr);
				continue;
			}
			else
			{
				break;
			}
		}
		// Remove certificate from the hash table so we can't get into infinite loops
		else
		{
			xcert = itr->second;
			subjectToCert.erase(itr);
		}

		if(!certificateTable)
		{
			certificateTable = new CertificateTable();
		}

		Certificate cert(xcert);
		certificateTable->addCertificate(cert);

		// Check if we are at signer or counter-signer certificate and let the certificate table known indices.
		if(xcert == signerCert)
		{
			certificateTable->setSignerCertificateIndex(certificateTable->getNumberOfCertificates() - 1);
		}
		else if(xcert == counterSignerCert)
		{
			certificateTable->setCounterSignerCertificateIndex(certificateTable->getNumberOfCertificates() - 1);
		}

		// Continue with next issuer
		nextIssuer = cert.getRawIssuer();
	}

	PKCS7_free(p7);
	BIO_free(bio);
}

/**
 * Load .NET headers.
 */
void PeFormat::loadDotnetHeaders()
{
	std::uint64_t metadataHeaderAddress = 0;

	// If our file contains CLR header, then use it
	unsigned long long comHeaderAddress, comHeaderSize;
	if(getDataDirectoryRelative(PELIB_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, comHeaderAddress, comHeaderSize) && comHeaderSize)
	{
		clrHeader = formatParser->getClrHeader();
		metadataHeaderAddress = formatParser->getImageBaseAddress() + clrHeader->getMetadataDirectoryAddress();
	}
	// If not, then try to guess whether the file could possibly be .NET file based on imports and try to search for metadata header
	else
	{
		if (importTable && importTable->getNumberOfImportsInLibraryCaseInsensitive("mscoree.dll"))
		{
			metadataHeaderAddress = detectPossibleMetadataHeaderAddress();
			if (metadataHeaderAddress == 0)
				return;
		}
		else
		{
			return;
		}
	}

	// This explicit initialization needs to be here, because clang 4.0 has bug in optimizer and it causes problem in valgrind.
	std::uint64_t signature = 0;
	if (!get4Byte(metadataHeaderAddress, signature) || signature != MetadataHeaderSignature)
	{
		return;
	}

	std::uint64_t majorVersion, minorVersion, versionLength;
	if (!get2Byte(metadataHeaderAddress + 4, majorVersion)
		|| !get2Byte(metadataHeaderAddress + 6, minorVersion)
		|| !get2Byte(metadataHeaderAddress + 12, versionLength))
	{
		return;
	}

	std::string version;
	if (!getNTBS(metadataHeaderAddress + 16, version, versionLength))
	{
		return;
	}

	auto metadataHeaderStreamsHeader = metadataHeaderAddress + 16 + versionLength;

	std::uint64_t flags, streamCount;
	if (!get1Byte(metadataHeaderStreamsHeader, flags)
		|| !get2Byte(metadataHeaderStreamsHeader + 2, streamCount))
	{
		return;
	}

	metadataHeader = std::make_unique<MetadataHeader>();
	metadataHeader->setAddress(metadataHeaderAddress - formatParser->getImageBaseAddress());
	metadataHeader->setMajorVersion(majorVersion);
	metadataHeader->setMinorVersion(minorVersion);
	metadataHeader->setVersion(version);
	metadataHeader->setFlags(flags);

	auto currentAddress = metadataHeaderStreamsHeader + 4;
	for (std::uint64_t i = 0; i < streamCount; ++i)
	{
		std::uint64_t streamOffset, streamSize;
		std::string streamName;

		if (!get4Byte(currentAddress, streamOffset)
			|| !get4Byte(currentAddress + 4, streamSize)
			|| !getNTBS(currentAddress + 8, streamName))
		{
			return;
		}

		if (streamName == "#~" || streamName == "#-")
			parseMetadataStream(metadataHeaderAddress, streamOffset, streamSize);
		else if (streamName == "#Blob")
			parseBlobStream(metadataHeaderAddress, streamOffset, streamSize);
		else if (streamName == "#GUID")
			parseGuidStream(metadataHeaderAddress, streamOffset, streamSize);
		else if (streamName == "#Strings")
			parseStringStream(metadataHeaderAddress, streamOffset, streamSize);
		else if (streamName == "#US")
			parseUserStringStream(metadataHeaderAddress, streamOffset, streamSize);

		// Round-up to the nearest higher multiple of 4
		currentAddress += 8 + ((streamName.length() + 4) & ~3);
	}

	detectModuleVersionId();
	detectTypeLibId();
	detectDotnetTypes();
}

/**
 * Verifies signature of PE file using PKCS7.
 * @param p7 PKCS7 structure.
 * @return @c true if signature is valid, otherwise @c false.
 */
bool PeFormat::verifySignature(PKCS7 *p7)
{
	// At first, verify that there are data in place where Microsoft Code Signing should be present
	if (!p7->d.sign->contents->d.other)
		return false;

	// We need this because PKCS7_verify() looks up algorithms and without this, tables are empty
	OpenSSL_add_all_algorithms();
	SCOPE_EXIT {
		EVP_cleanup();
	};

	// First, check whether the hash written in ContentInfo matches the hash of the whole file
	auto contentInfoPtr = p7->d.sign->contents->d.other->value.sequence->data;
	auto contentInfoLen = p7->d.sign->contents->d.other->value.sequence->length;
	std::vector<std::uint8_t> contentInfoData(contentInfoPtr, contentInfoPtr + contentInfoLen);
	auto contentInfo = Asn1Item::parse(contentInfoData);
	if (!contentInfo->isSequence())
		return false;

	auto digest = std::static_pointer_cast<Asn1Sequence>(contentInfo)->getElement(1);
	if (digest == nullptr || !digest->isSequence())
		return false;

	auto digestSeq = std::static_pointer_cast<Asn1Sequence>(digest);
	if (digestSeq->getNumberOfElements() != 2)
		return false;

	auto digestAlgo = digestSeq->getElement(0);
	auto digestValue = digestSeq->getElement(1);
	if (!digestAlgo->isSequence() || !digestValue->isOctetString())
		return false;

	auto digestAlgoSeq = std::static_pointer_cast<Asn1Sequence>(digestAlgo);
	if (digestAlgoSeq->getNumberOfElements() == 0)
		return false;

	auto digestAlgoOID = digestAlgoSeq->getElement(0);
	if (!digestAlgoOID->isObject())
		return false;

	auto digestAlgoOIDStr = std::static_pointer_cast<Asn1Object>(digestAlgoOID)->getIdentifier();

	retdec::crypto::HashAlgorithm algorithm;
	if (digestAlgoOIDStr == DigestAlgorithmOID_Sha1)
		algorithm = retdec::crypto::HashAlgorithm::Sha1;
	else if (digestAlgoOIDStr == DigestAlgorithmOID_Sha256)
		algorithm = retdec::crypto::HashAlgorithm::Sha256;
	else if (digestAlgoOIDStr == DigestAlgorithmOID_Md5)
		algorithm = retdec::crypto::HashAlgorithm::Md5;
	else
	{
		EVP_cleanup();
		return false;
	}

	auto storedHash = std::static_pointer_cast<Asn1OctetString>(digestValue)->getString();
	auto calculatedHash = calculateDigest(algorithm);
	if (storedHash != calculatedHash)
	{
		EVP_cleanup();
		return false;
	}

	auto contentData = contentInfo->getContentData();
	auto contentBio = std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new_mem_buf(contentData.data(), contentData.size()), &BIO_free);
	auto emptyTrustStore = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>(X509_STORE_new(), &X509_STORE_free);
	if (PKCS7_verify(p7, p7->d.sign->cert, emptyTrustStore.get(), contentBio.get(), nullptr, PKCS7_NOVERIFY) == 0)
		return false;

	return true;
}

/**
 * Returns ranges that are used for digest calculation. This digest is used for signature verification.
 * Range is represented in form of tuple where first element is pointer to the beginning of the range and second is size of the range.
 * @return Ranges used for digest process.
 */
std::vector<std::tuple<const std::uint8_t*, std::size_t>> PeFormat::getDigestRanges() const
{
	std::vector<std::tuple<const std::uint8_t*, std::size_t>> result;
	std::size_t checksumFileOffset = formatParser->getChecksumFileOffset();
	std::size_t secDirFileOffset = formatParser->getSecurityDirFileOffset(); // offset of security directory record in PE header
	std::size_t secDirOffset = formatParser->getSecurityDirRva();
	std::size_t secDirSize = formatParser->getSecurityDirSize();

	// To prevent crashes on unordinary binaries, we need to sort these offsets (together with sizes, but they are unimportant for sorting)
	// Usually, checksum is first, then security directory header and then security directory
	// There are a few binaries where this order is not followed
	std::vector<std::pair<std::size_t, std::size_t>> offsets = { std::make_pair(checksumFileOffset, 4), std::make_pair(secDirFileOffset, 8), std::make_pair(secDirOffset, secDirSize) };
	std::sort(offsets.begin(), offsets.end(), [](const auto& lhs, const auto& rhs) {
			return lhs.first < rhs.first;
		});

	std::size_t lastOffset = 0;
	for (auto& offsetSize : offsets)
	{
		// If the length of the range is bigger than the amount of data we have available, then sanitize the length
		if (offsetSize.second > bytes.size())
			offsetSize.second = bytes.size();

		// If the range overlaps the end of the file, then sanitize the length
		if (offsetSize.first + offsetSize.second > bytes.size())
			offsetSize.second = bytes.size() - offsetSize.first;

		// This offsetSize is completely covered by the last offset so ignore it
		if (offsetSize.first + offsetSize.second <= lastOffset)
			continue;

		// This offsetSize is partially covered by the last offset, so shrink it
		// Shrunk offsetSize begins where the last offset ended
		if (offsetSize.first <= lastOffset)
		{
			offsetSize.second = lastOffset - offsetSize.first;
			offsetSize.first = lastOffset;
		}

		result.emplace_back(bytes.data() + lastOffset, offsetSize.first - lastOffset);
		lastOffset = offsetSize.first + offsetSize.second;
	}

	// Finish off the data if the last offset didn't end at the end of all data
	if (lastOffset != bytes.size())
		result.emplace_back(bytes.data() + lastOffset, bytes.size() - lastOffset);

	return result;
}

/**
 * Calculates the digest using selected hash algorithm.
 * @param hashType Algorithm to use.
 * @return Hex string of hash.
 */
std::string PeFormat::calculateDigest(retdec::crypto::HashAlgorithm hashType) const
{
	retdec::crypto::HashContext hashCtx;
	if (!hashCtx.init(hashType))
		return {};

	auto digestRanges = getDigestRanges();
	for (const auto& range : digestRanges)
	{
		const std::uint8_t* data = std::get<0>(range);
		std::size_t size = std::get<1>(range);

		if (!hashCtx.addData(data, size))
			return {};
	}

	return hashCtx.getHash();
}

/**
 * Parses .NET metadata stream.
 * @param baseAddress Base address of .NET metadata header.
 * @param offset Offset of metadata stream.
 * @param size Size of stream.
 */
void PeFormat::parseMetadataStream(std::uint64_t baseAddress, std::uint64_t offset, std::uint64_t size)
{
	const std::uint64_t metadataStreamHeaderSize = 24;
	if (size <= metadataStreamHeaderSize)
	{
		return;
	}

	metadataStream = std::make_unique<MetadataStream>(offset, size);
	auto address = baseAddress + offset;

	std::uint64_t majorVersion, minorVersion, heapOffsetSizes, valid, sorted;
	if (!get1Byte(address + 4, majorVersion)
		|| !get1Byte(address + 5, minorVersion)
		|| !get1Byte(address + 6, heapOffsetSizes)
		|| !get8Byte(address + 8, valid)
		|| !get8Byte(address + 16, sorted))
	{
		return;
	}

	metadataStream->setMajorVersion(majorVersion);
	metadataStream->setMinorVersion(minorVersion);

	// 'heapOffsetSizes' define whether we should use word or dword for indexes into different streams
	metadataStream->setStringStreamIndexSize(heapOffsetSizes & 0x01 ? 4 : 2);
	metadataStream->setGuidStreamIndexSize(heapOffsetSizes & 0x02 ? 4 : 2);
	metadataStream->setBlobStreamIndexSize(heapOffsetSizes & 0x04 ? 4 : 2);

	// Tables that are present in the stream are marked with bit 1 in 'valid' attribute
	// At first we need to create all tables with their sizes because we don't know how many of them is there,
	// so we don't know where to start to parse table content.
	std::uint64_t currentAddress = address + metadataStreamHeaderSize;
	for (std::size_t i = 0; i < 64; ++i)
	{
		if ((valid >> i) & 1)
		{
			std::uint64_t tableSize;
			if (!get4Byte(currentAddress, tableSize))
			{
				return;
			}

			// If the size of the metadata table would be larger than there are data available, we just end. This must be corrupted.
			if (tableSize > getLoadedFileLength())
			{
				return;
			}

			metadataStream->addMetadataTable(static_cast<MetadataTableType>(i), tableSize);
			currentAddress += 4;
		}
	}

	for (std::size_t i = 0; i < 64; ++i)
	{
		auto table = metadataStream->getMetadataTable(static_cast<MetadataTableType>(i));
		if (table == nullptr)
		{
			continue;
		}

		switch (table->getType())
		{
			case MetadataTableType::Module:
				parseMetadataTable<DotnetModule>(table, currentAddress);
				break;
			case MetadataTableType::TypeRef:
				parseMetadataTable<TypeRef>(table, currentAddress);
				break;
			case MetadataTableType::TypeDef:
				parseMetadataTable<TypeDef>(table, currentAddress);
				break;
			case MetadataTableType::FieldPtr:
				parseMetadataTable<FieldPtr>(table, currentAddress);
				break;
			case MetadataTableType::Field:
				parseMetadataTable<Field>(table, currentAddress);
				break;
			case MetadataTableType::MethodPtr:
				parseMetadataTable<MethodPtr>(table, currentAddress);
				break;
			case MetadataTableType::MethodDef:
				parseMetadataTable<MethodDef>(table, currentAddress);
				break;
			case MetadataTableType::ParamPtr:
				parseMetadataTable<ParamPtr>(table, currentAddress);
				break;
			case MetadataTableType::Param:
				parseMetadataTable<Param>(table, currentAddress);
				break;
			case MetadataTableType::InterfaceImpl:
				parseMetadataTable<InterfaceImpl>(table, currentAddress);
				break;
			case MetadataTableType::MemberRef:
				parseMetadataTable<MemberRef>(table, currentAddress);
				break;
			case MetadataTableType::Constant:
				parseMetadataTable<Constant>(table, currentAddress);
				break;
			case MetadataTableType::CustomAttribute:
				parseMetadataTable<CustomAttribute>(table, currentAddress);
				break;
			case MetadataTableType::FieldMarshal:
				parseMetadataTable<FieldMarshal>(table, currentAddress);
				break;
			case MetadataTableType::DeclSecurity:
				parseMetadataTable<DeclSecurity>(table, currentAddress);
				break;
			case MetadataTableType::ClassLayout:
				parseMetadataTable<ClassLayout>(table, currentAddress);
				break;
			case MetadataTableType::FieldLayout:
				parseMetadataTable<FieldLayout>(table, currentAddress);
				break;
			case MetadataTableType::StandAloneSig:
				parseMetadataTable<StandAloneSig>(table, currentAddress);
				break;
			case MetadataTableType::EventMap:
				parseMetadataTable<EventMap>(table, currentAddress);
				break;
			case MetadataTableType::Event:
				parseMetadataTable<Event>(table, currentAddress);
				break;
			case MetadataTableType::PropertyMap:
				parseMetadataTable<PropertyMap>(table, currentAddress);
				break;
			case MetadataTableType::PropertyPtr:
				parseMetadataTable<PropertyPtr>(table, currentAddress);
				break;
			case MetadataTableType::Property:
				parseMetadataTable<Property>(table, currentAddress);
				break;
			case MetadataTableType::MethodSemantics:
				parseMetadataTable<MethodSemantics>(table, currentAddress);
				break;
			case MetadataTableType::MethodImpl:
				parseMetadataTable<MethodImpl>(table, currentAddress);
				break;
			case MetadataTableType::ModuleRef:
				parseMetadataTable<ModuleRef>(table, currentAddress);
				break;
			case MetadataTableType::TypeSpec:
				parseMetadataTable<TypeSpec>(table, currentAddress);
				break;
			case MetadataTableType::ImplMap:
				parseMetadataTable<ImplMap>(table, currentAddress);
				break;
			case MetadataTableType::FieldRVA:
				parseMetadataTable<FieldRVA>(table, currentAddress);
				break;
			case MetadataTableType::ENCLog:
				parseMetadataTable<ENCLog>(table, currentAddress);
				break;
			case MetadataTableType::ENCMap:
				parseMetadataTable<ENCMap>(table, currentAddress);
				break;
			case MetadataTableType::Assembly:
				parseMetadataTable<Assembly>(table, currentAddress);
				break;
			case MetadataTableType::AssemblyProcessor:
				parseMetadataTable<AssemblyProcessor>(table, currentAddress);
				break;
			case MetadataTableType::AssemblyOS:
				parseMetadataTable<AssemblyOS>(table, currentAddress);
				break;
			case MetadataTableType::AssemblyRef:
				parseMetadataTable<AssemblyRef>(table, currentAddress);
				break;
			case MetadataTableType::AssemblyRefProcessor:
				parseMetadataTable<AssemblyRefProcessor>(table, currentAddress);
				break;
			case MetadataTableType::AssemblyRefOS:
				parseMetadataTable<AssemblyRefOS>(table, currentAddress);
				break;
			case MetadataTableType::File:
				parseMetadataTable<File>(table, currentAddress);
				break;
			case MetadataTableType::ExportedType:
				parseMetadataTable<ExportedType>(table, currentAddress);
				break;
			case MetadataTableType::ManifestResource:
				parseMetadataTable<ManifestResource>(table, currentAddress);
				break;
			case MetadataTableType::NestedClass:
				parseMetadataTable<NestedClass>(table, currentAddress);
				break;
			case MetadataTableType::GenericParam:
				parseMetadataTable<GenericParam>(table, currentAddress);
				break;
			case MetadataTableType::GenericParamContstraint:
				parseMetadataTable<GenericParamContstraint>(table, currentAddress);
				break;
			default:
				break;
		}
	}
}

/**
 * Parses .NET blob stream.
 * @param baseAddress Base address of .NET metadata header.
 * @param offset Offset of blob stream.
 * @param size Size of stream.
 */
void PeFormat::parseBlobStream(std::uint64_t baseAddress, std::uint64_t offset, std::uint64_t size)
{
	blobStream = std::make_unique<BlobStream>(offset, size);
	auto address = baseAddress + offset;

	std::vector<std::uint8_t> elementData;
	std::uint64_t length, lengthSize;

	std::size_t inStreamOffset = 0;
	while (inStreamOffset < size)
	{
		// First byte is length of next element in the blob
		lengthSize = 1;
		if (!get1Byte(address + inStreamOffset, length))
		{
			return;
		}

		// 2-byte length encoding if the length is 10xxxxxx
		if ((length & 0xC0) == 0x80)
		{
			if (!get2Byte(address + inStreamOffset, length, Endianness::BIG))
			{
				return;
			}

			length &= ~0xC000;
			lengthSize = 2;
		}
		// 4-byte length encoding if the length is 110xxxxx
		else if ((length & 0xE0) == 0xC0)
		{
			if (!get4Byte(address + inStreamOffset, length, Endianness::BIG))
			{
				return;
			}

			length &= ~0xE0000000;
			lengthSize = 4;
		}

		// Read only if length is greater than 0
		elementData.clear();
		if (length > 0 && !getXBytes(address + inStreamOffset + lengthSize, length, elementData))
		{
			return;
		}

		blobStream->addElement(inStreamOffset, elementData);
		inStreamOffset += lengthSize + length;
	}
}

/**
 * Parses .NET GUID stream.
 * @param baseAddress Base address of .NET metadata header.
 * @param offset Offset of GUID stream.
 * @param size Size of stream.
 */
void PeFormat::parseGuidStream(std::uint64_t baseAddress, std::uint64_t offset, std::uint64_t size)
{
	std::vector<std::uint8_t> guids;
	if (!getXBytes(baseAddress + offset, size, guids))
	{
		return;
	}

	guidStream = std::make_unique<GuidStream>(offset, size);
	guidStream->addGuids(guids);
}

/**
 * Parses .NET string stream.
 * @param baseAddress Base address of .NET metadata header.
 * @param offset Offset of string stream.
 * @param size Size of stream.
 */
void PeFormat::parseStringStream(std::uint64_t baseAddress, std::uint64_t offset, std::uint64_t size)
{
	stringStream = std::make_unique<StringStream>(offset, size);
	auto address = baseAddress + offset;

	// First string is always empty, so we just skip it
	std::uint64_t currentOffset = 1;
	while (currentOffset < size)
	{
		std::string string;
		if (!getNTBS(address + currentOffset, string))
		{
			currentOffset += 1;
			continue;
		}

		stringStream->addString(currentOffset, string);

		// +1 for null-terminator
		currentOffset += 1 + string.length();
	}
}

/**
 * Parses .NET user string stream.
 * @param baseAddress Base address of .NET metadata header.
 * @param offset Offset of user string stream.
 * @param size Size of stream.
 */
void PeFormat::parseUserStringStream(std::uint64_t/* baseAddress*/, std::uint64_t offset, std::uint64_t size)
{
	userStringStream = std::make_unique<UserStringStream>(offset, size);
}

/**
 * Parses single metadata table from metadata stream.
 * @param table Table where to insert data.
 * @param address Address of table data.
 */
template <typename T>
void PeFormat::parseMetadataTable(BaseMetadataTable* table, std::uint64_t& address)
{
	auto specTable = static_cast<MetadataTable<T>*>(table);
	for (std::size_t i = 0; i < table->getSize(); ++i)
	{
		try
		{
			T row;
			row.load(this, metadataStream.get(), address);
			specTable->addRow(std::move(row));
		}
		catch (const InvalidDotnetRecordError&)
		{
			break;
		}
	}
}

/**
 * Detects Module Version ID (GUID) out of .NET tables.
 */
void PeFormat::detectModuleVersionId()
{
	moduleVersionId.clear();

	if (!metadataStream || !guidStream || !metadataStream->hasTable(MetadataTableType::Module))
	{
		return;
	}

	auto moduleTable = static_cast<const MetadataTable<DotnetModule>*>(metadataStream->getMetadataTable(MetadataTableType::Module));
	if (!moduleTable || moduleTable->getNumberOfRows() < 1)
	{
		return;
	}

	auto row = moduleTable->getRow(1);
	moduleVersionId = guidStream->getGuidString(row->mvId.getIndex());
}

/**
 * Detects TypeLib ID (GUID) out of .NET tables.
 */
void PeFormat::detectTypeLibId()
{
	typeLibId.clear();
	if (!metadataStream || !stringStream || !blobStream)
	{
		return;
	}

	auto typeRefTable = static_cast<const MetadataTable<TypeRef>*>(metadataStream->getMetadataTable(MetadataTableType::TypeRef));
	auto memberRefTable = static_cast<const MetadataTable<MemberRef>*>(metadataStream->getMetadataTable(MetadataTableType::MemberRef));
	auto customAttributeTable = static_cast<const MetadataTable<CustomAttribute>*>(metadataStream->getMetadataTable(MetadataTableType::CustomAttribute));
	auto assemblyRefTable = static_cast<const MetadataTable<AssemblyRef>*>(metadataStream->getMetadataTable(MetadataTableType::AssemblyRef));
	if (!typeRefTable || !memberRefTable || !customAttributeTable || !assemblyRefTable)
	{
		return;
	}

	// First find the index of GuidAttribute type reference in TypeRef table, which has ResolutionScope as mscorlib
	std::size_t guidTypeRef = typeRefTable->getNumberOfRows();
	for (std::size_t i = 1; i <= typeRefTable->getNumberOfRows(); ++i)
	{
		auto typeRefRow = typeRefTable->getRow(i);
		auto assemblyRef = assemblyRefTable->getRow(typeRefRow->resolutionScope.getIndex());
		if (!assemblyRef)
		{
			continue;
		}

		std::string assemblyName;
		if (!stringStream->getString(assemblyRef->name.getIndex(), assemblyName) || assemblyName != "mscorlib")
		{
			continue;
		}

		std::string typeName;
		if (stringStream->getString(typeRefRow->typeName.getIndex(), typeName) && typeName == "GuidAttribute")
		{
			guidTypeRef = i;
			break;
		}
	}

	// No GuidAttribute type reference, that means no TypeLib
	if (guidTypeRef == typeRefTable->getNumberOfRows())
	{
		return;
	}

	// Then try to find the MemberRef which refers to this TypeRef
	std::size_t guidMemberRef = memberRefTable->getNumberOfRows();
	for (std::size_t i = 1; i <= memberRefTable->getNumberOfRows(); ++i)
	{
		auto memberRefRow = memberRefTable->getRow(i);
		if (memberRefRow->classType.getIndex() == guidTypeRef)
		{
			guidMemberRef = i;
			break;
		}
	}

	// No MemberRef reference to type reference, that means no TypeLib
	if (guidMemberRef == memberRefTable->getNumberOfRows())
	{
		return;
	}

	std::regex guidRegex("[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}", std::regex::icase | std::regex::ECMAScript);

	// As last, try to find CustomAttribute with type referring to MemberRef
	for (std::size_t i = 1; i <= customAttributeTable->getNumberOfRows(); ++i)
	{
		auto customAttributeRow = customAttributeTable->getRow(i);
		if (customAttributeRow->type.getIndex() == guidMemberRef)
		{
			// Its value is the TypeLib we are looking for
			auto typeLibData = blobStream->getElement(customAttributeRow->value.getIndex());
			if (typeLibData.size() < 3)
			{
				continue;
			}

			// Custom attributes contain one word 0x0001 at the beginning so we skip it,
			// followed by length of the string, which is GUID we are looking for
			auto length = typeLibData[2];
			typeLibId = retdec::utils::toLower(std::string(reinterpret_cast<const char*>(typeLibData.data() + 3), length));
			if (!std::regex_match(typeLibId, guidRegex))
			{
				typeLibId.clear();
				continue;
			}

			break;
		}
	}
}

/**
 * Detects and reconstructs .NET types such as classes, methods, fields, properties etc.
 */
void PeFormat::detectDotnetTypes()
{
	DotnetTypeReconstructor reconstructor(metadataStream.get(), stringStream.get(), blobStream.get());

	definedClasses.clear();
	importedClasses.clear();
	if (reconstructor.reconstruct())
	{
		definedClasses = reconstructor.getDefinedClasses();
		importedClasses = reconstructor.getReferencedClasses();
	}
}

/**
 * Detects possible metadata header structure. It first searches for metadata header signature
 * `0x424A5342`. If it finds this signature, it then tries to look further for possible stream names.
 *
 * @return Possible metadata header address, 0 if unsuccessful.
 */
std::uint64_t PeFormat::detectPossibleMetadataHeaderAddress() const
{
	const auto possibleStreamNames = { "#~", "#-", "#Strings", "#Blob", "#GUID", "#US" };

	bool metadataHeaderFound = false;
	std::uint64_t address = 0;
	std::uint64_t signature = 0;
	for (const auto* sec : sections)
	{
		address = sec->getAddress();

		for (std::uint64_t inSecAddress = address; !metadataHeaderFound && inSecAddress < sec->getEndAddress(); ++inSecAddress)
		{
			if (!get4Byte(inSecAddress, signature))
				break;

			if (signature == MetadataHeaderSignature)
			{
				std::uint64_t versionLength = 0;
				if (!get2Byte(inSecAddress + 12, versionLength))
					break;

				auto firstStreamNameAddress = inSecAddress
					+ 16 // skip metadata header fields
					+ versionLength // skip version string
					+ 4 // skip stream count
					+ 8; // skip offset and size of the first stream
				std::string streamName;
				if (!getNTBS(firstStreamNameAddress, streamName))
					break;

				if (std::any_of(possibleStreamNames.begin(), possibleStreamNames.end(),
							[&streamName](const auto& possibleStreamName) {
								return streamName == possibleStreamName;
							}))
				{
					metadataHeaderFound = true;
					address = inSecAddress;
					break;
				}
			}
		}

		if (metadataHeaderFound)
			break;
	}

	return metadataHeaderFound ? address : 0;
}

retdec::utils::Endianness PeFormat::getEndianness() const
{
	switch(formatParser->getMachineType())
	{
		case PELIB_IMAGE_FILE_MACHINE_I386:
		case PELIB_IMAGE_FILE_MACHINE_I486:
		case PELIB_IMAGE_FILE_MACHINE_PENTIUM:
		case PELIB_IMAGE_FILE_MACHINE_AMD64:
		case PELIB_IMAGE_FILE_MACHINE_R3000_LITTLE:
		case PELIB_IMAGE_FILE_MACHINE_R4000:
		case PELIB_IMAGE_FILE_MACHINE_R10000:
		case PELIB_IMAGE_FILE_MACHINE_WCEMIPSV2:
		case PELIB_IMAGE_FILE_MACHINE_MIPS16:
		case PELIB_IMAGE_FILE_MACHINE_MIPSFPU:
		case PELIB_IMAGE_FILE_MACHINE_MIPSFPU16:
		case PELIB_IMAGE_FILE_MACHINE_ARM:
		case PELIB_IMAGE_FILE_MACHINE_THUMB:
		case PELIB_IMAGE_FILE_MACHINE_ARMNT:
		case PELIB_IMAGE_FILE_MACHINE_ARM64:
		case PELIB_IMAGE_FILE_MACHINE_POWERPC:
		case PELIB_IMAGE_FILE_MACHINE_POWERPCFP:
			return Endianness::LITTLE;
		case PELIB_IMAGE_FILE_MACHINE_R3000_BIG:
			return Endianness::BIG;
		default:
			return Endianness::UNKNOWN;
	}
}

std::size_t PeFormat::getBytesPerWord() const
{
	switch(formatParser->getMachineType())
	{
		// Architecture::X86
		case PELIB_IMAGE_FILE_MACHINE_I386:
		case PELIB_IMAGE_FILE_MACHINE_I486:
		case PELIB_IMAGE_FILE_MACHINE_PENTIUM:
			return 4;

		// Architecture::X86_64
		case PELIB_IMAGE_FILE_MACHINE_AMD64:
			return 8;

		// Architecture::MIPS
		case PELIB_IMAGE_FILE_MACHINE_R3000_BIG:
		case PELIB_IMAGE_FILE_MACHINE_R3000_LITTLE:
			return 4;
		case PELIB_IMAGE_FILE_MACHINE_R4000:
			return (peClass == PEFILE64 ? 8 : 4);
		case PELIB_IMAGE_FILE_MACHINE_R10000:
			return 8;
		case PELIB_IMAGE_FILE_MACHINE_WCEMIPSV2:
			return 4;
		case PELIB_IMAGE_FILE_MACHINE_MIPS16:
			return 2;
		case PELIB_IMAGE_FILE_MACHINE_MIPSFPU:
			return 8;
		case PELIB_IMAGE_FILE_MACHINE_MIPSFPU16:
			return 2;

		// Architecture::ARM
		case PELIB_IMAGE_FILE_MACHINE_ARM:
		case PELIB_IMAGE_FILE_MACHINE_THUMB:
		case PELIB_IMAGE_FILE_MACHINE_ARMNT:
			return 4;
		case PELIB_IMAGE_FILE_MACHINE_ARM64:
			return 8;

		// Architecture::POWERPC
		case PELIB_IMAGE_FILE_MACHINE_POWERPC:
		case PELIB_IMAGE_FILE_MACHINE_POWERPCFP:
			return (peClass == PEFILE64 ? 8 : 4);

		// unsupported architecture
		default:
			return 0;
	}
}

bool PeFormat::hasMixedEndianForDouble() const
{
	return false;
}

/**
 * Get declared length of file. This length may be shorter or longer than real length of file.
 * @return Declared length of file
 */
std::size_t PeFormat::getDeclaredFileLength() const
{
	std::size_t declSize = FileFormat::getDeclaredFileLength();
	if(getNumberOfCoffSymbols() && getCoffSymbolTableOffset())
	{
		const std::size_t symTabMaxOffset = getCoffSymbolTableOffset() + (getNumberOfCoffSymbols() * PELIB_IMAGE_SIZEOF_COFF_SYMBOL);
		declSize = std::max(declSize, symTabMaxOffset);
	}

	return declSize + getSizeOfStringTable();
}

bool PeFormat::areSectionsValid() const
{
	return true;
}

bool PeFormat::isObjectFile() const
{
	return false;
}

bool PeFormat::isDll() const
{
	return formatParser->isDll();
}

bool PeFormat::isExecutable() const
{
	return !isDll();
}

bool PeFormat::getMachineCode(unsigned long long &result) const
{
	result = formatParser->getMachineType();
	return true;
}

bool PeFormat::getAbiVersion(unsigned long long &result) const
{
	// not in PE files
	static_cast<void>(result);
	return false;
}

bool PeFormat::getImageBaseAddress(unsigned long long &imageBase) const
{
	imageBase = formatParser->getImageBaseAddress();
	return true;
}

bool PeFormat::getEpAddress(unsigned long long &result) const
{
	return formatParser->getEpAddress(result);
}

bool PeFormat::getEpOffset(unsigned long long &epOffset) const
{
	return formatParser->getEpOffset(epOffset);
}

Architecture PeFormat::getTargetArchitecture() const
{
	switch(formatParser->getMachineType())
	{
		case PELIB_IMAGE_FILE_MACHINE_I386:
		case PELIB_IMAGE_FILE_MACHINE_I486:
		case PELIB_IMAGE_FILE_MACHINE_PENTIUM:
			return Architecture::X86;
		case PELIB_IMAGE_FILE_MACHINE_AMD64:
			return Architecture::X86_64;
		case PELIB_IMAGE_FILE_MACHINE_R3000_BIG:
		case PELIB_IMAGE_FILE_MACHINE_R3000_LITTLE:
		case PELIB_IMAGE_FILE_MACHINE_R4000:
		case PELIB_IMAGE_FILE_MACHINE_R10000:
		case PELIB_IMAGE_FILE_MACHINE_WCEMIPSV2:
		case PELIB_IMAGE_FILE_MACHINE_MIPS16:
		case PELIB_IMAGE_FILE_MACHINE_MIPSFPU:
		case PELIB_IMAGE_FILE_MACHINE_MIPSFPU16:
			return Architecture::MIPS;
		case PELIB_IMAGE_FILE_MACHINE_ARM:
		case PELIB_IMAGE_FILE_MACHINE_THUMB:
		case PELIB_IMAGE_FILE_MACHINE_ARMNT:
		case PELIB_IMAGE_FILE_MACHINE_ARM64:
			return Architecture::ARM;
		case PELIB_IMAGE_FILE_MACHINE_POWERPC:
		case PELIB_IMAGE_FILE_MACHINE_POWERPCFP:
			return Architecture::POWERPC;
		default:
			return Architecture::UNKNOWN;
	}
}

std::size_t PeFormat::getDeclaredNumberOfSections() const
{
	return formatParser->getDeclaredNumberOfSections();
}

std::size_t PeFormat::getDeclaredNumberOfSegments() const
{
	return 0;
}

std::size_t PeFormat::getSectionTableOffset() const
{
	std::size_t res = getPeHeaderOffset() + formatParser->getSizeOfPeSignature() + PELIB_IMAGE_FILE_HEADER::size() + getOptionalHeaderSize();
	if(res >= getFileLength())
	{
		res = getPeHeaderOffset() + formatParser->getLoadedSizeOfNtHeaders();
	}

	return res;
}

std::size_t PeFormat::getSectionTableEntrySize() const
{
	return PELIB_IMAGE_SECTION_HEADER::size();
}

std::size_t PeFormat::getSegmentTableOffset() const
{
	return 0;
}

std::size_t PeFormat::getSegmentTableEntrySize() const
{
	return 0;
}

/**
 * Get size of MZ header
 * @return Size of MZ header
 */
std::size_t PeFormat::getMzHeaderSize() const
{
	return mzHeader.size();
}

/**
 * Get size of optional header
 * @return Size of optional header
 */
std::size_t PeFormat::getOptionalHeaderSize() const
{
	return formatParser->getOptionalHeaderSize();
}

/**
 * Get offset of PE signature
 * @return Offset of PE signature
 *
 * In some cases (e.g. FSG packer), offset of PE signature may be inside MZ header and
 * therefore this method may return lesser number that method @a getMzHeaderSize().
 */
std::size_t PeFormat::getPeHeaderOffset() const
{
	return mzHeader.getAddressOfPeHeader();
}

/**
 * Get offset of COFF symbol table
 * @return Offset of COFF symbol table
 */
std::size_t PeFormat::getCoffSymbolTableOffset() const
{
	return formatParser->getCoffSymbolTableOffset();
}

/**
 * Get number of symbols in COFF symbol table
 * @return Number of symbols in COFF symbol table
 */
std::size_t PeFormat::getNumberOfCoffSymbols() const
{
	return formatParser->getNumberOfCoffSymbols();
}

/**
 * Get size in bytes of string table
 * @return Size in bytes of string table
 */
std::size_t PeFormat::getSizeOfStringTable() const
{
	return file->coffSymTab().getSizeOfStringTable();
}

/**
 * Get major version of used linker
 * @return Major version of used linker
 */
std::size_t PeFormat::getMajorLinkerVersion() const
{
	return formatParser->getMajorLinkerVersion();
}

/**
 * Get minor version of used linker
 * @return Minor version of used linker
 */
std::size_t PeFormat::getMinorLinkerVersion() const
{
	return formatParser->getMinorLinkerVersion();
}

/**
 * Get file flags
 * @return File flags as number
 */
std::size_t PeFormat::getFileFlags() const
{
	return formatParser->getFileFlags();
}

/**
 * Get time stamp
 * @return File time stamp
 */
std::size_t PeFormat::getTimeStamp() const
{
	return formatParser->getTimeStamp();
}

/**
 * Get file alignment
 * @return File alignment
 */
std::size_t PeFormat::getFileAlignment() const
{
	return formatParser->getFileAlignment();
}

/**
 * Get section alignment
 * @return Section alignment
 */
std::size_t PeFormat::getSectionAlignment() const
{
	return formatParser->getSectionAlignment();
}

/**
 * Get size of image
 * @return Size of image
 */
std::size_t PeFormat::getSizeOfImage() const
{
	return formatParser->getSizeOfImage();
}

/**
 * Get file checksum
 * @return File checksum
 */
std::size_t PeFormat::getChecksum() const
{
	return formatParser->getChecksum();
}

/**
 * Get size of the stack to reserve
 * @return Size of the stack to reserve
 */
std::size_t PeFormat::getSizeOfStackReserve() const
{
	return formatParser->getSizeOfStackReserve();
}

/**
 * Get size of the stack to commit
 * @return Size of the stack to commit
 */
std::size_t PeFormat::getSizeOfStackCommit() const
{
	return formatParser->getSizeOfStackCommit();
}

/**
 * Get size of the local heap space to reserve
 * @return Size of the local heap space to reserve
 */
std::size_t PeFormat::getSizeOfHeapReserve() const
{
	return formatParser->getSizeOfHeapReserve();
}

/**
 * Get size of the local heap space to commit
 * @return Size of the local heap space to commit
 */
std::size_t PeFormat::getSizeOfHeapCommit() const
{
	return formatParser->getSizeOfHeapCommit();
}

/**
 * Get number of data-directory entries in input file
 * @return Number of data-directory entries in input file
 */
std::size_t PeFormat::getNumberOfDataDirectories() const
{
	return formatParser->getStoredNumberOfDataDirectories();
}

/**
 * Get number of data-directory entries declared in the optional header
 * @return Number of data-directory entries declared in the optional header
 */
std::size_t PeFormat::getDeclaredNumberOfDataDirectories() const
{
	return formatParser->getDeclaredNumberOfDataDirectories();
}

/**
 * Get class of PE file
 * @return PeLib::PEFILE32 if file is 32-bit PE file, PeLib::PEFILE64 if file is
 *    64-bit PE file or any other value otherwise
 */
int PeFormat::getPeClass() const
{
	return peClass;
}

/**
 * Check if input file contains CIL/.NET code
 * @return @c true if input file contains CIL/.NET code, @c false otherwise
 */
bool PeFormat::isDotNet() const
{
	return clrHeader != nullptr || metadataHeader != nullptr;
}

/**
 * Check if input file contains packed CIL/.NET code
 * @return @c true if input file contains packed CIL/.NET code, @c false otherwise
 */
bool PeFormat::isPackedDotNet() const
{
	if(isDotNet())
	{
		return false;
	}

	return importTable
		&& importTable->getNumberOfLibraries() == 1
		&& importTable->getNumberOfImportsInLibraryCaseInsensitive("mscoree.dll");
}

/**
 * Check if input file original language is Visual Basic
 * @param version Into this parameter is stored version of Visual Basic, or @c 0 if
 *    version was not detected
 * @return @c true if input file original language is Visual Basic, @c false otherwise
 */
bool PeFormat::isVisualBasic(unsigned long long &version) const
{
	version = 0;
	return importTable && std::any_of(visualBasicLibrariesMap.begin(), visualBasicLibrariesMap.end(),
		[&] (const auto &item)
		{
			if(this->importTable->getNumberOfImportsInLibraryCaseInsensitive(item.first))
			{
				version = item.second;
				return true;
			}

			return false;
		}
	);
}

/**
 * Get DLL flags
 * @param dllFlags Into this parameter DLL flags will be stored
 * @return @c true if file is DLL and flags are successfully detected, @c false otherwise
 */
bool PeFormat::getDllFlags(unsigned long long &dllFlags) const
{
	return formatParser->getDllFlags(dllFlags);
}

/**
 * Get number of base relocation blocks
 * @param relocs Into this parameter the number of blocks is stored
 * @return @c true if number of blocks is successfully detected, @c false otherwise
 *
 * If function returns @c false, @a relocs is left unchanged
 */
bool PeFormat::getNumberOfBaseRelocationBlocks(unsigned long long &relocs) const
{
	unsigned long long addr, size;
	if(!getDataDirectoryRelative(PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC, addr, size) || !addr)
	{
		return false;
	}

	relocs = formatParser->getNumberOfRelocations();
	return true;
}

/**
 * Get number of relocations
 * @param relocs Into this parameter the number of relocations is stored
 * @return @c true if number of relocations is successfully detected, @c false otherwise
 *
 * If function returns @c false, @a relocs is left unchanged
 */
bool PeFormat::getNumberOfRelocations(unsigned long long &relocs) const
{
	unsigned long long blocks = 0;
	if(!getNumberOfBaseRelocationBlocks(blocks))
	{
		return false;
	}
	relocs = 0;

	for(unsigned long long i = 0; i < blocks; ++i)
	{
		relocs += formatParser->getNumberOfRelocationData(i);
	}

	return true;
}

/**
 * Get data directory
 * @param index Index of selected directory
 * @param relAddr Into this parameter is stored relative virtual address of directory
 * @param size Into this parameter is stored size of directory
 * @return @c true if index of selected directory is valid, @c false otherwise
 *
 * If method returns @c false, @a relAddr and @a size are left unchanged.
 */
bool PeFormat::getDataDirectoryRelative(unsigned long long index, unsigned long long &relAddr, unsigned long long &size) const
{
	return formatParser->getDataDirectoryRelative(index, relAddr, size);
}

/**
 * Get data directory
 * @param index Index of selected directory
 * @param absAddr Into this parameter is stored absolute virtual address of directory
 * @param size Into this parameter is stored size of directory
 * @return @c true if index of selected directory is valid, @c false otherwise
 *
 * If method returns @c false, @a absAddr and @a size are left unchanged.
 */
bool PeFormat::getDataDirectoryAbsolute(unsigned long long index, unsigned long long &absAddr, unsigned long long &size) const
{
	return formatParser->getDataDirectoryAbsolute(index, absAddr, size);
}

/**
 * Get information about section with name @a secName
 * @param secName Name of section
 * @return Pointer to section or @c nullptr if section was not found
 *
 * If file has more sections with name equal to @a secName, then is returned first such section.
 */
const PeCoffSection* PeFormat::getPeSection(const std::string &secName) const
{
	return dynamic_cast<const PeCoffSection*>(getSection(secName));
}

/**
 * Get information about section with index @a secIndex
 * @param secIndex Index of section (indexed from 0)
 * @return Pointer to section or @c nullptr if section was not detected
 */
const PeCoffSection* PeFormat::getPeSection(unsigned long long secIndex) const
{
	return dynamic_cast<const PeCoffSection*>(getSection(secIndex));
}

const CLRHeader* PeFormat::getCLRHeader() const
{
	return clrHeader.get();
}

const MetadataHeader* PeFormat::getMetadataHeader() const
{
	return metadataHeader.get();
}

const MetadataStream* PeFormat::getMetadataStream() const
{
	return metadataStream.get();
}

const StringStream* PeFormat::getStringStream() const
{
	return stringStream.get();
}

const BlobStream* PeFormat::getBlobStream() const
{
	return blobStream.get();
}

const GuidStream* PeFormat::getGuidStream() const
{
	return guidStream.get();
}

const UserStringStream* PeFormat::getUserStringStream() const
{
	return userStringStream.get();
}

const std::string& PeFormat::getModuleVersionId() const
{
	return moduleVersionId;
}

const std::string& PeFormat::getTypeLibId() const
{
	return typeLibId;
}

const std::vector<std::shared_ptr<DotnetClass>>& PeFormat::getDefinedDotnetClasses() const
{
	return definedClasses;
}

const std::vector<std::shared_ptr<DotnetClass>>& PeFormat::getImportedDotnetClasses() const
{
	return importedClasses;
}

} // namespace fileformat
} // namespace retdec
