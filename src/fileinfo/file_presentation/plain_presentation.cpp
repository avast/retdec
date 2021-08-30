/**
 * @file src/fileinfo/file_presentation/plain_presentation.cpp
 * @brief Plain text presentation class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/certificate_table/certificate.h"
#include "retdec/fileformat/types/certificate_table/certificate_table.h"
#include "retdec/utils/string.h"
#include "retdec/utils/io/log.h"
#include "retdec/utils/version.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/format.h"
#include "fileinfo/file_presentation/getters/plain_getters.h"
#include "fileinfo/file_presentation/plain_presentation.h"
#include <string>

using namespace retdec::utils;
using namespace retdec::utils::io;
using namespace retdec::cpdetect;
using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

namespace
{

const std::size_t MAX_LINE_LENGTH = 120;

/**
 * Present title
 * @param title Title of presented structure
 */
void presentTitle(const std::string &title)
{
	const auto pos = title.find_first_not_of(" ");
	if(pos != std::string::npos)
	{
		Log::info() << "\n\n" << title << "\n" << std::string(pos, ' ') << std::string(title.length() - pos, '-') << "\n";
	}
}

/**
 * Present title
 * @param getter Instance of IterativeGetter class
 */
void presentTitle(const IterativeGetter &getter)
{
	std::string title;
	getter.getTitle(title);
	presentTitle(title);
}

/**
 * Simple presentation of information
 * @param desc Descriptors of information
 * @param info Vector of information
 * @param space Print empty line before first item
 */
void presentSimple(const std::vector<std::string> &desc, const std::vector<std::string> &info, bool space)
{
	for(std::size_t i = 0, e = std::min(desc.size(), info.size()); i < e; ++i)
	{
		if(!desc[i].empty() && !info[i].empty())
		{
			if(space)
			{
				Log::info() << "\n";
				space = false;
			}
			Log::info() << desc[i] << info[i] << "\n";
		}
	}
}

/**
 * Present information from simple getter
 * @param getter Instance of SimpleGetter class
 * @param space Print empty line before first item
 */
void presentSimple(const SimpleGetter &getter, bool space)
{
	std::vector<std::string> desc, info;
	getter.loadInformation(desc, info);
	presentSimple(desc, info, space);
}

/**
 * Present information from simple getter with title
 * @param getter Instance of SimpleGetter class
 * @param space Print empty line before first item
 * @param title Title of presented information
 */
void presentSimple(const SimpleGetter &getter, bool space, const std::string &title)
{
	std::vector<std::string> desc, info;
	bool hasRecords = false;

	for(std::size_t i = 0, e = getter.loadInformation(desc, info); i < e; ++i)
	{
		if(!desc[i].empty() && !info[i].empty())
		{
			hasRecords = true;
			break;
		}
	}

	if(!hasRecords)
	{
		return;
	}

	presentTitle(title);
	presentSimple(desc, info, space);
}

/**
 * Get separator of iterative distribution getter
 * @param getter Instance of IterativeDistributionGetter class
 * @param separator Into this parameter is separator stored
 * @param structIndex Index of selected structure (indexed from 0)
 * @return Number of whitespaces before separator
 */
std::size_t getIterativeDistributionSeparator(const IterativeDistributionGetter &getter, std::string &separator, std::size_t structIndex)
{
	getter.getHeader(structIndex, separator);
	const auto pos = separator.find_first_not_of(" ");
	if(pos != std::string::npos)
	{
		separator = std::string(pos, ' ') + std::string(separator.length() - pos, '-');
		return pos;
	}
	else
	{
		separator = std::string(separator.length(), '-');
		return 0;
	}
}

/**
 * Present header of iterative distribution getter
 * @param getter Instance of IterativeDistributionGetter class
 * @param explanatory Print explanatory notes
 * @param structIndex Index of selected structure (indexed from 0)
 */
void presentIterativeDistributionHeader(const IterativeDistributionGetter &getter, bool explanatory, std::size_t structIndex)
{
	std::string header, separator;
	getter.getHeader(structIndex, header);
	const auto wSpaces = getIterativeDistributionSeparator(getter, separator, structIndex);
	Log::info() << "\n" << header << "\n" << separator << "\n";
	if(!explanatory)
	{
		return;
	}

	std::vector<std::string> desc, abbv;
	const std::size_t noOfDesc = getter.getHeaderDesc(structIndex, desc, abbv);
	std::vector<std::size_t> lens;
	std::size_t maxLen = 0;

	for(std::size_t i = 0; i < noOfDesc; ++i)
	{
		lens.push_back(abbv[i].length());
		maxLen = std::max(maxLen, lens.back());
	}

	for(std::size_t i = 0; i < noOfDesc; ++i)
	{
		if(abbv[i].find_first_not_of(" ") != std::string::npos && desc[i].find_first_not_of(" ") != std::string::npos)
		{
			Log::info() << std::string(wSpaces, ' ') << abbv[i] << std::string(maxLen - lens[i], ' ') << " - " << desc[i] << "\n";
		}
	}

	Log::info() << separator << "\n" << header << "\n" << separator << "\n";
}

/**
 * Present information from one structure of iterative distribution getter
 * @param getter Instance of IterativeDistributionGetter class
 * @param explanatory Print explanatory notes
 * @param structIndex Index of selected structure (indexed from 0).
 */
void presentIterativeDistributionStructure(const IterativeDistributionGetter &getter, bool explanatory, std::size_t structIndex)
{
	if(structIndex >= getter.getNumberOfStructures())
	{
		return;
	}

	std::vector<std::string> desc, info;
	const auto basicLen = getter.getBasicInfo(structIndex, desc, info);
	const auto records = getter.getNumberOfStoredRecords(structIndex);

	if(!basicLen && !records)
	{
		return;
	}
	presentTitle(getter);

	for(std::size_t i = 0; i < basicLen; ++i)
	{
		if(!desc[i].empty() && !info[i].empty())
		{
			Log::info() << desc[i] << info[i] << "\n";
		}
	}

	if(!records)
	{
		return;
	}

	std::vector<std::size_t> distribution;
	getter.getDistribution(structIndex, distribution);
	const auto elements = distribution.size();
	std::vector<bool> columns;
	getter.getDistributionFlags(structIndex, columns);
	presentIterativeDistributionHeader(getter, explanatory, structIndex);
	std::size_t len;
	std::string value, line;

	for(std::size_t i = 0; getter.getRecord(structIndex, i, info); ++i)
	{
		line.clear();

		for(std::size_t j = 0; j < elements; ++j)
		{
			if(!columns[j])
			{
				continue;
			}
			value = info[j];
			len = value.length();
			if(len < distribution[j])
			{
				line += value + std::string(distribution[j] - len, ' ');
			}
			else if(j + 1 < elements && columns[j + 1] && info[j + 1].empty() && len < distribution[j] + distribution[j + 1] && value.find(' ') == std::string::npos)
			{
				line += value + std::string(distribution[j] + distribution[j + 1] - len, ' ');
				++j;
			}
			else
			{
				Log::info() << line << value << "\n";
				line = std::string(line.length() + distribution[j], ' ');
			}
		}

		if(line != std::string(line.length(), ' '))
		{
			Log::info() << line << "\n";
		}
	}

	if(!explanatory || !getter.getFlagDescriptors(structIndex, desc, info))
	{
		return;
	}

	if((len = info.size()))
	{
		getIterativeDistributionSeparator(getter, line, structIndex);
		Log::info() << line << "\nFlags:\n";

		for(std::size_t i = 0; i < len; ++i)
		{
			Log::info() << "  " << info[i] << " - " << desc[i] << "\n";
		}
	}
}

/**
 * Present information from iterative distribution getter
 * @param getter Instance of IterativeDistributionGetter class
 * @param explanatory Print explanatory notes
 */
void presentIterativeDistribution(const IterativeDistributionGetter &getter, bool explanatory)
{
	for(std::size_t i = 0, e = getter.getNumberOfStructures(); i < e; ++i)
	{
		presentIterativeDistributionStructure(getter, explanatory, i);
	}
}

/**
 * Present information from one structure of iterative simple getter
 * @param getter Instance of IterativeSimpleGetter class
 * @param structIndex Index of selected structure (indexed from 0).
 */
void presentIterativeSimpleStructure(const IterativeSimpleGetter &getter, std::size_t structIndex)
{
	if(structIndex >= getter.getNumberOfStructures())
	{
		return;
	}

	std::vector<std::string> desc, info;
	const auto basicLen = getter.getBasicInfo(structIndex, desc, info);
	const auto records = getter.getNumberOfStoredRecords(structIndex);

	if(!basicLen && !records)
	{
		return;
	}

	presentTitle(getter);
	for(std::size_t i = 0; i < basicLen; ++i)
	{
		if(!desc[i].empty() && !info[i].empty())
		{
			Log::info() << desc[i] << info[i] << "\n";
		}
	}

	desc.clear();
	info.clear();

	std::string elemHeader;
	getter.getElementHeader(elemHeader);
	getter.getHeaderElements(structIndex, desc);

	for(std::size_t i = 0; getter.getRecord(structIndex, i, info); ++i)
	{
		Log::info() << '\n' << elemHeader << " #" << i << std::endl;
		presentSimple(desc, info, false);
	}
}

/**
 * Present information from iterative simple getter
 * @param getter Instance of IterativeSimpleGetter class
 */
void presentIterativeSimple(const IterativeSimpleGetter &getter)
{
	for(std::size_t i = 0, e = getter.getNumberOfStructures(); i < e; ++i)
	{
		presentIterativeSimpleStructure(getter, i);
	}
}

} // anonymous namespace

/**
 * Constructor
 */
PlainPresentation::PlainPresentation(FileInformation &fileinfo_, bool verbose_, bool explanatory_) :
	FilePresentation(fileinfo_), verbose(verbose_), explanatory(explanatory_)
{

}

/**
 * Present information about used compiler (or packer)
 */
void PlainPresentation::presentCompiler() const
{
	for(std::size_t i = 0, e = fileinfo.getNumberOfDetectedCompilers(); i < e; ++i)
	{
		const DetectResult& tool = fileinfo.toolInfo.detectedTools[i];

		Log::info() << "Detected tool            : " << tool.name;
		if (!tool.versionInfo.empty())
		{
			Log::info() << " (" << tool.versionInfo << ")";
		}
		if (!tool.additionalInfo.empty())
		{
			Log::info() << " " << tool.additionalInfo;
		}
		Log::info() << " (" << toolTypeToString(tool.type) << ")";
		if (tool.source == DetectionMethod::SIGNATURE)
		{
			std::string nibbles = tool.impCount ? "nibbles" : "nibble";
			auto ratio = static_cast<double>(tool.agreeCount) / tool.impCount * 100;

			Log::info() << ", " << tool.agreeCount << " from " << tool.impCount << " significant " << nibbles;
			Log::info() << " (" << ratio << "%)";
		}
		else
		{
			Log::info() << ", " << detectionMetodToString(tool.source);
		}
		Log::info() << "\n";
	}
}

/**
 * Present information about original programming language(s)
 */
void PlainPresentation::presentLanguages() const
{
	const auto noOfLanguages = fileinfo.toolInfo.detectedLanguages.size();
	if(!noOfLanguages)
	{
		return;
	}
	Log::info() << "Original language        : ";

	for(std::size_t i = 0; i < noOfLanguages; )
	{
		Log::info() << fileinfo.toolInfo.detectedLanguages[i].name;
		if(fileinfo.toolInfo.detectedLanguages[i].additionalInfo.length())
		{
			Log::info() << " (" << fileinfo.toolInfo.detectedLanguages[i].additionalInfo << ")";
		}
		if(fileinfo.toolInfo.detectedLanguages[i].bytecode)
		{
			Log::info() << " (bytecode)";
		}
		if(++i < noOfLanguages)
		{
			Log::info() << ", ";
		}
	}

	Log::info() << "\n";
}

/**
 * Present basic information about rich header
 */
void PlainPresentation::presentRichHeader() const
{
	const auto offset = fileinfo.getRichHeaderOffsetStr(hexWithPrefix);
	const auto key = fileinfo.getRichHeaderKeyStr(hexWithPrefix);
	const auto sig = toLower(fileinfo.getRichHeaderSignature());
	if(!offset.empty())
	{
		Log::info() << "Rich header offset       : " << offset << "\n";
	}
	if(!key.empty())
	{
		Log::info() << "Rich header key          : " << key << "\n";
	}
	if(!sig.empty())
	{
		const std::string signDesc = "Rich header signature    : ";
		const std::size_t richHeaderSignRecordLength = 8;
		auto signLineLen = MAX_LINE_LENGTH - signDesc.length();
		signLineLen -= signLineLen % richHeaderSignRecordLength;

		for(std::size_t i = 0, e = sig.length(); i < e; i += signLineLen)
		{
			Log::info() << (i ? std::string(signDesc.length(), ' ') : signDesc) << sig.substr(i, signLineLen) << "\n";
		}
	}
	auto crc32 = fileinfo.getRichHeaderCrc32();
	auto md5 = fileinfo.getRichHeaderMd5();
	auto sha256 = fileinfo.getRichHeaderSha256();

	if (!crc32.empty()) {
		Log::info() << "Rich header CRC32        : " << crc32 << "\n";
	}
	if (!md5.empty()) {
		Log::info() << "Rich header MD5          : " << md5 << "\n";
	}
	if (!sha256.empty()) {
		Log::info() << "Rich header SHA256       : " << sha256 << "\n";
	}
}

/**
 * Present information about overlay
 */
void PlainPresentation::presentOverlay() const
{
	const auto offset = fileinfo.getOverlayOffsetStr(hexWithPrefix);
	const auto size = fileinfo.getOverlaySizeStr(hexWithPrefix);
	const auto entropy = fileinfo.getOverlayEntropyStr(truncFloat);
	if(!offset.empty())
	{
		Log::info() << "Overlay offset           : " << offset << "\n";
	}
	if(!size.empty())
	{
		Log::info() << "Overlay size             : " << size << "\n";
	}
	if(!entropy.empty())
	{
		Log::info() << "Overlay entropy          : " << entropy << "\n";
	}
}

/**
 * Present information about packing
 */
void PlainPresentation::presentPackingInfo() const
{
	const auto packed = fileinfo.toolInfo.isPacked();
	Log::info() << "Packed                   : " << packedToString(packed) << "\n";
}

/**
 * Print information about flags
 * @param title Flags title
 * @param flags Flags in binary string representation
 * @param desc Vector of descriptors (descriptor is complete information about flag)
 * @param abbv Vector of abbreviations (abbreviation is short information about flag)
 */
void PlainPresentation::presentSimpleFlags(const std::string &title, const std::string &flags, const std::vector<std::string> &desc, const std::vector<std::string> &abbv) const
{
	if(flags.empty() && abbv.empty())
	{
		return;
	}

	Log::info() << title << flags;
	const std::string abbreviations = abbvSerialization(abbv);
	if(!abbreviations.empty())
	{
		flags.empty() ? Log::info() << abbreviations : Log::info() << " (" << abbreviations << ")";
	}
	Log::info() << "\n";
	if(explanatory)
	{
		for(std::size_t i = 0, e = abbv.size(); i < e; ++i)
		{
			Log::info() << "  " << abbv[i] << " - " << desc[i] << "\n";
		}
	}
}

/**
 * Present detected patterns
 * @param title Title of presented patterns
 * @param patterns Detected patterns
 */
void PlainPresentation::presentPatterns(const std::string &title, const std::vector<Pattern> &patterns)
{
	if(patterns.empty())
	{
		return;
	}

	presentTitle(title);
	Log::info() << "Number of detected patterns: " << patterns.size() << "\n\n";

	for(std::size_t i = 0, e = patterns.size(); i < e; ++i)
	{
		Log::info() << patterns[i].getYaraRuleName() << "\n";
		const auto description = patterns[i].getDescription();
		if(!description.empty())
		{
			Log::info() << "  description: " << description << "\n";
		}
		if(patterns[i].isLittle() || patterns[i].isBig())
		{
			const std::string end = patterns[i].isLittle() ? "little" : "big";
			Log::info() << "  endianness: " << end << "\n";
		}
		Log::info() << "  number of matches: " << patterns[i].getNumberOfMatches();
		const auto &matches = patterns[i].getMatches();
		presentIterativeDistribution(PatternMatchesPlainGetter(fileinfo, matches), explanatory);
		if(matches.empty())
		{
			Log::info() << "\n";
		}
		if(i + 1 != e)
		{
			Log::info() << "\n";
		}
	}
}

void PlainPresentation::presentDotnetClasses() const
{
	const auto& classes = fileinfo.getDotnetDefinedClassList();
	if (classes.empty())
		return;

	Log::info() << '\n';
	for (const auto& dotnetClass : classes)
	{
		Log::info() << dotnetClass->getVisibilityString() << ' '
			<< (dotnetClass->isAbstract() ? "abstract " : "")
			<< (dotnetClass->isSealed() ? "sealed " : "")
			<< dotnetClass->getTypeString() << ' '
			<< dotnetClass->getFullyQualifiedNameWithGenericParameters();

		if (!dotnetClass->getBaseTypes().empty())
		{
			Log::info() << " : ";
			for (auto itr = dotnetClass->getBaseTypes().begin(), end = dotnetClass->getBaseTypes().end(); itr != end; ++itr)
			{
				Log::info() << (*itr)->getText();
				if (itr + 1 != end)
					Log::info() << ", ";
			}
		}

		Log::info() << '\n';

		if (!dotnetClass->getMethods().empty())
			Log::info() << "    // Methods\n";

		for (const auto& dotnetMethod : dotnetClass->getMethods())
		{
			Log::info() << "    " << dotnetMethod->getVisibilityString() << ' '
				<< (dotnetMethod->isStatic() ? "static " : "")
				<< (dotnetMethod->isVirtual() ? "virtual " : "")
				<< (dotnetMethod->isFinal() ? "sealed " : "")
				<< (dotnetMethod->isAbstract() ? "abstract " : "")
				<< (!dotnetMethod->isConstructor() ? dotnetMethod->getReturnType()->getText() + ' ' : "")
				<< dotnetMethod->getNameWithGenericParameters()
				<< '(';

			for (auto itr = dotnetMethod->getParameters().begin(), end = dotnetMethod->getParameters().end(); itr != end; ++itr)
			{
				Log::info() << (*itr)->getDataType()->getText() << ' ' << (*itr)->getName();
				if (itr + 1 != end)
					Log::info() << ", ";
			}

			Log::info() << ")\n";
		}

		if (!dotnetClass->getFields().empty())
			Log::info() << "    // Fields\n";

		for (const auto& dotnetField : dotnetClass->getFields())
		{
			Log::info() << "    " << dotnetField->getVisibilityString() << ' '
				<< dotnetField->getDataType()->getText() << ' '
				<< dotnetField->getName()
				<< '\n';
		}

		if (!dotnetClass->getProperties().empty())
			Log::info() << "    // Properties\n";

		for (const auto& dotnetProperty : dotnetClass->getProperties())
		{
			Log::info() << "    " << dotnetProperty->getVisibilityString() << ' '
				<< dotnetProperty->getDataType()->getText() << ' '
				<< dotnetProperty->getName()
				<< '\n';
		}
	}
}

void PlainPresentation::presentVisualBasicObjects() const
{
	auto nObjs = fileinfo.getVisualBasicNumberOfObjects();
	auto guid = fileinfo.getVisualBasicObjectTableGUID();
	if (!fileinfo.isVisualBasicUsed() || (nObjs == 0 && guid.empty()))
	{
		return;
	}

	Log::info() << "\n";
	Log::info() << "Visual Basic Object table" << "\n";
	Log::info() << "-------------------------" << "\n";
	Log::info() << "CRC32            : " << fileinfo.getVisualBasicObjectTableHashCrc32() << "\n";
	Log::info() << "MD5              : " << fileinfo.getVisualBasicObjectTableHashMd5() << "\n";
	Log::info() << "SHA256           : " << fileinfo.getVisualBasicObjectTableHashSha256() << "\n";
	Log::info() << "GUID             : " << guid << "\n";
	Log::info() << "\n";

	std::size_t cnt = 0;
	for (std::size_t i = 0; i < nObjs; i++)
	{
		auto obj = fileinfo.getVisualBasicObject(i);
		if (!obj)
		{
			continue;
		}
		auto objName = obj->getName();
		if (objName.empty())
		{
			continue;
		}
		Log::info() << cnt << ". " << "object name: " << objName << "\n";
		for (const auto &m : obj->getMethods())
		{
			Log::info() << "    method name: " << m << "\n";
		}
		cnt++;
	}
}

/**
 * Present ELF notes
 */
void PlainPresentation::presentNotes() const
{
	auto& notes = fileinfo.getElfNotes();
	if(notes.empty())
	{
		return;
	}

	presentIterativeDistribution(ElfNotesPlainGetter(fileinfo), explanatory);
	presentCore();
}

/**
 * Present ELF core
 */
void PlainPresentation::presentCore() const
{
	const auto& core = fileinfo.getElfCoreInfo();
	if(core.hasAuxVector())
	{
		presentIterativeDistribution(ElfAuxVPlainGetter(fileinfo), explanatory);
	}
	if(core.hasFileMap())
	{
		presentIterativeDistribution(ElfCoreMapPlainGetter(fileinfo), explanatory);
	}
}

static void printCertificate(const Certificate& cert, int indent)
{
	Log::info() << std::string(indent, ' ') << "Subject:              " << cert.getRawSubject() << "\n";
	Log::info() << std::string(indent, ' ') << "Issuer:               " << cert.getRawIssuer() << "\n";
	Log::info() << std::string(indent, ' ') << "Serial:               " << cert.getSerialNumber() << "\n";
	Log::info() << std::string(indent, ' ') << "SHA1:                 " << cert.getSha1Digest() << "\n";
	Log::info() << std::string(indent, ' ') << "SHA256:               " << cert.getSha256Digest() << "\n";
	Log::info() << std::string(indent, ' ') << "Valid since:          " << cert.getValidSince() << "\n";
	Log::info() << std::string(indent, ' ') << "Valid until:          " << cert.getValidUntil() << "\n";
	Log::info() << std::string(indent, ' ') << "Signature Algorithm:  " << cert.getSignatureAlgorithm() << "\n";
	Log::info() << std::string(indent, ' ') << "Public Key Algorithm: " << cert.getPublicKeyAlgorithm() << "\n";
	Log::info() << std::string(indent, ' ') << "Public key:           " << cert.getPublicKey() << "\n";
}

static void printCertificateChain(const std::vector<Certificate>& certs, int indent)
{
	for (int idx = 0; idx < certs.size(); idx++) {
		Log::info() << std::string(indent, ' ') << "Certificate #" << idx << "\n";
		printCertificate(certs[idx], indent + 4);
		Log::info() << "\n";
	}
}

static void printSigner(const Signer& signer, int indent)
{

	Log::info() << std::string(indent, ' ') << "Digest Algorithm: " << signer.digestAlgorithm << "\n";
	Log::info() << std::string(indent, ' ') << "Digest:           " << signer.digest << "\n";
	if (!signer.signingTime.empty()) {
		Log::info() << std::string(indent, ' ') << "Signing time:     " << signer.signingTime << "\n";
	}

	printCertificateChain(signer.chain, indent);

	for (int idx = 0; idx < signer.counterSigners.size(); idx++) {
		Log::info() << std::string(indent, ' ') << "Countersigner #" << idx << ":\n";
		printSigner(signer.counterSigners[idx], indent + 4);
		Log::info() << "\n";
	}
}

static void printSignature(const DigitalSignature& signature, int indent)
{
	Log::info() << std::string(indent, ' ') << "Is Valid: " << signature.isValid << "\n";
	Log::info() << std::string(indent, ' ') << "Digest Algorithm: " << signature.digestAlgorithm << "\n";
	Log::info() << std::string(indent, ' ') << "Signed Digest:    " << signature.signedDigest << "\n";
	Log::info() << std::string(indent, ' ') << "File  Digest:     " << signature.fileDigest << "\n";
	Log::info() << std::string(indent, ' ') << "Program Name: " << signature.programName << "\n";

	Log::info() << std::string(indent, ' ') << "Signer:\n";
	printSigner(signature.signer, indent + 4);
	Log::info() << "\n";
}

void PlainPresentation::presentSignatures() const
{
	const CertificateTable* table = fileinfo.certificateTable;
	if (!table || !table->isOutsideImage)
	{
		return;
	}
	Log::info() << "\n";
	Log::info() << "Digital Signatures\n";
	Log::info() << "------------------\n\n";
	int indent = 4;

	Log::info() << std::string(indent, ' ') << "Signature count: " << table->signatureCount() << "\n";

	for (int idx = 0; idx < table->signatureCount(); idx++)
	{
		Log::info() << std::string(indent, ' ') << "Signature #" << idx << ":\n";
		printSignature(table->signatures[idx], indent + 4);
		Log::info() << "\n";
	}
}

bool PlainPresentation::present()
{
	if(verbose)
	{
		Log::info() << "RetDec Fileinfo version  : "
				<< utils::version::getVersionStringShort() << "\n";
	}
	Log::info() << "Input file               : " << fileinfo.getPathToFile() << "\n";
	presentSimple(BasicPlainGetter(fileinfo), false);
	presentCompiler();
	presentLanguages();
	presentRichHeader();
	presentOverlay();
	if(returnCode != ReturnCode::OK)
	{
		Log::error() << getErrorMessage(returnCode, fileinfo.getFileFormatEnum()) << "\n";
	}

	for(std::size_t i = 0, e = fileinfo.messages.size(); i < e; ++i)
	{
		Log::error() << fileinfo.messages[i] << "\n";
	}

	if(verbose)
	{
		std::string errorMessage;

		errorMessage = fileinfo.getLoaderStatusMessage();
		if(!errorMessage.empty())
		{
			Log::error() << Log::Warning << errorMessage << "\n";
		}

		errorMessage = fileinfo.getDepsListFailedToLoad();
		if (!errorMessage.empty())
		{
			Log::error() << Log::Warning << "Failed to load the dependency list (\"" << errorMessage << "\")\n";
		}

		std::string flags, title;
		std::vector<std::string> desc, info;

		presentPackingInfo();

		HeaderPlainGetter headerInfo(fileinfo);
		presentSimple(headerInfo, true);
		headerInfo.getFileFlags(title, flags, desc, info);
		presentSimpleFlags(title, flags, desc, info);
		headerInfo.getDllFlags(title, flags, desc, info);
		presentSimpleFlags(title, flags, desc, info);
		presentSimple(PdbPlainGetter(fileinfo), false, "Related PDB file");

		presentIterativeDistribution(RichHeaderPlainGetter(fileinfo), explanatory);
		presentIterativeDistribution(DataDirectoryPlainGetter(fileinfo), explanatory);
		presentIterativeDistribution(SegmentPlainGetter(fileinfo), explanatory);
		presentIterativeDistribution(SectionPlainGetter(fileinfo), explanatory);
		presentIterativeDistribution(SymbolTablesPlainGetter(fileinfo), explanatory);
		presentIterativeDistribution(ImportTablePlainGetter(fileinfo), explanatory);
		presentIterativeDistribution(ExportTablePlainGetter(fileinfo), explanatory);
		presentIterativeDistribution(TypeRefTablePlainGetter(fileinfo), explanatory);
		presentIterativeDistribution(VisualBasicExternTablePlainGetter(fileinfo), explanatory);
		presentIterativeDistribution(RelocationTablesPlainGetter(fileinfo), explanatory);
		presentIterativeDistribution(DynamicSectionsPlainGetter(fileinfo), explanatory);
		presentIterativeDistribution(ResourcePlainGetter(fileinfo), explanatory);
		presentIterativeDistribution(VersionInfoStringTablePlainGetter(fileinfo), explanatory);
		presentIterativeDistribution(VersionInfoLanguageTablePlainGetter(fileinfo), explanatory);
		presentIterativeDistribution(TlsInfoPlainGetter(fileinfo), explanatory);
		presentIterativeDistribution(AnomaliesPlainGetter(fileinfo), explanatory);

		presentNotes();

		auto manifest = fileinfo.getManifest();
		if(!manifest.empty())
		{
			presentTitle("Manifest");
			if(manifest[0] != '\n')
			{
				Log::info() << "\n";
			}
			if(manifest[manifest.length() - 1] != '\n')
			{
				manifest += '\n';
			}
			Log::info() << replaceNonasciiChars(manifest);
		}
		presentSignatures();

		presentSimple(DotnetPlainGetter(fileinfo), false, ".NET Information");
		presentDotnetClasses();
		presentSimple(VisualBasicPlainGetter(fileinfo), false, "Visual Basic Information");
		presentVisualBasicObjects();

		if(returnCode != ReturnCode::FILE_NOT_EXIST && returnCode != ReturnCode::UNKNOWN_FORMAT)
		{
			presentIterativeDistribution(MissingDepsPlainGetter(fileinfo), explanatory);
			presentIterativeDistribution(LoaderInfoPlainGetter(fileinfo), explanatory);
		}

		presentPatterns("Detected cryptography patterns", fileinfo.getCryptoPatterns());
		presentPatterns("Detected malware patterns", fileinfo.getMalwarePatterns());
		presentPatterns("Other detected patterns", fileinfo.getOtherPatterns());
	}

	presentIterativeDistribution(StringsPlainGetter(fileinfo), explanatory);
	return true;
}

} // namespace fileinfo
} // namespace retdec
