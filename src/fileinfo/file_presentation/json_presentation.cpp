/**
 * @file src/fileinfo/file_presentation/json_presentation.cpp
 * @brief Plain text presentation class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <json/json.h>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/json_getters.h"
#include "fileinfo/file_presentation/getters/pattern_config_getter/pattern_config_getter.h"
#include "fileinfo/file_presentation/json_presentation.h"

using namespace retdec::utils;
using namespace Json;
using namespace retdec::cpdetect;
using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

/**
 * Present information from simple getter
 * @param getter Instance of SimpleGetter class
 * @param root Parent node in output document
 * @return @c true if at least one record from getter is presented, @c false otherwise
 */
bool presentSimple(const SimpleGetter &getter, Json::Value &root)
{
	bool result = false;
	std::vector<std::string> desc, info;

	for(std::size_t i = 0, e = getter.loadInformation(desc, info); i < e; ++i)
	{
		if(!desc[i].empty() && !info[i].empty())
		{
			root[desc[i]] = info[i];
			result = true;
		}
	}

	return result;
}

/**
 * Present information from value as key
 * @param key Key for JSON attribute
 * @param value Value to present
 * @param root Parent node in output document
 */
void presentIfNotEmpty(const std::string &key, const std::string &value, Json::Value& root)
{
	if(!value.empty())
	{
		root[key] = replaceNonprintableChars(value);
	}
}

} // anonymous namespace

/**
 * Constructor
 */
JsonPresentation::JsonPresentation(FileInformation &fileinfo_, bool verbose_) :
	FilePresentation(fileinfo_), verbose(verbose_)
{

}

/**
 * Destructor
 */
JsonPresentation::~JsonPresentation()
{

}

/**
 * Present information about warning and error messages
 * @param root Parent node in output document
 */
void JsonPresentation::presentErrors(Json::Value &root) const
{
	std::vector<std::string> messages;
	if(returnCode != ReturnCode::OK)
	{
		messages.push_back(getErrorMessage(returnCode, fileinfo.getFileFormatEnum()));
	}
	const auto loaderMessage = fileinfo.getLoaderStatusMessage();
	if(!loaderMessage.empty())
	{
		messages.push_back("Warning: " + loaderMessage);
	}

	for(const auto &message : fileinfo.messages)
	{
		messages.push_back(message);
	}

	for(const auto message : messages)
	{
		const auto pos = message.find(':');
		if(pos >= message.length() - 1)
		{
			continue;
		}
		const auto prefix = toLower(message.substr(0, pos));
		auto content = removeLeadingCharacter(message.substr(pos + 1), ' ');
		if(prefix.empty() || content.empty())
		{
			continue;
		}
		if(content.back() != '.')
		{
			content += '.';
		}
		content[0] = toupper(static_cast<unsigned char>(content[0]));
		root[prefix + "s"].append(content);
	}
}

/**
* Present information about Windows PE loader error
* @param root Parent node in output document
*/
void JsonPresentation::presentLoaderError(Json::Value &root) const
{
	auto ldrErrInfo = fileinfo.getLoaderErrorInfo();

	if (ldrErrInfo.loaderErrorCode != 0)
	{
		Json::Value loaderErrorNode;

		loaderErrorNode["code"] = ldrErrInfo.loaderErrorCode;
		loaderErrorNode["code_text"] = ldrErrInfo.loaderError;
		loaderErrorNode["description"] = ldrErrInfo.loaderErrorUserFriendly;

		root["loaderError"] = loaderErrorNode;
	}
}

/**
 * Present information about detected compilers and packers
 * @param root Parent node in output document
 */
void JsonPresentation::presentCompiler(Json::Value &root) const
{
	for(const auto &tool : fileinfo.toolInfo.detectedTools)
	{
		Value jDetected;
		jDetected["type"] = toolTypeToString(tool.type);
		if(!tool.name.empty())
		{
			jDetected["name"] = tool.name;
		}
		if(!tool.versionInfo.empty())
		{
			jDetected["version"] = tool.versionInfo;
		}
		if(!tool.additionalInfo.empty())
		{
			jDetected["additional"] = tool.additionalInfo;
		}
		jDetected["method"] = detectionMetodToString(tool.source);
		jDetected["heuristics"] = (tool.source != DetectionMethod::SIGNATURE);
		jDetected["identicalSignificantNibbles"] = static_cast<Json::Value::UInt64>(tool.agreeCount);
		jDetected["totalSignificantNibbles"] = static_cast<Json::Value::UInt64>(tool.impCount);
		jDetected["percentage"] = tool.impCount ? static_cast<double>(tool.agreeCount) / tool.impCount * 100 : 0.0;
		root["tools"].append(jDetected);
	}
}

/**
 * Present information about detected languages
 * @param root Parent node in output document
 */
void JsonPresentation::presentLanguages(Json::Value &root) const
{
	for(const auto &l : fileinfo.toolInfo.detectedLanguages)
	{
		Value jLan;
		jLan["name"] = l.name;
		jLan["bytecode"] = l.bytecode;
		if(!l.additionalInfo.empty())
		{
			jLan["additional"] = l.additionalInfo;
		}
		root["languages"].append(jLan);
	}
}

/**
 * Present basic information about rich header
 * @param root Parent node in output document
 */
void JsonPresentation::presentRichHeader(Json::Value &root) const
{
	const auto offset = fileinfo.getRichHeaderOffsetStr(hexWithPrefix);
	const auto key = fileinfo.getRichHeaderKeyStr(hexWithPrefix);
	const auto sig = toLower(fileinfo.getRichHeaderSignature());
	if(offset.empty() && key.empty() && sig.empty())
	{
		return;
	}

	Value jRich;
	if(!offset.empty())
	{
		jRich["offset"] = offset;
	}
	if(!key.empty())
	{
		jRich["key"] = key;
	}
	if(!sig.empty())
	{
		jRich["signature"] = sig;
	}
	root["richHeader"] = jRich;
}

/**
 * Present information about packing
 * @param root Parent node in output document
 */
void JsonPresentation::presentPackingInfo(Value &root) const
{
	const auto packed = fileinfo.toolInfo.isPacked();
	root["packed"] = toLower(packedToString(packed));
}

/**
 * Present information about overlay
 * @param root Parent node in output document
 */
void JsonPresentation::presentOverlay(Json::Value &root) const
{
	const auto offset = fileinfo.getOverlayOffsetStr(hexWithPrefix);
	const auto size = fileinfo.getOverlaySizeStr(hexWithPrefix);
	if(!offset.empty() || !size.empty())
	{
		Value jOverlay;
		if(!offset.empty())
		{
			jOverlay["offset"] = offset;
		}
		if(!size.empty())
		{
			jOverlay["size"] = size;
		}
		root["overlay"] = jOverlay;
	}
}

/**
 * Present detected patterns
 * @param root Parent node in output document
 */
void JsonPresentation::presentPatterns(Json::Value &root) const
{
	auto pcg = PatternConfigGetter(fileinfo);
	if(pcg.isEmpty())
	{
		return;
	}
	auto patterns = pcg.getJsonValue();

	for(auto &pattern : patterns)
	{
		if(!pattern.isMember("matches"))
		{
			continue;
		}

		for(auto &match : pattern["matches"])
		{
			if(match.isMember("offset") && match["offset"].isIntegral())
			{
				match["offset"] = numToStr(match["offset"].asLargestUInt(), hexWithPrefix);
			}
			if(match.isMember("address") && match["address"].isIntegral())
			{
				match["address"] = numToStr(match["address"].asLargestUInt(), hexWithPrefix);
			}
		}
	}

	root["patterns"] = patterns;
}

/**
 * Present information about loader
 * @param root Parent node in output document
 */
void JsonPresentation::presentLoaderInfo(Json::Value &root) const
{
	if(returnCode == ReturnCode::FILE_NOT_EXIST || returnCode == ReturnCode::UNKNOWN_FORMAT)
	{
		return;
	}

	const auto baseAddress = fileinfo.getLoadedBaseAddressStr(hexWithPrefix);
	const auto numberOfSegments = fileinfo.getNumberOfLoadedSegmentsStr(std::dec);

	Value jLoaderInfo;
	jLoaderInfo["baseAddress"] = baseAddress;
	jLoaderInfo["numberOfSegments"] = numberOfSegments;

	presentIterativeSubtitle(jLoaderInfo, LoaderInfoJsonGetter(fileinfo));

	root["loaderInfo"] = jLoaderInfo;
}

/**
 * Present information about certificate attributes into certificate table
 * @param root Parent node in output document
 */
void JsonPresentation::presentCertificateAttributes(Json::Value &root) const
{
	if(!fileinfo.hasCertificateTableRecords())
	{
		return;
	}

	for(std::size_t i = 0; i < fileinfo.getNumberOfStoredCertificates(); ++i)
	{
		Value& jCert = root["certificateTable"]["certificates"][ArrayIndex(i)];

		Value jCertAttrsIssuer, jCertAttrsSubject;
		presentIfNotEmpty("country", fileinfo.getCertificateIssuerCountry(i), jCertAttrsIssuer);
		presentIfNotEmpty("organization", fileinfo.getCertificateIssuerOrganization(i), jCertAttrsIssuer);
		presentIfNotEmpty("organizationalUnit", fileinfo.getCertificateIssuerOrganizationalUnit(i), jCertAttrsIssuer);
		presentIfNotEmpty("nameQualifier", fileinfo.getCertificateIssuerNameQualifier(i), jCertAttrsIssuer);
		presentIfNotEmpty("state", fileinfo.getCertificateIssuerState(i), jCertAttrsIssuer);
		presentIfNotEmpty("commonName", fileinfo.getCertificateIssuerCommonName(i), jCertAttrsIssuer);
		presentIfNotEmpty("serialNumber", fileinfo.getCertificateIssuerSerialNumber(i), jCertAttrsIssuer);
		presentIfNotEmpty("locality", fileinfo.getCertificateIssuerLocality(i), jCertAttrsIssuer);
		presentIfNotEmpty("title", fileinfo.getCertificateIssuerTitle(i), jCertAttrsIssuer);
		presentIfNotEmpty("surname", fileinfo.getCertificateIssuerSurname(i), jCertAttrsIssuer);
		presentIfNotEmpty("givenName", fileinfo.getCertificateIssuerGivenName(i), jCertAttrsIssuer);
		presentIfNotEmpty("initials", fileinfo.getCertificateIssuerInitials(i), jCertAttrsIssuer);
		presentIfNotEmpty("pseudonym", fileinfo.getCertificateIssuerPseudonym(i), jCertAttrsIssuer);
		presentIfNotEmpty("generationQualifier", fileinfo.getCertificateIssuerGenerationQualifier(i), jCertAttrsIssuer);
		presentIfNotEmpty("emailAddress", fileinfo.getCertificateIssuerEmailAddress(i), jCertAttrsIssuer);

		presentIfNotEmpty("country", fileinfo.getCertificateSubjectCountry(i), jCertAttrsSubject);
		presentIfNotEmpty("organization", fileinfo.getCertificateSubjectOrganization(i), jCertAttrsSubject);
		presentIfNotEmpty("organizationalUnit", fileinfo.getCertificateSubjectOrganizationalUnit(i), jCertAttrsSubject);
		presentIfNotEmpty("nameQualifier", fileinfo.getCertificateSubjectNameQualifier(i), jCertAttrsSubject);
		presentIfNotEmpty("state", fileinfo.getCertificateSubjectState(i), jCertAttrsSubject);
		presentIfNotEmpty("commonName", fileinfo.getCertificateSubjectCommonName(i), jCertAttrsSubject);
		presentIfNotEmpty("serialNumber", fileinfo.getCertificateSubjectSerialNumber(i), jCertAttrsSubject);
		presentIfNotEmpty("locality", fileinfo.getCertificateSubjectLocality(i), jCertAttrsSubject);
		presentIfNotEmpty("title", fileinfo.getCertificateSubjectTitle(i), jCertAttrsSubject);
		presentIfNotEmpty("surname", fileinfo.getCertificateSubjectSurname(i), jCertAttrsSubject);
		presentIfNotEmpty("givenName", fileinfo.getCertificateSubjectGivenName(i), jCertAttrsSubject);
		presentIfNotEmpty("initials", fileinfo.getCertificateSubjectInitials(i), jCertAttrsSubject);
		presentIfNotEmpty("pseudonym", fileinfo.getCertificateSubjectPseudonym(i), jCertAttrsSubject);
		presentIfNotEmpty("generationQualifier", fileinfo.getCertificateSubjectGenerationQualifier(i), jCertAttrsSubject);
		presentIfNotEmpty("emailAddress", fileinfo.getCertificateSubjectEmailAddress(i), jCertAttrsSubject);

		jCert["attributes"]["issuer"] = jCertAttrsIssuer.empty() ? objectValue : jCertAttrsIssuer;
		jCert["attributes"]["subject"] = jCertAttrsSubject.empty() ? objectValue : jCertAttrsSubject;
	}
}

/**
 * Present information about .NET
 * @param root Parent node in output document
 */
void JsonPresentation::presentDotnetInfo(Json::Value &root) const
{
	Value jDotnet;
	if (!presentSimple(DotnetJsonGetter(fileinfo), jDotnet))
	{
		return;
	}

	if (fileinfo.hasDotnetMetadataStream())
	{
		jDotnet["metadataStream"]["offset"] = fileinfo.getDotnetMetadataStreamOffsetStr(hexWithPrefix);
		jDotnet["metadataStream"]["size"] = fileinfo.getDotnetMetadataStreamSizeStr(hexWithPrefix);
	}
	if (fileinfo.hasDotnetStringStream())
	{
		jDotnet["stringStream"]["offset"] = fileinfo.getDotnetStringStreamOffsetStr(hexWithPrefix);
		jDotnet["stringStream"]["size"] = fileinfo.getDotnetStringStreamSizeStr(hexWithPrefix);
	}
	if (fileinfo.hasDotnetBlobStream())
	{
		jDotnet["blobStream"]["offset"] = fileinfo.getDotnetBlobStreamOffsetStr(hexWithPrefix);
		jDotnet["blobStream"]["size"] = fileinfo.getDotnetBlobStreamSizeStr(hexWithPrefix);
	}
	if (fileinfo.hasDotnetGuidStream())
	{
		jDotnet["guidStream"]["offset"] = fileinfo.getDotnetGuidStreamOffsetStr(hexWithPrefix);
		jDotnet["guidStream"]["size"] = fileinfo.getDotnetGuidStreamSizeStr(hexWithPrefix);
	}
	if (fileinfo.hasDotnetUserStringStream())
	{
		jDotnet["userStringStream"]["offset"] = fileinfo.getDotnetUserStringStreamOffsetStr(hexWithPrefix);
		jDotnet["userStringStream"]["size"] = fileinfo.getDotnetUserStringStreamSizeStr(hexWithPrefix);
	}

	const auto& classes = fileinfo.getDotnetDefinedClassList();
	for (const auto& dotnetClass : classes)
	{
		Value jClass;
		jClass["name"] = dotnetClass->getName();
		jClass["fullyQualifiedName"] = dotnetClass->getFullyQualifiedName();
		jClass["namespace"] = dotnetClass->getNameSpace();
		jClass["visibility"] = dotnetClass->getVisibilityString();
		jClass["type"] = dotnetClass->getTypeString();
		jClass["abstract"] = dotnetClass->isAbstract();
		jClass["sealed"] = dotnetClass->isSealed();
		for (const auto& genericParam : dotnetClass->getGenericParameters())
			jClass["genericParameters"].append(genericParam);
		for (const auto& baseType : dotnetClass->getBaseTypes())
			jClass["baseTypes"].append(baseType->getText());

		for (const auto& dotnetMethod : dotnetClass->getMethods())
		{
			Value jMethod;
			jMethod["name"] = dotnetMethod->getName();
			jMethod["visibility"] = dotnetMethod->getVisibilityString();
			jMethod["static"] = dotnetMethod->isStatic();
			jMethod["virtual"] = dotnetMethod->isVirtual();
			jMethod["final"] = dotnetMethod->isFinal();
			jMethod["abstract"] = dotnetMethod->isAbstract();
			if (!dotnetMethod->isConstructor())
				jMethod["returnType"] = dotnetMethod->getReturnType()->getText();
			jMethod["parameters"] = arrayValue;
			for (const auto& dotnetParam : dotnetMethod->getParameters())
			{
				Value jParam;
				jParam["name"] = dotnetParam->getName();
				jParam["type"] = dotnetParam->getDataType()->getText();

				jMethod["parameters"].append(jParam);
			}
			for (const auto& genericParam : dotnetMethod->getGenericParameters())
				jMethod["genericParameters"].append(genericParam);

			jClass["methods"].append(jMethod);
		}

		for (const auto& dotnetField : dotnetClass->getFields())
		{
			Value jField;
			jField["name"] = dotnetField->getName();
			jField["type"] = dotnetField->getDataType()->getText();
			jField["visibility"] = dotnetField->getVisibilityString();
			jField["static"] = dotnetField->isStatic();

			jClass["fields"].append(jField);
		}

		for (const auto& dotnetProperty : dotnetClass->getProperties())
		{
			Value jProperty;
			jProperty["name"] = dotnetProperty->getName();
			jProperty["type"] = dotnetProperty->getDataType()->getText();
			jProperty["visibility"] = dotnetProperty->getVisibilityString();
			jProperty["static"] = dotnetProperty->isStatic();

			jClass["properties"].append(jProperty);
		}

		jDotnet["classes"].append(jClass);
	}

	root["dotnetInfo"] = jDotnet;
}

/**
 * Present ELF notes
 * @param root Parent node in output document
 */
void JsonPresentation::presentElfNotes(Json::Value& root) const
{
	auto& noteSection = fileinfo.getElfNotes();
	if(noteSection.empty())
	{
		return;
	}

	Value jNotesArr;
	for(const auto& notes : noteSection)
	{
		Value jNotes;

		if(notes.isNamedSection())
		{
			jNotes["name"] = replaceNonprintableChars(notes.getSectionName());
		}
		if(notes.isMalformed())
		{
			jNotes["warning"] = notes.getErrorMessage();
		}

		jNotes["size"] = static_cast<std::uint64_t>(notes.getSecSegLength());
		jNotes["offset"] = static_cast<std::uint64_t>(notes.getSecSegOffset());
		jNotes["numberOfNotes"] = static_cast<std::uint64_t>(notes.getNotes().size());

		Value jNoteArr;
		std::size_t idx = 0;
		for(const auto& note : notes.getNotes())
		{
			Value jNote;

			jNote["index"] = static_cast<std::uint64_t>(idx++);
			jNote["owner"] = replaceNonprintableChars(note.owner);
			jNote["type"] = static_cast<std::uint64_t>(note.type);
			jNote["dataSize"] = static_cast<std::uint64_t>(note.dataLength);
			jNote["dataOffset"] = static_cast<std::uint64_t>(note.dataOffset);
			jNote["description"] = replaceNonprintableChars(note.description);
			jNoteArr.append(jNote);
		}

		jNotes["noteEntries"] = jNoteArr;
		jNotesArr.append(jNotes);
	}

	root["elfNotes"] = jNotesArr;

	Value jCoreInfo;
	auto someCoreInfo = false;

	const auto& core = fileinfo.getElfCoreInfo();
	if(core.hasAuxVector())
	{
		Value jAuxInfo;
		someCoreInfo =  true;

		const auto& auxVec = core.getAuxVector();
		for(const auto& auxEntry : auxVec)
		{
			Value jAuxEntry;
			jAuxEntry["name"] = auxEntry.first;
			jAuxEntry["value"] = auxEntry.second;
			jAuxInfo.append(jAuxEntry);
		}

		jCoreInfo["numberOfAuxVectorEntries"] = static_cast<std::uint64_t>(auxVec.size());
		jCoreInfo["auxVector"] = jAuxInfo;
	}
	if(core.hasFileMap())
	{
		Value jMapInfo;
		someCoreInfo =  true;

		const auto& fileMap = core.getFileMap();
		for(const auto& mapEntry : fileMap)
		{
			Value jMapEntry;
			jMapEntry["address"] = mapEntry.address;
			jMapEntry["size"] = mapEntry.size;
			jMapEntry["page"] = mapEntry.page;
			jMapEntry["path"] = replaceNonprintableChars(mapEntry.path);
			jMapInfo.append(jMapEntry);
		}

		jCoreInfo["numberOfFileMapEntries"] = static_cast<std::uint64_t>(fileMap.size());
		jCoreInfo["fileMap"] = jMapInfo;
	}

	if(someCoreInfo)
	{
		root["elfCore"] = jCoreInfo;
	}
}

/**
 * Present information about flags
 * @param root Parent node in output document
 * @param title Flags title
 * @param flags Flags in binary string representation
 * @param desc Vector of descriptors (descriptor is complete information about flag)
 */
void JsonPresentation::presentFlags(Json::Value &root, const std::string &title, const std::string &flags, const std::vector<std::string> &desc) const
{
	if(flags.empty() && desc.empty())
	{
		return;
	}

	Value jFlags;
	if(!flags.empty())
	{
		jFlags["value"] = flags;
	}

	for(const auto &d : desc)
	{
		jFlags["descriptors"].append(d);
	}

	root[title] = jFlags;
}

/**
 * Present information from one structure of iterative subtitle getter
 * @param root Parent node in output document
 * @param getter Instance of IterativeSubtitleGetter class
 * @param structIndex Index of selected structure (indexed from 0)
 */
void JsonPresentation::presentIterativeSubtitleStructure(Json::Value &root, const IterativeSubtitleGetter &getter, std::size_t structIndex) const
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

	std::string header, title, subtitle;
	getter.getHeader(header);
	getter.getTitle(title);
	getter.getSubtitle(subtitle);
	const auto simplyStructure = header.empty();
	if((simplyStructure && (title.empty() || (basicLen && subtitle.empty()))) ||
		(!simplyStructure && (header.empty() || subtitle.empty())))
	{
		return;
	}

	Value jTitle;

	for(std::size_t i = 0; i < basicLen; ++i)
	{
		if(!desc[i].empty() && !info[i].empty())
		{
			jTitle[desc[i]] = info[i];
		}
	}

	const auto elements = getter.getHeaderElements(structIndex, desc);
	std::string flags;
	std::vector<std::string> flagsDesc;

	for(std::size_t i = 0; getter.getRecord(structIndex, i, info); ++i)
	{
		Value jEntry;

		for(std::size_t j = 0; j < elements; ++j)
		{
			if(!desc[j].empty() && !info[j].empty())
			{
				jEntry[desc[j]] = info[j];
			}
		}

		getter.getFlags(structIndex, i, flags, flagsDesc);
		presentFlags(jEntry, "flags", flags, flagsDesc);
		simplyStructure && !basicLen ? jTitle.append(jEntry) : jTitle[subtitle].append(jEntry);
	}

	simplyStructure ? root[title] = jTitle : root[header].append(jTitle);
}

/**
 * Present information from iterative subtitle getter
 * @param root Parent node in output document
 * @param getter Instance of IterativeSubtitleGetter class
 */
void JsonPresentation::presentIterativeSubtitle(Json::Value &root, const IterativeSubtitleGetter &getter) const
{
	for(std::size_t i = 0, e = getter.getNumberOfStructures(); i < e; ++i)
	{
		presentIterativeSubtitleStructure(root, getter, i);
	}
}

bool JsonPresentation::present()
{
	Value root, jEp;
	root["inputFile"] = fileinfo.getPathToFile();
	presentErrors(root);
	presentLoaderError(root);
	presentSimple(BasicJsonGetter(fileinfo), root);
	if(presentSimple(EntryPointJsonGetter(fileinfo), jEp))
	{
		root["entryPoint"] = jEp;
	}
	presentCompiler(root);
	presentLanguages(root);
	presentOverlay(root);

	if(verbose)
	{
		std::string flags, title;
		std::vector<std::string> desc, info;

		presentPackingInfo(root);

		HeaderJsonGetter headerInfo(fileinfo);
		presentSimple(headerInfo, root);
		headerInfo.getFileFlags(title, flags, desc, info);
		presentFlags(root, title, flags, desc);
		headerInfo.getDllFlags(title, flags, desc, info);
		presentFlags(root, title, flags, desc);
		Value jPdb;
		if(presentSimple(PdbJsonGetter(fileinfo), jPdb))
		{
			root["pdbInfo"] = jPdb;
		}

		presentIterativeSubtitle(root, RichHeaderJsonGetter(fileinfo));
		presentIterativeSubtitle(root, DataDirectoryJsonGetter(fileinfo));
		presentIterativeSubtitle(root, SegmentJsonGetter(fileinfo));
		presentIterativeSubtitle(root, SectionJsonGetter(fileinfo));
		presentIterativeSubtitle(root, SymbolTablesJsonGetter(fileinfo));
		presentIterativeSubtitle(root, ImportTableJsonGetter(fileinfo));
		presentIterativeSubtitle(root, ExportTableJsonGetter(fileinfo));
		presentIterativeSubtitle(root, RelocationTablesJsonGetter(fileinfo));
		presentIterativeSubtitle(root, DynamicSectionsJsonGetter(fileinfo));
		presentIterativeSubtitle(root, ResourceJsonGetter(fileinfo));
		presentIterativeSubtitle(root, CertificateTableJsonGetter(fileinfo));
		const auto manifest = fileinfo.getCompactManifest();
		if(!manifest.empty())
		{
			root["manifest"] = replaceNonasciiChars(manifest);
		}
		presentElfNotes(root);
		presentLoaderInfo(root);
		presentPatterns(root);
		presentCertificateAttributes(root);
		presentDotnetInfo(root);
	}
	else
	{
		presentRichHeader(root);
	}

	presentIterativeSubtitle(root, StringsJsonGetter(fileinfo));

	StreamWriterBuilder builder;
	std::cout << writeString(builder, root) << std::endl;
	return true;
}

} // namespace fileinfo
