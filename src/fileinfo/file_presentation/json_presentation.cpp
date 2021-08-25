/**
 * @file src/fileinfo/file_presentation/json_presentation.cpp
 * @brief Plain text presentation class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/certificate_table/certificate_table.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/utils/io/log.h"
#include "retdec/utils/version.h"
#include "retdec/fileformat/utils/conversions.h"
#include "retdec/serdes/pattern.h"
#include "retdec/serdes/std.h"
#include "fileinfo/file_presentation/getters/json_getters.h"
#include "fileinfo/file_presentation/getters/pattern_config_getter/pattern_config_getter.h"
#include "fileinfo/file_presentation/json_presentation.h"

using namespace retdec;
using namespace retdec::utils;
using namespace retdec::utils::io;
using namespace retdec::cpdetect;
using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

namespace
{

/**
 * All unprintable characters are replaced with their byte values as '\x??'.
 * This is not ideal, but fileinfo consumers expect it like this.
 * It would be better to leave this for the rapidjson serializer to deal with.
 * It would serialize it as '\u????'.
 */
template <typename Writer>
void serializeString(
		Writer& writer,
		const std::string& key,
		const std::string& val,
		bool serializeIfValueEmpty = false)
{
	serdes::serializeString(
			writer,
			key,
			utils::replaceNonprintableChars(val),
			serializeIfValueEmpty);
}

/**
 * Present information from simple getter
 * @param getter Instance of SimpleGetter class
 * @param writer JSON writer to write to
 * @param key If set then everything is written into a JSO object with the name.
 * @return @c true if at least one record from getter is presented, @c false otherwise
 */
bool presentSimple(
		const SimpleGetter &getter,
		JsonPresentation::Writer& writer,
		const std::string& key = std::string())
{
	bool result = false;
	std::vector<std::string> desc, info;

	bool first = !key.empty();
	bool objectGenerated = false;

	for(std::size_t i = 0, e = getter.loadInformation(desc, info); i < e; ++i)
	{
		if(!desc[i].empty() && !info[i].empty())
		{
			if (first)
			{
				writer.String(key);
				writer.StartObject();
				objectGenerated = true;
				first = false;
			}

			serializeString(writer, desc[i], info[i]);
			result = true;
		}
	}

	if (objectGenerated)
	{
		writer.EndObject();
	}

	return result;
}

} // anonymous namespace

/**
 * Constructor
 */
JsonPresentation::JsonPresentation(FileInformation &fileinfo_, bool verbose_)
		: FilePresentation(fileinfo_)
		, verbose(verbose_)
{

}

void JsonPresentation::presentFileinfoVersion(Writer& writer) const
{
	writer.String("fileinfoVersion");
	writer.StartObject();
	serializeString(writer, "commitHash", utils::version::getCommitHash());
	serializeString(writer, "versionTag", utils::version::getVersionTag());
	serializeString(writer, "buildDate", utils::version::getBuildDate());
	writer.EndObject();
}

/**
 * Present information about warning and error messages
 */
void JsonPresentation::presentErrors(Writer& writer) const
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

	const auto errorMessage = fileinfo.getDepsListFailedToLoad();
	if (!errorMessage.empty())
	{
		messages.push_back("Warning: Failed to load the dependency list (\"" + errorMessage + "\")\n");
	}

	for(const auto &message : fileinfo.messages)
	{
		messages.push_back(message);
	}

	std::map<std::string, std::vector<std::string>> result;
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
		result[prefix + "s"].push_back(content);
	}

	for (auto& p : result)
	{
		writer.String(p.first);
		writer.StartArray();
		for (auto& msg : p.second)
		{
			writer.String(msg);
		}
		writer.EndArray();
	}
}

/**
* Present information about Windows PE loader error
*/
void JsonPresentation::presentLoaderError(Writer& writer) const
{
	auto ldrErrInfo = fileinfo.getLoaderErrorInfo();

	if (ldrErrInfo.loaderErrorCode != 0)
	{
		writer.String("loaderError");
		writer.StartObject();

		serdes::serializeUint64(writer, "code", ldrErrInfo.loaderErrorCode);
		serializeString(writer, "code_text", ldrErrInfo.loaderError);
		serializeString(writer, "description", ldrErrInfo.loaderErrorUserFriendly);
		serializeString(
				writer,
				"loadable_anyway",
				ldrErrInfo.isLoadableAnyway ? "true" : "false"
		);

		writer.EndObject();
	}
}

/**
 * Present information about detected compilers and packers
 */
void JsonPresentation::presentCompiler(Writer& writer) const
{
	if (fileinfo.toolInfo.detectedTools.empty())
	{
		return;
	}

	writer.String("tools");
	writer.StartArray();

	for(const auto &tool : fileinfo.toolInfo.detectedTools)
	{
		writer.StartObject();

		serializeString(writer, "type", toolTypeToString(tool.type));
		serializeString(writer, "name", tool.name);
		serializeString(writer, "version", tool.versionInfo);
		serializeString(writer, "additional", tool.additionalInfo);
		serializeString(
				writer,
				"method",
				detectionMetodToString(tool.source));
		serdes::serializeBool(
				writer,
				"heuristics",
				tool.source != DetectionMethod::SIGNATURE);
		serdes::serializeUint64(
				writer,
				"identicalSignificantNibbles",
				tool.agreeCount);
		serdes::serializeUint64(
				writer,
				"totalSignificantNibbles",
				tool.impCount);
		serdes::serializeDouble(
				writer,
				"percentage",
				tool.impCount
					? static_cast<double>(tool.agreeCount) / tool.impCount * 100
					: 0.0);

		writer.EndObject();
	}

	writer.EndArray();
}

/**
 * Present information about detected languages
 */
void JsonPresentation::presentLanguages(Writer& writer) const
{
	if (fileinfo.toolInfo.detectedLanguages.empty())
	{
		return;
	}

	writer.String("languages");
	writer.StartArray();

	for(const auto &l : fileinfo.toolInfo.detectedLanguages)
	{
		writer.StartObject();
		serializeString(writer, "name", l.name);
		serdes::serializeBool(writer, "bytecode", l.bytecode);
		serializeString(writer, "additional", l.additionalInfo);
		writer.EndObject();
	}

	writer.EndArray();
}

/**
 * Present basic information about rich header
 */
void JsonPresentation::presentRichHeader(Writer& writer) const
{
	const auto offset = fileinfo.getRichHeaderOffsetStr(hexWithPrefix);
	const auto key = fileinfo.getRichHeaderKeyStr(hexWithPrefix);
	const auto sig = toLower(fileinfo.getRichHeaderSignature());
	if(offset.empty() && key.empty() && sig.empty())
	{
		return;
	}

	writer.String("richHeader");
	writer.StartObject();
	serializeString(writer, "offset", offset);
	serializeString(writer, "key", key);
	serializeString(writer, "signature", sig);

	auto crc32 = fileinfo.getRichHeaderCrc32();
	auto md5 = fileinfo.getRichHeaderMd5();
	auto sha256 = fileinfo.getRichHeaderSha256();

	serializeString(writer, "crc32", crc32);
	serializeString(writer, "md5", md5);
	serializeString(writer, "sha256", sha256);

	writer.EndObject();
}

/**
 * Present information about packing
 */
void JsonPresentation::presentPackingInfo(Writer& writer) const
{
	const auto packed = fileinfo.toolInfo.isPacked();
	serializeString(writer, "packed", toLower(packedToString(packed)));
}

/**
 * Present information about overlay
 */
void JsonPresentation::presentOverlay(Writer& writer) const
{
	const auto offset = fileinfo.getOverlayOffsetStr(hexWithPrefix);
	const auto size = fileinfo.getOverlaySizeStr(hexWithPrefix);
	const auto entropy = fileinfo.getOverlayEntropyStr(truncFloat);
	if(!offset.empty() || !size.empty())
	{
		writer.String("overlay");
		writer.StartObject();
		serializeString(writer, "offset", offset);
		serializeString(writer, "size", size);
		serializeString(writer, "entropy", entropy);
		writer.EndObject();
	}
}

/**
 * Present detected patterns
 */
void JsonPresentation::presentPatterns(Writer& writer) const
{
	auto pcg = PatternConfigGetter(fileinfo);
	if(pcg.isEmpty())
	{
		return;
	}

	serdes::serializeContainer(writer, "patterns", pcg.getPatterns());
}

/**
 * Present information about missing dependencies
 */
void JsonPresentation::presentMissingDepsInfo(Writer& writer) const
{
	if (returnCode == ReturnCode::FILE_NOT_EXIST
			|| returnCode == ReturnCode::UNKNOWN_FORMAT)
	{
		return;
	}

	const auto numberOfMissingDeps = fileinfo.getNumberOfMissingDeps();

	writer.String("missingDeps");
	writer.StartObject();
	serializeString(writer, "count", std::to_string(numberOfMissingDeps));
	presentIterativeSubtitle(writer, MissingDepsJsonGetter(fileinfo));
	writer.EndObject();
}

/**
 * Present information about loader
 */
void JsonPresentation::presentLoaderInfo(Writer& writer) const
{
	if(returnCode == ReturnCode::FILE_NOT_EXIST
			|| returnCode == ReturnCode::UNKNOWN_FORMAT)
	{
		return;
	}

	const auto baseAddress = fileinfo.getLoadedBaseAddressStr(hexWithPrefix);
	const auto numberOfSegments = fileinfo.getNumberOfLoadedSegmentsStr(std::dec);

	writer.String("loaderInfo");
	writer.StartObject();
	serializeString(writer, "baseAddress", baseAddress);
	serializeString(writer, "numberOfSegments", numberOfSegments);
	presentIterativeSubtitle(writer, LoaderInfoJsonGetter(fileinfo));
	writer.EndObject();
}

void WriteCertificateChain(JsonPresentation::Writer& writer, const std::vector<Certificate>& certificates)
{
	writer.StartArray();
	for (auto&& cert : certificates)
	{
		writer.StartObject();
		serializeString(writer, "subject", cert.getRawSubject());
		serializeString(writer, "issuer", cert.getRawIssuer());
		serializeString(writer, "subjectOneline", cert.getOnelineSubject());
		serializeString(writer, "issuerOneline", cert.getOnelineIssuer());
		serializeString(writer, "serialNumber", cert.getSerialNumber());
		serializeString(writer, "publicKeyAlgorithm", cert.getPublicKeyAlgorithm());
		serializeString(writer, "signatureAlgorithm", cert.getSignatureAlgorithm());;
		serializeString(writer, "validSince", cert.getValidSince());
		serializeString(writer, "validUntil", cert.getValidUntil());
		serializeString(writer, "sha1", cert.getSha1Digest());
		serializeString(writer, "sha256", cert.getSha256Digest());
		serializeString(writer, "publicKey", cert.getPublicKey());

		writer.String("attributes");
		writer.StartObject();

		writer.String("subject");
		writer.StartObject();
		serializeString(writer, "country", cert.getSubject().country);
		serializeString(writer, "organization", cert.getSubject().organization);
		serializeString(writer, "organizationalUnit",  cert.getSubject().organizationalUnit);
		serializeString(writer, "nameQualifier",  cert.getSubject().nameQualifier);
		serializeString(writer, "state", cert.getSubject().state);
		serializeString(writer, "commonName", cert.getSubject().commonName);
		serializeString(writer, "serialNumber", cert.getSubject().serialNumber);
		serializeString(writer, "locality", cert.getSubject().locality);
		serializeString(writer, "title", cert.getSubject().title);
		serializeString(writer, "surname", cert.getSubject().surname);
		serializeString(writer, "givenName", cert.getSubject().givenName);
		serializeString(writer, "initials", cert.getSubject().initials);
		serializeString(writer, "pseudonym", cert.getSubject().pseudonym);
		serializeString(writer, "generationQualifier", cert.getSubject().generationQualifier);
		serializeString(writer, "emailAddress", cert.getSubject().emailAddress);
		writer.EndObject();

		writer.String("issuer");
		writer.StartObject();
		serializeString(writer, "country", cert.getIssuer().country);
		serializeString(writer, "organization", cert.getIssuer().organization);
		serializeString(writer, "organizationalUnit",  cert.getIssuer().organizationalUnit);
		serializeString(writer, "nameQualifier",  cert.getIssuer().nameQualifier);
		serializeString(writer, "state", cert.getIssuer().state);
		serializeString(writer, "commonName", cert.getIssuer().commonName);
		serializeString(writer, "serialNumber", cert.getIssuer().serialNumber);
		serializeString(writer, "locality", cert.getIssuer().locality);
		serializeString(writer, "title", cert.getIssuer().title);
		serializeString(writer, "surname", cert.getIssuer().surname);
		serializeString(writer, "givenName", cert.getIssuer().givenName);
		serializeString(writer, "initials", cert.getIssuer().initials);
		serializeString(writer, "pseudonym", cert.getIssuer().pseudonym);
		serializeString(writer, "generationQualifier", cert.getIssuer().generationQualifier);
		serializeString(writer, "emailAddress", cert.getIssuer().emailAddress);
		writer.EndObject();

		writer.EndObject();

		writer.EndObject();
	}
	writer.EndArray();
}

void WriteSigner(JsonPresentation::Writer& writer, const Signer& signer)
{
	writer.StartObject();
	writer.String("warnings");
	writer.StartArray();
	for (auto&& warn : signer.warnings) {
		writer.String(warn);
	}
	writer.EndArray();

	serializeString(writer, "signTime", signer.signingTime);

	serializeString(writer, "digest", signer.digest);

	serializeString(writer, "digestAlgorithm", signer.digestAlgorithm);

	writer.String("chain");
	WriteCertificateChain(writer, signer.chain);

	writer.String("counterSigners");
	writer.StartArray();
	for (auto&& csigner : signer.counterSigners) {
		WriteSigner(writer, csigner);
	}
	writer.EndArray();

	writer.EndObject();
}

void WriteSignature(JsonPresentation::Writer& writer, const DigitalSignature& signature)
{
	writer.StartObject();
	writer.String("signatureVerified");
	writer.Bool(signature.isValid);
	writer.String("warnings");
	writer.StartArray();
	for (auto&& warn : signature.warnings) {
		writer.String(warn);
	}
	writer.EndArray();

	serializeString(writer, "digestAlgorithm", signature.digestAlgorithm);
	serializeString(writer, "fileDigest", signature.fileDigest);
	serializeString(writer, "signedDigest", signature.signedDigest);
	serializeString(writer, "programName", signature.programName);

	writer.String("allCertificates");
	WriteCertificateChain(writer, signature.certificates);

	writer.String("signer");
	WriteSigner(writer, signature.signer);

	writer.EndObject();
}

/**
 * Present information about certificates into certificate table
 */
void JsonPresentation::presentCertificates(Writer& writer) const
{

	if (!fileinfo.certificateTable || !fileinfo.certificateTable->isOutsideImage)
	{
		return;
	}
	writer.String("digitalSignatures");

	writer.StartObject();
	writer.Key("numberOfSignatures");
	writer.Int64(fileinfo.certificateTable->signatures.size());
	writer.String("signatures");
	writer.StartArray();
	for (auto&& signature : fileinfo.certificateTable->signatures)
	{
		WriteSignature(writer, signature);
	}
	writer.EndArray();
	writer.EndObject();
}

/**
 * Present information about TLS
 */
void JsonPresentation::presentTlsInfo(Writer& writer) const
{
	if (!fileinfo.isTlsUsed())
	{
		return;
	}

	writer.String("tlsInfo");
	writer.StartObject();

	serializeString(writer, "rawDataStartAddress", fileinfo.getTlsRawDataStartAddrStr(hexWithPrefix));
	serializeString(writer, "rawDataEndAddress", fileinfo.getTlsRawDataEndAddrStr(hexWithPrefix));
	serializeString(writer, "indexAddress", fileinfo.getTlsIndexAddrStr(hexWithPrefix));
	serializeString(writer, "callbacksAddress", fileinfo.getTlsCallBacksAddrStr(hexWithPrefix));
	serializeString(writer, "sizeOfZeroFill", fileinfo.getTlsZeroFillSizeStr(std::dec));
	serializeString(writer, "characteristics", fileinfo.getTlsCharacteristicsStr());

	if (fileinfo.getTlsNumberOfCallBacks() > 0)
	{
		writer.String("callbacks");
		writer.StartArray();
		for (std::size_t i = 0; i < fileinfo.getTlsNumberOfCallBacks(); i++)
		{
			writer.String(fileinfo.getTlsCallBackAddrStr(i, hexWithPrefix));
		}
		writer.EndArray();
	}

	writer.EndObject();
}

/**
 * Present information about .NET
 */
void JsonPresentation::presentDotnetInfo(Writer& writer) const
{
	if (!fileinfo.isDotnetUsed())
	{
		return;
	}

	writer.String("dotnetInfo");
	writer.StartObject();

	// Basic info.
	//
	serializeString(
			writer,
			"runtimeVersion",
			fileinfo.getDotnetRuntimeVersion());
	serializeString(
			writer,
			"metadataHeaderAddress",
			fileinfo.getDotnetMetadataHeaderAddressStr(hexWithPrefix));
	serializeString(
			writer,
			"moduleVersionId",
			fileinfo.getDotnetModuleVersionId());
	if (fileinfo.hasDotnetTypeLibId())
	{
		serializeString(writer, "typeLibId", fileinfo.getDotnetTypeLibId());
	}

	// Streams.
	//
	if (fileinfo.hasDotnetMetadataStream())
	{
		writer.String("metadataStream");
		writer.StartObject();
		serializeString(
				writer,
				"offset",
				fileinfo.getDotnetMetadataStreamOffsetStr(hexWithPrefix));
		serializeString(
				writer,
				"size",
				fileinfo.getDotnetMetadataStreamSizeStr(hexWithPrefix));
		writer.EndObject();
	}
	if (fileinfo.hasDotnetStringStream())
	{
		writer.String("stringStream");
		writer.StartObject();
		serializeString(
				writer,
				"offset",
				fileinfo.getDotnetStringStreamOffsetStr(hexWithPrefix));
		serializeString(
				writer,
				"size",
				fileinfo.getDotnetStringStreamSizeStr(hexWithPrefix));
		writer.EndObject();
	}
	if (fileinfo.hasDotnetBlobStream())
	{
		writer.String("blobStream");
		writer.StartObject();
		serializeString(
				writer,
				"offset",
				fileinfo.getDotnetBlobStreamOffsetStr(hexWithPrefix));
		serializeString(
				writer,
				"size",
				fileinfo.getDotnetBlobStreamSizeStr(hexWithPrefix));
		writer.EndObject();
	}
	if (fileinfo.hasDotnetGuidStream())
	{
		writer.String("guidStream");
		writer.StartObject();
		serializeString(
				writer,
				"offset",
				fileinfo.getDotnetGuidStreamOffsetStr(hexWithPrefix));
		serializeString(
				writer,
				"size",
				fileinfo.getDotnetGuidStreamSizeStr(hexWithPrefix));
		writer.EndObject();
	}
	if (fileinfo.hasDotnetUserStringStream())
	{
		writer.String("userStringStream");
		writer.StartObject();
		serializeString(
				writer,
				"offset",
				fileinfo.getDotnetUserStringStreamOffsetStr(hexWithPrefix));
		serializeString(
				writer,
				"size",
				fileinfo.getDotnetUserStringStreamSizeStr(hexWithPrefix));
		writer.EndObject();
	}

	// Classes.
	//
	const auto& classes = fileinfo.getDotnetDefinedClassList();
	if (!classes.empty())
	{
		writer.String("classes");
		writer.StartArray();

		for (const auto& dotnetClass : classes)
		{
			writer.StartObject();

			serializeString(writer, "name", dotnetClass->getName());
			serializeString(writer, "fullyQualifiedName", dotnetClass->getFullyQualifiedName());
			serializeString(writer, "namespace", dotnetClass->getNameSpace());
			serializeString(writer, "visibility", dotnetClass->getVisibilityString());
			serializeString(writer, "type", dotnetClass->getTypeString());
			serdes::serializeBool(writer, "abstract", dotnetClass->isAbstract());
			serdes::serializeBool(writer, "sealed", dotnetClass->isSealed());

			serdes::serializeContainer(
					writer,
					"genericParameters",
					dotnetClass->getGenericParameters());

			if (!dotnetClass->getBaseTypes().empty())
			{
				writer.String("baseTypes");
				writer.StartArray();
				for (const auto& baseType : dotnetClass->getBaseTypes())
				{
					writer.String(utils::replaceNonprintableChars(baseType->getText()));
				}
				writer.EndArray();
			}

			if (!dotnetClass->getMethods().empty())
			{
				writer.String("methods");
				writer.StartArray();
				for (const auto& dotnetMethod : dotnetClass->getMethods())
				{
					writer.StartObject();

					serializeString(writer, "name", dotnetMethod->getName());
					serializeString(writer, "visibility", dotnetMethod->getVisibilityString());
					serdes::serializeBool(writer, "static", dotnetMethod->isStatic());
					serdes::serializeBool(writer, "virtual", dotnetMethod->isVirtual());
					serdes::serializeBool(writer, "final", dotnetMethod->isFinal());
					serdes::serializeBool(writer, "abstract", dotnetMethod->isAbstract());

					if (!dotnetMethod->isConstructor())
					{
						serializeString(
								writer,
								"returnType",
								dotnetMethod->getReturnType()->getText());
					}

					writer.String("parameters");
					writer.StartArray();
					for (const auto& dotnetParam : dotnetMethod->getParameters())
					{
						writer.StartObject();
						serializeString(
								writer,
								"name",
								dotnetParam->getName());
						serializeString(
								writer,
								"type",
								dotnetParam->getDataType()->getText());
						writer.EndObject();
					}
					writer.EndArray();

					if (!dotnetMethod->getGenericParameters().empty())
					{
						writer.String("genericParameters");
						writer.StartArray();
						for (const auto& genericParam : dotnetMethod->getGenericParameters())
							writer.String(
									utils::replaceNonprintableChars(genericParam));
						writer.EndArray();
					}

					writer.EndObject();
				}
				writer.EndArray();
			}

			if (!dotnetClass->getFields().empty())
			{
				writer.String("fields");
				writer.StartArray();
				for (const auto& dotnetField : dotnetClass->getFields())
				{
					writer.StartObject();
					serializeString(writer, "name", dotnetField->getName());
					serializeString(writer, "type", dotnetField->getDataType()->getText());
					serializeString(writer, "visibility", dotnetField->getVisibilityString());
					serdes::serializeBool(writer, "static", dotnetField->isStatic());
					writer.EndObject();
				}
				writer.EndArray();
			}

			if (!dotnetClass->getProperties().empty())
			{
				writer.String("properties");
				writer.StartArray();
				for (const auto& dotnetProperty : dotnetClass->getProperties())
				{
					writer.StartObject();
					serializeString(writer, "name", dotnetProperty->getName());
					serializeString(writer, "type", dotnetProperty->getDataType()->getText());
					serializeString(writer, "visibility", dotnetProperty->getVisibilityString());
					serdes::serializeBool(writer, "static", dotnetProperty->isStatic());
					writer.EndObject();
				}
				writer.EndArray();
			}

			writer.EndObject();
		}

		writer.EndArray();
	}

	presentIterativeSubtitle(writer, TypeRefTableJsonGetter(fileinfo));

	writer.EndObject();
}

/**
 * Present information about Visual Basic
 */
void JsonPresentation::presentVisualBasicInfo(Writer& writer) const
{
	if (!fileinfo.isVisualBasicUsed())
	{
		return;
	}

	writer.String("visualBasicInfo");
	writer.StartObject();

	// Basic info.
	serializeString(writer, "projectName", fileinfo.getVisualBasicProjectName());
	serializeString(writer, "projectExeName", fileinfo.getVisualBasicProjectExeName());
	serializeString(writer, "projectPath", fileinfo.getVisualBasicProjectPath());
	serializeString(writer, "projectDescription", fileinfo.getVisualBasicProjectDescription());
	serializeString(writer, "projectHelpFile", fileinfo.getVisualBasicProjectHelpFile());
	serializeString(writer, "languageDLL", fileinfo.getVisualBasicLanguageDLL());
	serializeString(writer, "backupLanguageDLL", fileinfo.getVisualBasicBackupLanguageDLL());
	serializeString(writer, "languageDLLPrimaryLCID", fileinfo.getVisualBasicLanguageDLLPrimaryLCIDStr());
	serializeString(writer, "languageDLLSecondaryLCID", fileinfo.getVisualBasicLanguageDLLSecondaryLCIDStr());
	serializeString(writer, "projectPrimaryLCID", fileinfo.getVisualBasicProjectPrimaryLCIDStr());
	serializeString(writer, "projectSecondaryLCID", fileinfo.getVisualBasicProjectSecondaryLCIDStr());
	serializeString(writer, "typeLibCLSID", fileinfo.getVisualBasicTypeLibCLSID());
	serializeString(writer, "typeLibMajorVersion", fileinfo.getVisualBasicTypeLibMajorVersionStr());
	serializeString(writer, "typeLibMinorVersion", fileinfo.getVisualBasicTypeLibMinorVersionStr());
	serializeString(writer, "typeLibLCID", fileinfo.getVisualBasicTypeLibLCIDStr());
	serializeString(writer, "comObjectName", fileinfo.getVisualBasicCOMObjectName());
	serializeString(writer, "comObjectDescription", fileinfo.getVisualBasicCOMObjectDescription());
	serializeString(writer, "comObjectCLSID", fileinfo.getVisualBasicCOMObjectCLSID());
	serializeString(writer, "comObjectInterfaceCLSID", fileinfo.getVisualBasicCOMObjectInterfaceCLSID());
	serializeString(writer, "comObjectEventsCLSID", fileinfo.getVisualBasicCOMObjectEventsCLSID());
	serializeString(writer, "comObjectType", fileinfo.getVisualBasicCOMObjectType());
	serializeString(writer, "isPCode", (fileinfo.getVisualBasicIsPcode() ? "yes" : "no"));

	if (auto nExterns = fileinfo.getVisualBasicNumberOfExterns())
	{
		writer.String("externTable");
		writer.StartObject();

		serializeString(writer, "crc32", fileinfo.getVisualBasicExternTableHashCrc32());
		serializeString(writer, "md5", fileinfo.getVisualBasicExternTableHashMd5());
		serializeString(writer, "sha256", fileinfo.getVisualBasicExternTableHashSha256());

		bool first = true;
		for (std::size_t i = 0; i < nExterns; i++)
		{
			auto ext = fileinfo.getVisualBasicExtern(i);
			if (!ext)
			{
				continue;
			}

			if (first)
			{
				writer.String("externs");
				writer.StartArray();
				first = false;
			}

			writer.StartObject();
			serializeString(writer, "moduleName", ext->getModuleName());
			serializeString(writer, "apiName", ext->getApiName());
			writer.EndObject();
		}
		if (!first)
		{
			writer.EndArray();
		}

		writer.EndObject();
	}

	auto guid = fileinfo.getVisualBasicObjectTableGUID();
	auto nObjects = fileinfo.getVisualBasicNumberOfObjects();
	if (guid.empty() && nObjects == 0)
	{
		writer.EndObject();
		return;
	}

	writer.String("objectTable");
	writer.StartObject();
	if (!guid.empty())
	{
		serializeString(writer, "guid", guid);
	}
	if (nObjects)
	{
		serializeString(writer, "crc32", fileinfo.getVisualBasicObjectTableHashCrc32());
		serializeString(writer, "md5", fileinfo.getVisualBasicObjectTableHashMd5());
		serializeString(writer, "sha256", fileinfo.getVisualBasicObjectTableHashSha256());

		bool first = true;
		for (std::size_t i = 0; i < nObjects; i++)
		{
			auto obj = fileinfo.getVisualBasicObject(i);
			if (!obj)
			{
				continue;
			}

			if (first)
			{
				writer.String("objects");
				writer.StartArray();
				first = false;
			}

			writer.StartObject();
			serializeString(writer, "name", obj->getName());
			const auto& methods = obj->getMethods();
			if (!methods.empty())
			{
				writer.String("methods");
				writer.StartArray();
				for (const auto &method : methods)
				{
					writer.String(utils::replaceNonprintableChars(method));
				}
				writer.EndArray();
			}
			writer.EndObject();
		}
		if (!first)
		{
			writer.EndArray();
		}
	}
	writer.EndObject();

	writer.EndObject();
}

/**
 * Present version information
 */
void JsonPresentation::presentVersionInfo(Writer& writer) const
{
	writer.String("versionInfo");
	writer.StartObject();

	auto nStrings = fileinfo.getNumberOfVersionInfoStrings();
	if (nStrings)
	{
		writer.String("strings");
		writer.StartArray();

		for (std::size_t i = 0; i < nStrings; i++)
		{
			writer.StartObject();
			serializeString(writer, "name", fileinfo.getVersionInfoStringName(i));
			serializeString(
					writer,
					"value",
					fileinfo.getVersionInfoStringValue(i),
					true);
			writer.EndObject();
		}

		writer.EndArray();
	}

	auto nLangs = fileinfo.getNumberOfVersionInfoLanguages();
	if (nLangs)
	{
		writer.String("languages");
		writer.StartArray();
		for (std::size_t i = 0; i < nLangs; i++)
		{
			writer.StartObject();
			serializeString(writer, "lcid", fileinfo.getVersionInfoLanguageLcid(i));
			serializeString(writer, "codePage", fileinfo.getVersionInfoLanguageCodePage(i));
			writer.EndObject();
		}
		writer.EndArray();
	}

	writer.EndObject();
}

/**
 * Present ELF notes
 */
void JsonPresentation::presentElfNotes(Writer& writer) const
{
	auto& noteSection = fileinfo.getElfNotes();
	if(noteSection.empty())
	{
		return;
	}

	writer.String("elfNotes");
	writer.StartArray();
	for(const auto& notes : noteSection)
	{
		writer.StartObject();

		if(notes.isNamedSection())
		{
			serializeString(writer, "name", notes.getSectionName());
		}
		if(notes.isMalformed())
		{
			serializeString(
					writer,
					"warning",
					notes.getErrorMessage());
		}

		serdes::serializeUint64(writer, "size", notes.getSecSegLength());
		serdes::serializeUint64(writer, "offset", notes.getSecSegOffset());
		serdes::serializeUint64(writer, "numberOfNotes", notes.getNotes().size());

		writer.String("noteEntries");
		writer.StartArray();
		std::size_t idx = 0;
		for(const auto& note : notes.getNotes())
		{
			writer.StartObject();
			serdes::serializeUint64(writer, "index", idx++);
			serializeString(writer, "owner", note.owner);
			serdes::serializeUint64(writer, "type", note.type);
			serdes::serializeUint64(writer, "dataSize", note.dataLength);
			serdes::serializeUint64(writer, "dataOffset", note.dataOffset);
			serializeString(writer, "description", note.description);
			writer.EndObject();
		}
		writer.EndArray();

		writer.EndObject();
	}
	writer.EndArray();

	const auto& core = fileinfo.getElfCoreInfo();
	if (!core.hasAuxVector() && !core.hasFileMap())
	{
		return;
	}

	writer.String("elfCore");
	writer.StartObject();

	if(core.hasAuxVector())
	{
		const auto& auxVec = core.getAuxVector();
		serdes::serializeUint64(writer, "numberOfAuxVectorEntries", auxVec.size());

		writer.String("auxVector");
		writer.StartArray();
		for(const auto& auxEntry : auxVec)
		{
			writer.StartObject();
			serializeString(writer, "name", auxEntry.first);
			serdes::serializeUint64(writer, "value", auxEntry.second);
			writer.EndObject();
		}
		writer.EndArray();
	}
	if(core.hasFileMap())
	{
		const auto& fileMap = core.getFileMap();
		serdes::serializeUint64(writer, "numberOfFileMapEntries", fileMap.size());

		writer.String("fileMap");
		writer.StartArray();
		for(const auto& mapEntry : fileMap)
		{
			writer.StartObject();
			serdes::serializeUint64(writer, "address", mapEntry.address);
			serdes::serializeUint64(writer, "size", mapEntry.size);
			serdes::serializeUint64(writer, "page", mapEntry.page);
			serializeString(writer, "path", mapEntry.path);
			writer.EndObject();
		}
		writer.EndArray();
	}

	writer.EndObject();
}

/**
 * Present information about flags
 * @param writer JSON writter
 * @param title Flags title
 * @param flags Flags in binary string representation
 * @param desc Vector of descriptors (descriptor is complete information about flag)
 */
void JsonPresentation::presentFlags(
		Writer& writer,
		const std::string &title,
		const std::string &flags,
		const std::vector<std::string> &desc) const
{
	if(flags.empty() && desc.empty())
	{
		return;
	}

	writer.String(title);
	writer.StartObject();

	serializeString(writer, "value", flags);

	if (!desc.empty())
	{
		writer.String("descriptors");
		writer.StartArray();
		for(const auto &d : desc)
		{
			writer.String(d);
		}
		writer.EndArray();
	}

	writer.EndObject();
}

/**
 * Present information from one structure of iterative subtitle getter
 */
void JsonPresentation::presentIterativeSubtitleStructure(
		Writer& writer,
		const IterativeSubtitleGetter &getter,
		std::size_t structIndex) const
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

	bool genArray = false;
	if (simplyStructure)
	{
		writer.String(title);

		if (!basicLen)
		{
			writer.StartArray();
			genArray = true;
		}
	}
	if (!genArray)
	{
		writer.StartObject();
	}

	for(std::size_t i = 0; i < basicLen; ++i)
	{
		if(!desc[i].empty() && !info[i].empty())
		{
			serializeString(writer, desc[i], info[i]);
		}
	}

	const auto elements = getter.getHeaderElements(structIndex, desc);
	std::string flags;
	std::vector<std::string> flagsDesc;

	if (!genArray)
	{
		writer.String(subtitle);
		writer.StartArray();
	}
	for(std::size_t i = 0; getter.getRecord(structIndex, i, info); ++i)
	{
		writer.StartObject();
		for(std::size_t j = 0; j < elements; ++j)
		{
			if(!desc[j].empty() && !info[j].empty())
			{
				serializeString(writer, desc[j], info[j]);
			}
		}
		getter.getFlags(structIndex, i, flags, flagsDesc);
		presentFlags(writer, "flags", flags, flagsDesc);
		writer.EndObject();
	}
	if (!genArray)
	{
		writer.EndArray();
	}

	if (genArray)
	{
		writer.EndArray();
	}
	else
	{
		writer.EndObject();
	}
}

/**
 * Present information from iterative subtitle getter
 */
void JsonPresentation::presentIterativeSubtitle(
		Writer& writer,
		const IterativeSubtitleGetter &getter) const
{
	if (getter.getNumberOfStructures() == 0)
	{
		return;
	}

	std::string header;
	getter.getHeader(header);
	if (!header.empty())
	{
		writer.String(header);
		writer.StartArray();
	}

	for(std::size_t i = 0, e = getter.getNumberOfStructures(); i < e; ++i)
	{
		presentIterativeSubtitleStructure(writer, getter, i);
	}

	if (!header.empty())
	{
		writer.EndArray();
	}
}

bool JsonPresentation::present()
{
	rapidjson::StringBuffer sb;
	Writer writer(sb);
	writer.StartObject();

	if(verbose)
	{
		presentFileinfoVersion(writer);
	}

	serializeString(writer, "inputFile", fileinfo.getPathToFile());

	presentErrors(writer);
	presentLoaderError(writer);
	presentSimple(BasicJsonGetter(fileinfo), writer);
	presentSimple(EntryPointJsonGetter(fileinfo), writer, "entryPoint");
	presentCompiler(writer);
	presentLanguages(writer);
	presentOverlay(writer);

	if(verbose)
	{
		std::string flags, title;
		std::vector<std::string> desc, info;

		presentPackingInfo(writer);

		HeaderJsonGetter headerInfo(fileinfo);
		presentSimple(headerInfo, writer);
		headerInfo.getFileFlags(title, flags, desc, info);
		presentFlags(writer, title, flags, desc);
		headerInfo.getDllFlags(title, flags, desc, info);
		presentFlags(writer, title, flags, desc);

		presentSimple(PdbJsonGetter(fileinfo), writer, "pdbInfo");

		presentIterativeSubtitle(writer, RichHeaderJsonGetter(fileinfo));
		presentIterativeSubtitle(writer, DataDirectoryJsonGetter(fileinfo));
		presentIterativeSubtitle(writer, SegmentJsonGetter(fileinfo));
		presentIterativeSubtitle(writer, SectionJsonGetter(fileinfo));
		presentIterativeSubtitle(writer, SymbolTablesJsonGetter(fileinfo));
		presentIterativeSubtitle(writer, ImportTableJsonGetter(fileinfo));
		presentIterativeSubtitle(writer, ExportTableJsonGetter(fileinfo));
		presentIterativeSubtitle(writer, RelocationTablesJsonGetter(fileinfo));
		presentIterativeSubtitle(writer, DynamicSectionsJsonGetter(fileinfo));
		presentIterativeSubtitle(writer, ResourceJsonGetter(fileinfo));
		presentIterativeSubtitle(writer, AnomaliesJsonGetter(fileinfo));
		const auto manifest = fileinfo.getCompactManifest();
		if(!manifest.empty())
		{
			serializeString(writer, "manifest", manifest);
		}
		presentElfNotes(writer);
		presentMissingDepsInfo(writer);
		presentLoaderInfo(writer);
		presentPatterns(writer);
		presentCertificates(writer);
		presentTlsInfo(writer);
		presentDotnetInfo(writer);
		presentVisualBasicInfo(writer);
		presentVersionInfo(writer);
	}
	else
	{
		presentRichHeader(writer);
	}

	presentIterativeSubtitle(writer, StringsJsonGetter(fileinfo));

	writer.EndObject();
	Log::info() << sb.GetString() << std::endl;

	return true;
}

} // namespace fileinfo
} // namespace retdec
