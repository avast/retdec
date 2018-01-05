/**
 * @file include/retdec/config/patterns.h
 * @brief Decompilation configuration manipulation: patterns.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_PATTERNS_H
#define RETDEC_CONFIG_PATTERNS_H

#include <string>

#include "retdec/config/base.h"
#include "retdec/utils/value.h"

namespace retdec {
namespace config {

/**
 * Represents pattern (e.g. crypto signature, malware) found in binary.
 */
class Pattern
{
	public:
		class Match
		{
			public:
				Match();
				static Match unknown(
						const retdec::utils::Address& offset
							= retdec::utils::Address::getUndef,
						const retdec::utils::Address& address
							= retdec::utils::Address::getUndef,
						retdec::utils::Maybe<unsigned> size
							= retdec::utils::Maybe<unsigned>(),
						retdec::utils::Maybe<unsigned> entrySize
							= retdec::utils::Maybe<unsigned>());
				static Match integral(
						const retdec::utils::Address& offset
							= retdec::utils::Address::getUndef,
						const retdec::utils::Address& address
							= retdec::utils::Address::getUndef,
						retdec::utils::Maybe<unsigned> size
							= retdec::utils::Maybe<unsigned>(),
						retdec::utils::Maybe<unsigned> entrySize
							= retdec::utils::Maybe<unsigned>());
				static Match floatingPoint(
						const retdec::utils::Address& offset
							= retdec::utils::Address::getUndef,
						const retdec::utils::Address& address
							= retdec::utils::Address::getUndef,
						retdec::utils::Maybe<unsigned> size
							= retdec::utils::Maybe<unsigned>(),
						retdec::utils::Maybe<unsigned> entrySize
							= retdec::utils::Maybe<unsigned>());

				bool operator==(const Match& val) const;
				bool operator!=(const Match& val) const;

				static Match fromJsonValue(const Json::Value& val);
				Json::Value getJsonValue() const;

				/// @name Match query methods.
				/// @{
				bool isOffsetDefined() const;
				bool isAddressDefined() const;
				bool isSizeDefined() const;
				bool isEntrySizeDefined() const;
				bool isTypeUnknown() const;
				bool isTypeIntegral() const;
				bool isTypeFloatingPoint() const;
				/// @}

				/// @name Tool set methods.
				/// @{
				void setOffset(const retdec::utils::Address& offset);
				void setAddress(const retdec::utils::Address& address);
				void setSize(const unsigned size);
				void setEntrySize(const unsigned entrySize);
				void setIsTypeUnknown();
				void setIsTypeIntegral();
				void setIsTypeFloatingPoint();
				/// @}

				/// @name Tool get methods.
				/// @{
				retdec::utils::Address getOffset() const;
				retdec::utils::Address getAddress() const;
				retdec::utils::Maybe<unsigned> getSize() const;
				retdec::utils::Maybe<unsigned> getEntrySize() const;
				/// @}

			private:
				enum class eType
				{
					UNKNOWN,
					INTEGRAL,
					FLOATING_POINT
				};

			private:
				Match(const retdec::utils::Address& offset,
						const retdec::utils::Address& address,
						retdec::utils::Maybe<unsigned> size,
						retdec::utils::Maybe<unsigned> entrySize,
						eType type);

			private:
				retdec::utils::Address _offset;
				retdec::utils::Address _address;
				retdec::utils::Maybe<unsigned> _size;
				retdec::utils::Maybe<unsigned> _entrySize;
				eType _type = eType::UNKNOWN;
		};

	public:
		Pattern();
		static Pattern other(
				const std::string& name = "",
				const std::string& description = "",
				const std::string& yaraRuleName = "");
		static Pattern otherLittle(
				const std::string& name = "",
				const std::string& description = "",
				const std::string& yaraRuleName = "");
		static Pattern otherBig(
				const std::string& name = "",
				const std::string& description = "",
				const std::string& yaraRuleName = "");
		static Pattern crypto(
				const std::string& name = "",
				const std::string& description = "",
				const std::string& yaraRuleName = "");
		static Pattern cryptoLittle(
				const std::string& name = "",
				const std::string& description = "",
				const std::string& yaraRuleName = "");
		static Pattern cryptoBig(
				const std::string& name = "",
				const std::string& description = "",
				const std::string& yaraRuleName = "");
		static Pattern malware(
				const std::string& name = "",
				const std::string& description = "",
				const std::string& yaraRuleName = "");
		static Pattern malwareLittle(
				const std::string& name = "",
				const std::string& description = "",
				const std::string& yaraRuleName = "");
		static Pattern malwareBig(
				const std::string& name = "",
				const std::string& description = "",
				const std::string& yaraRuleName = "");

		bool operator==(const Pattern& val) const;
		bool operator!=(const Pattern& val) const;

		static Pattern fromJsonValue(const Json::Value& val);
		Json::Value getJsonValue() const;

		/// @name Pattern query methods.
		/// @{
		bool isTypeOther() const;
		bool isTypeCrypto() const;
		bool isTypeMalware() const;
		bool isEndianUnknown() const;
		bool isEndianLittle() const;
		bool isEndianBig() const;
		/// @}

		/// @name Pattern set methods.
		/// @{
		void setName(const std::string& name);
		void setDescription(const std::string& description);
		void setYaraRuleName(const std::string& yaraRuleName);
		void setIsTypeOther();
		void setIsTypeCrypto();
		void setIsTypeMalware();
		void setIsEndianUnknown();
		void setIsEndianLittle();
		void setIsEndianBig();
		/// @}

		/// @name Pattern get methods.
		/// @{
		std::string getName() const;
		std::string getDescription() const;
		std::string getYaraRuleName() const;
		/// @}

	private:
		enum class eType
		{
			OTHER,
			CRYPTO,
			MALWARE
		};

		enum class eEndian
		{
			UNKNOWN,
			LITTLE,
			BIG
		};

	private:
		Pattern(const std::string& name,
				const std::string& description,
				const std::string& yaraRuleName,
				eType type,
				eEndian endian);

	public:
		BaseSequentialContainer<Match> matches;

	private:
		std::string _name;
		std::string _description;
		std::string _yaraRuleName;
		eType _type = eType::OTHER;
		eEndian _endian = eEndian::UNKNOWN;
};

/**
 * Sequential container of pattern informations.
 */
class PatternContainer : public BaseSequentialContainer<Pattern>
{

};

} // namespace config
} // namespace retdec

#endif
