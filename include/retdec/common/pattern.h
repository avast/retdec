/**
 * @file include/retdec/common/pattern.h
 * @brief Common pattern representation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_COMMON_PATTERN_H
#define RETDEC_COMMON_PATTERN_H

#include <string>
#include <optional>

#include "retdec/common/address.h"

namespace retdec {
namespace common {

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
						const retdec::common::Address& offset
							= retdec::common::Address::Undefined,
						const retdec::common::Address& address
							= retdec::common::Address::Undefined,
						std::optional<unsigned> size = std::nullopt,
						std::optional<unsigned> entrySize = std::nullopt);
				static Match integral(
						const retdec::common::Address& offset
							= retdec::common::Address::Undefined,
						const retdec::common::Address& address
							= retdec::common::Address::Undefined,
						std::optional<unsigned> size = std::nullopt,
						std::optional<unsigned> entrySize = std::nullopt);
				static Match floatingPoint(
						const retdec::common::Address& offset
							= retdec::common::Address::Undefined,
						const retdec::common::Address& address
							= retdec::common::Address::Undefined,
						std::optional<unsigned> size = std::nullopt,
						std::optional<unsigned> entrySize = std::nullopt);

				bool operator==(const Match& val) const;
				bool operator!=(const Match& val) const;

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
				void setOffset(const retdec::common::Address& offset);
				void setAddress(const retdec::common::Address& address);
				void setSize(const unsigned size);
				void setEntrySize(const unsigned entrySize);
				void setIsTypeUnknown();
				void setIsTypeIntegral();
				void setIsTypeFloatingPoint();
				/// @}

				/// @name Tool get methods.
				/// @{
				retdec::common::Address getOffset() const;
				retdec::common::Address getAddress() const;
				std::optional<unsigned> getSize() const;
				std::optional<unsigned> getEntrySize() const;
				/// @}

			private:
				enum class eType
				{
					UNKNOWN,
					INTEGRAL,
					FLOATING_POINT
				};

			private:
				Match(const retdec::common::Address& offset,
						const retdec::common::Address& address,
						std::optional<unsigned> size,
						std::optional<unsigned> entrySize,
						eType type);

			private:
				retdec::common::Address _offset;
				retdec::common::Address _address;
				std::optional<unsigned> _size;
				std::optional<unsigned> _entrySize;
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
		std::vector<Match> matches;

	private:
		std::string _name;
		std::string _description;
		std::string _yaraRuleName;
		eType _type = eType::OTHER;
		eEndian _endian = eEndian::UNKNOWN;
};

using PatternContainer = std::vector<Pattern>;

} // namespace common
} // namespace retdec

#endif
