/**
 * @file include/retdec/common/architecture.h
 * @brief Common architecture representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_COMMON_ARCHITECTURE_H
#define RETDEC_COMMON_ARCHITECTURE_H

#include <string>

namespace retdec {
namespace common {

/**
 * Represents input binary's target architecture.
 */
class Architecture
{
	public:
		/// @name Architecture query methods.
		/// @{
		bool isUnknown() const;
		bool isKnown() const;
		bool isMips() const;
		bool isMips64() const;
		bool isPic32() const;
		bool isMipsOrPic32() const;
		bool isArm() const;
		bool isArm32() const;
		bool isArm64() const;
		bool isThumb() const;
		bool isArm32OrThumb() const;
		bool isX86() const;
		bool isX86_16() const;
		bool isX86_32() const;
		bool isX86_64() const;
		bool isPpc() const;
		bool isPpc64() const;
		bool isEndianLittle() const;
		bool isEndianBig() const;
		bool isEndianKnown() const;
		bool isEndianUnknown() const;
		/// @}

		/// @name Architecture set methods.
		/// @{
		void setIsUnknown();
		void setIsMips();
		void setIsPic32();
		void setIsArm();
		void setIsThumb();
		void setIsArm32();
		void setIsArm64();
		void setIsX86();
		void setIsPpc();
		void setIsEndianLittle();
		void setIsEndianBig();
		void setIsEndianUnknown();
		void setName(const std::string &n);
		void setBitSize(unsigned bs);
		/// @}

		/// @name Architecture get methods.
		/// @{
		std::string getName() const;
		unsigned getBitSize() const;
		unsigned getByteSize() const;
		/// @}

	private:
		enum eEndian
		{
			E_UNKNOWN,
			E_LITTLE,
			E_BIG
		};

		enum class eArch
		{
			UNKNOWN,
			MIPS,
			PIC32,
			ARM,
			X86,
			PPC,
		};

	private:
		bool isArch(const std::string& a) const;
		bool isArch(eArch a) const;
		void setArch();

	private:
		std::string _name;
		unsigned _bitSize = 32;
		bool _thumbFlag = false;
		eEndian _endian = E_UNKNOWN;
		eArch _arch = eArch::UNKNOWN;
};

} // namespace common
} // namespace retdec

#endif
