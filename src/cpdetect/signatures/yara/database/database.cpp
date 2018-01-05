/**
 * @file src/cpdetect/signatures/yara/database/database.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "cpdetect/signatures/yara/database/arm/elf/compiler.h"
#include "cpdetect/signatures/yara/database/arm/elf/packer.h"
#include "cpdetect/signatures/yara/database/arm/macho/compiler.h"
#include "cpdetect/signatures/yara/database/arm/macho/packer.h"
#include "cpdetect/signatures/yara/database/arm/pe/compiler.h"
#include "cpdetect/signatures/yara/database/arm/pe/packer.h"
#include "cpdetect/signatures/yara/database/database.h"
#include "cpdetect/signatures/yara/database/mips/elf/compiler.h"
#include "cpdetect/signatures/yara/database/mips/elf/packer.h"
#include "cpdetect/signatures/yara/database/mips/macho/compiler.h"
#include "cpdetect/signatures/yara/database/mips/macho/packer.h"
#include "cpdetect/signatures/yara/database/mips/pe/compiler.h"
#include "cpdetect/signatures/yara/database/mips/pe/packer.h"
#include "cpdetect/signatures/yara/database/powerpc/elf/compiler.h"
#include "cpdetect/signatures/yara/database/powerpc/elf/packer.h"
#include "cpdetect/signatures/yara/database/powerpc/macho/compiler.h"
#include "cpdetect/signatures/yara/database/powerpc/macho/packer.h"
#include "cpdetect/signatures/yara/database/powerpc/pe/compiler.h"
#include "cpdetect/signatures/yara/database/powerpc/pe/packer.h"
#include "cpdetect/signatures/yara/database/x86/elf/compiler_01.h"
#include "cpdetect/signatures/yara/database/x86/elf/compiler_02.h"
#include "cpdetect/signatures/yara/database/x86/elf/packer.h"
#include "cpdetect/signatures/yara/database/x86/macho/compiler.h"
#include "cpdetect/signatures/yara/database/x86/macho/packer.h"
#include "cpdetect/signatures/yara/database/x86/pe/compiler/compiler_01.h"
#include "cpdetect/signatures/yara/database/x86/pe/compiler/compiler_02.h"
#include "cpdetect/signatures/yara/database/x86/pe/compiler/compiler_03.h"
#include "cpdetect/signatures/yara/database/x86/pe/compiler/compiler_04.h"
#include "cpdetect/signatures/yara/database/x86/pe/compiler/compiler_05.h"
#include "cpdetect/signatures/yara/database/x86/pe/compiler/compiler_06.h"
#include "cpdetect/signatures/yara/database/x86/pe/compiler/compiler_07.h"
#include "cpdetect/signatures/yara/database/x86/pe/compiler/compiler_08.h"
#include "cpdetect/signatures/yara/database/x86/pe/compiler/compiler_09.h"
#include "cpdetect/signatures/yara/database/x86/pe/compiler/compiler_10.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_01.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_02.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_03.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_04.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_05.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_06.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_07.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_08.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_09.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_10.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_11.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_12.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_13.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_14.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_15.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_16.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_17.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_18.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_19.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_20.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_21.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_22.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_23.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_24.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_25.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_26.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_27.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_28.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_29.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_30.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_31.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_32.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_33.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_34.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_35.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_36.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_37.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_38.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_39.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_40.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_41.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_42.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_43.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_44.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_45.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_46.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_47.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_48.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_49.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_50.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_51.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_52.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_53.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_54.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_55.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_56.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_57.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_58.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_59.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_60.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_61.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_62.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_63.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_64.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_65.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_66.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_67.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_68.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_69.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_70.h"
#include "cpdetect/signatures/yara/database/x86/pe/packer/packer_71.h"

namespace cpdetect {

namespace
{

template<typename T>
auto operator+(std::vector<T> v1, const std::vector<T>& v2)
{
	v1.insert(v1.end(), v2.begin(), v2.end());
	return v1;
}

const std::vector<const char*> armElf =
{
		armElfCompiler,
		armElfPacker
};
const std::vector<const char*> mipsElf =
{
		mipsElfCompiler,
		mipsElfPacker
};
const std::vector<const char*> powerPcElf =
{
		powerpcElfCompiler,
		powerpcElfPacker
};
const std::vector<const char*> x86Elf =
{
		x86ElfCompiler_01,
		x86ElfCompiler_02,
		x86ElfPacker
};
const std::vector<const char*> armMachO =
{
		armMachOCompiler,
		armMachOPacker
};
const std::vector<const char*> mipsMachO =
{
		mipsMachOCompiler,
		mipsMachOPacker
};
const std::vector<const char*> powerPcMachO =
{
		powerpcMachOCompiler,
		powerpcMachOPacker
};
const std::vector<const char*> x86MachO =
{
		x86MachOCompiler,
		x86MachOPacker
};
const std::vector<const char*> fatMacho =
{
		x86MachOCompiler,
		x86MachOPacker,
		armMachOCompiler,
		armMachOPacker,
		powerpcMachOCompiler,
		powerpcMachOPacker
};
const std::vector<const char*> armPe =
{
		armPeCompiler,
		armPePacker};
const std::vector<const char*> mipsPe =
{
		mipsPeCompiler,
		mipsPePacker
};
const std::vector<const char*> powerPcPe =
{
		powerpcPeCompiler,
		powerpcPePacker
};
const std::vector<const char*> x86Pe =
{
	x86PeCompiler_01,
	x86PeCompiler_02,
	x86PeCompiler_03,
	x86PeCompiler_04,
	x86PeCompiler_05,
	x86PeCompiler_06,
	x86PeCompiler_07,
	x86PeCompiler_08,
	x86PeCompiler_09,
	x86PeCompiler_10,
	x86PePacker_01,
	x86PePacker_02,
	x86PePacker_03,
	x86PePacker_04,
	x86PePacker_05,
	x86PePacker_06,
	x86PePacker_07,
	x86PePacker_08,
	x86PePacker_09,
	x86PePacker_10,
	x86PePacker_11,
	x86PePacker_12,
	x86PePacker_13,
	x86PePacker_14,
	x86PePacker_15,
	x86PePacker_16,
	x86PePacker_17,
	x86PePacker_18,
	x86PePacker_19,
	x86PePacker_20,
	x86PePacker_21,
	x86PePacker_22,
	x86PePacker_23,
	x86PePacker_24,
	x86PePacker_25,
	x86PePacker_26,
	x86PePacker_27,
	x86PePacker_28,
	x86PePacker_29,
	x86PePacker_30,
	x86PePacker_31,
	x86PePacker_32,
	x86PePacker_33,
	x86PePacker_34,
	x86PePacker_35,
	x86PePacker_36,
	x86PePacker_37,
	x86PePacker_38,
	x86PePacker_39,
	x86PePacker_40,
	x86PePacker_41,
	x86PePacker_42,
	x86PePacker_43,
	x86PePacker_44,
	x86PePacker_45,
	x86PePacker_46,
	x86PePacker_47,
	x86PePacker_48,
	x86PePacker_49,
	x86PePacker_50,
	x86PePacker_51,
	x86PePacker_52,
	x86PePacker_53,
	x86PePacker_54,
	x86PePacker_55,
	x86PePacker_56,
	x86PePacker_57,
	x86PePacker_58,
	x86PePacker_59,
	x86PePacker_60,
	x86PePacker_61,
	x86PePacker_62,
	x86PePacker_63,
	x86PePacker_64,
	x86PePacker_65,
	x86PePacker_66,
	x86PePacker_67,
	x86PePacker_68,
	x86PePacker_69,
	x86PePacker_70,
	x86PePacker_71
};
const std::vector<const char*> arm = armElf + armMachO + armPe;
const std::vector<const char*> mips = mipsElf + mipsMachO + mipsPe;
const std::vector<const char*> powerPc = powerPcElf + powerPcMachO + powerPcPe;
const std::vector<const char*> x86 = x86Elf + x86MachO + x86Pe;

} // anonymous namespace

/**
 * Get ARM ELF signatures
 */
const std::vector<const char*>* getArmElfDatabase()
{
	return &armElf;
}

/**
 * Get MIPS ELF signatures
 */
const std::vector<const char*>* getMipsElfDatabase()
{
	return &mipsElf;
}

/**
 * Get PowerPC ELF signatures
 */
const std::vector<const char*>* getPowerPcElfDatabase()
{
	return &powerPcElf;
}

/**
 * Get x86 ELF signatures
 */
const std::vector<const char*>* getX86ElfDatabase()
{
	return &x86Elf;
}

/**
 * Get ARM Mach-O signatures
 */
const std::vector<const char*>* getArmMachODatabase()
{
	return &armMachO;
}

/**
 * Get MIPS Mach-O signatures
 */
const std::vector<const char*>* getMipsMachODatabase()
{
	return &mipsMachO;
}

/**
 * Get PowerPC Mach-O signatures
 */
const std::vector<const char*>* getPowerPcMachODatabase()
{
	return &powerPcMachO;
}

/**
 * Get x86 Mach-O signatures
 */
const std::vector<const char*>* getX86MachODatabase()
{
	return &x86MachO;
}

/**
 * Get all Mach-O signatures for fat binaries
 */
const std::vector<const char*>* getFatMachoDatabase()
{
	return &fatMacho;
}

/**
 * Get ARM PE signatures
 */
const std::vector<const char*>* getArmPeDatabase()
{
	return &armPe;
}

/**
 * Get MIPS PE signatures
 */
const std::vector<const char*>* getMipsPeDatabase()
{
	return &mipsPe;
}

/**
 * Get PowerPC PE signatures
 */
const std::vector<const char*>* getPowerPcPeDatabase()
{
	return &powerPcPe;
}

/**
 * Get x86 PE signatures
 */
const std::vector<const char*>* getX86PeDatabase()
{
	return &x86Pe;
}

/**
 * Get ARM signatures
 */
const std::vector<const char*>* getArmDatabase()
{
	return &arm;
}

/**
 * Get MIPS signatures
 */
const std::vector<const char*>* getMipsDatabase()
{
	return &mips;
}

/**
 * Get PowerPC signatures
 */
const std::vector<const char*>* getPowerPcDatabase()
{
	return &powerPc;
}

/**
 * Get x86 signatures
 */
const std::vector<const char*>* getX86Database()
{
	return &x86;
}

} // namespace cpdetect
