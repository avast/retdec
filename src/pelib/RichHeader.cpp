/**
 * @file RichHeader.cpp
 * @brief Class for rich header.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cstring>
#include <sstream>
#include <iomanip>
#include <array>
#include <unordered_map>
#include <algorithm>

#include "retdec/pelib/PeLibInc.h"
#include "retdec/pelib/RichHeader.h"

namespace PeLib
{
	// Map of richHeaderProductId -> ProductName
	const std::vector<std::string> productNames =
	{
		"Import        (old)",      // 0x00
		"Import",                   // 0x01
		"Linker510",                // 0x02
		"Cvtomf510",                // 0x03
		"Linker600",                // 0x04
		"Cvtomf600",                // 0x05
		"Cvtres500",                // 0x06
		"Utc11_Basic",              // 0x07
		"Utc11_C",                  // 0x08
		"Utc12_Basic",              // 0x09
		"Utc12_C",                  // 0x0A
		"Utc12_CPP",                // 0x0B
		"AliasObj60",               // 0x0C
		"VisualBasic60",            // 0x0D
		"Masm613",                  // 0x0E
		"Masm710",                  // 0x0F
		"Linker511",                // 0x10
		"Cvtomf511",                // 0x11
		"Masm614",                  // 0x12
		"Linker512",                // 0x13
		"Cvtomf512",                // 0x14
		"Utc12_C_Std",              // 0x15
		"Utc12_CPP_Std",            // 0x16
		"Utc12_C_Book",             // 0x17
		"Utc12_CPP_Book",           // 0x18
		"Implib700",                // 0x19
		"Cvtomf700",                // 0x1A
		"Utc13_Basic",              // 0x1B
		"Utc13_C",                  // 0x1C
		"Utc13_CPP",                // 0x1D
		"Linker610",                // 0x1E
		"Cvtomf610",                // 0x1F
		"Linker601",                // 0x20
		"Cvtomf601",                // 0x21
		"Utc12_1_Basic",            // 0x22
		"Utc12_1_C",                // 0x23
		"Utc12_1_CPP",              // 0x24
		"Linker620",                // 0x25
		"Cvtomf620",                // 0x26
		"AliasObj70",               // 0x27
		"Linker621",                // 0x28
		"Cvtomf621",                // 0x29
		"Masm615",                  // 0x2A
		"Utc13_LTCG_C",             // 0x2B
		"Utc13_LTCG_CPP",           // 0x2C
		"Masm620",                  // 0x2D
		"ILAsm100",                 // 0x2E
		"Utc12_2_Basic",            // 0x2F
		"Utc12_2_C",                // 0x30
		"Utc12_2_CPP",              // 0x31
		"Utc12_2_C_Std",            // 0x32
		"Utc12_2_CPP_Std",          // 0x33
		"Utc12_2_C_Book",           // 0x34
		"Utc12_2_CPP_Book",         // 0x35
		"Implib622",                // 0x36
		"Cvtomf622",                // 0x37
		"Cvtres501",                // 0x38
		"Utc13_C_Std",              // 0x39
		"Utc13_CPP_Std",            // 0x3A
		"Cvtpgd1300",               // 0x3B
		"Linker622",                // 0x3C
		"Linker700",                // 0x3D
		"Export622",                // 0x3E
		"Export700",                // 0x3F
		"Masm700",                  // 0x40
		"Utc13_POGO_I_C",           // 0x41
		"Utc13_POGO_I_CPP",         // 0x42
		"Utc13_POGO_O_C",           // 0x43
		"Utc13_POGO_O_CPP",         // 0x44
		"Cvtres700",                // 0x45
		"Cvtres710p",               // 0x46
		"Linker710p",               // 0x47
		"Cvtomf710p",               // 0x48
		"Export710p",               // 0x49
		"Implib710p",               // 0x4A
		"Masm710p",                 // 0x4B
		"Utc1310p_C",               // 0x4C
		"Utc1310p_CPP",             // 0x4D
		"Utc1310p_C_Std",           // 0x4E
		"Utc1310p_CPP_Std",         // 0x4F
		"Utc1310p_LTCG_C",          // 0x50
		"Utc1310p_LTCG_CPP",        // 0x51
		"Utc1310p_POGO_I_C",        // 0x52
		"Utc1310p_POGO_I_CPP",      // 0x53
		"Utc1310p_POGO_O_C",        // 0x54
		"Utc1310p_POGO_O_CPP",      // 0x55
		"Linker624",                // 0x56
		"Cvtomf624",                // 0x57
		"Export624",                // 0x58
		"Implib624",                // 0x59
		"Linker710",                // 0x5A
		"Cvtomf710",                // 0x5B
		"Export710",                // 0x5C
		"Implib710",                // 0x5D
		"Cvtres710",                // 0x5E
		"Utc1310_C",                // 0x5F
		"Utc1310_CPP",              // 0x60
		"Utc1310_C_Std",            // 0x61
		"Utc1310_CPP_Std",          // 0x62
		"Utc1310_LTCG_C",           // 0x63
		"Utc1310_LTCG_CPP",         // 0x64
		"Utc1310_POGO_I_C",         // 0x65
		"Utc1310_POGO_I_CPP",       // 0x66
		"Utc1310_POGO_O_C",         // 0x67
		"Utc1310_POGO_O_CPP",       // 0x68
		"AliasObj710",              // 0x69
		"AliasObj710p",             // 0x6A
		"Cvtpgd1310",               // 0x6B
		"Cvtpgd1310p",              // 0x6C
		"Utc1400_C",                // 0x6D
		"Utc1400_CPP",              // 0x6E
		"Utc1400_C_Std",            // 0x6F
		"Utc1400_CPP_Std",          // 0x70
		"Utc1400_LTCG_C",           // 0x71
		"Utc1400_LTCG_CPP",         // 0x72
		"Utc1400_POGO_I_C",         // 0x73
		"Utc1400_POGO_I_CPP",       // 0x74
		"Utc1400_POGO_O_C",         // 0x75
		"Utc1400_POGO_O_CPP",       // 0x76
		"Cvtpgd1400",               // 0x77
		"Linker800",                // 0x78
		"Cvtomf800",                // 0x79
		"Export800",                // 0x7A
		"Implib800",                // 0x7B
		"Cvtres800",                // 0x7C
		"Masm800",                  // 0x7D
		"AliasObj800",              // 0x7E
		"PhoenixPrerelease",        // 0x7F
		"Utc1400_CVTCIL_C",         // 0x80
		"Utc1400_CVTCIL_CPP",       // 0x81
		"Utc1400_LTCG_MSIL",        // 0x82
		"Utc1500_C",                // 0x83
		"Utc1500_CPP",              // 0x84
		"Utc1500_C_Std",            // 0x85
		"Utc1500_CPP_Std",          // 0x86
		"Utc1500_CVTCIL_C",         // 0x87
		"Utc1500_CVTCIL_CPP",       // 0x88
		"Utc1500_LTCG_C",           // 0x89
		"Utc1500_LTCG_CPP",         // 0x8A
		"Utc1500_LTCG_MSIL",        // 0x8B
		"Utc1500_POGO_I_C",         // 0x8C
		"Utc1500_POGO_I_CPP",       // 0x8D
		"Utc1500_POGO_O_C",         // 0x8E
		"Utc1500_POGO_O_CPP",       // 0x8F
		"Cvtpgd1500",               // 0x90
		"Linker900",                // 0x91
		"Export900",                // 0x92
		"Implib900",                // 0x93
		"Cvtres900",                // 0x94
		"Masm900",                  // 0x95
		"AliasObj900",              // 0x96
		"Resource",                 // 0x97
		"AliasObj1000",             // 0x98
		"Cvtpgd1600",               // 0x99
		"Cvtres1000",               // 0x9A
		"Export1000",               // 0x9B
		"Implib1000",               // 0x9C
		"Linker1000",               // 0x9D
		"Masm1000",                 // 0x9E
		"Phx1600_C",                // 0x9F
		"Phx1600_CPP",              // 0xA0
		"Phx1600_CVTCIL_C",         // 0xA1
		"Phx1600_CVTCIL_CPP",       // 0xA2
		"Phx1600_LTCG_C",           // 0xA3
		"Phx1600_LTCG_CPP",         // 0xA4
		"Phx1600_LTCG_MSIL",        // 0xA5
		"Phx1600_POGO_I_C",         // 0xA6
		"Phx1600_POGO_I_CPP",       // 0xA7
		"Phx1600_POGO_O_C",         // 0xA8
		"Phx1600_POGO_O_CPP",       // 0xA9
		"Utc1600_C",                // 0xAA
		"Utc1600_CPP",              // 0xAB
		"Utc1600_CVTCIL_C",         // 0xAC
		"Utc1600_CVTCIL_CPP",       // 0xAD
		"Utc1600_LTCG_C",           // 0xAE
		"Utc1600_LTCG_CPP",         // 0xAF
		"Utc1600_LTCG_MSIL",        // 0xB0
		"Utc1600_POGO_I_C",         // 0xB1
		"Utc1600_POGO_I_CPP",       // 0xB2
		"Utc1600_POGO_O_C",         // 0xB3
		"Utc1600_POGO_O_CPP",       // 0xB4
		"AliasObj1010",             // 0xB5
		"Cvtpgd1610",               // 0xB6
		"Cvtres1010",               // 0xB7
		"Export1010",               // 0xB8
		"Implib1010",               // 0xB9
		"Linker1010",               // 0xBA
		"Masm1010",                 // 0xBB
		"Utc1610_C",                // 0xBC
		"Utc1610_CPP",              // 0xBD
		"Utc1610_CVTCIL_C",         // 0xBE
		"Utc1610_CVTCIL_CPP",       // 0xBF
		"Utc1610_LTCG_C",           // 0xC0
		"Utc1610_LTCG_CPP",         // 0xC1
		"Utc1610_LTCG_MSIL",        // 0xC2
		"Utc1610_POGO_I_C",         // 0xC3
		"Utc1610_POGO_I_CPP",       // 0xC4
		"Utc1610_POGO_O_C",         // 0xC5
		"Utc1610_POGO_O_CPP",       // 0xC6
		"AliasObj1100",             // 0xC7
		"Cvtpgd1700",               // 0xC8
		"Cvtres1100",               // 0xC9
		"Export1100",               // 0xCA
		"Implib1100",               // 0xCB
		"Linker1100",               // 0xCC
		"Masm1100",                 // 0xCD
		"Utc1700_C",                // 0xCE
		"Utc1700_CPP",              // 0xCF
		"Utc1700_CVTCIL_C",         // 0xD0
		"Utc1700_CVTCIL_CPP",       // 0xD1
		"Utc1700_LTCG_C",           // 0xD2
		"Utc1700_LTCG_CPP",         // 0xD3
		"Utc1700_LTCG_MSIL",        // 0xD4
		"Utc1700_POGO_I_C",         // 0xD5
		"Utc1700_POGO_I_CPP",       // 0xD6
		"Utc1700_POGO_O_C",         // 0xD7
		"Utc1700_POGO_O_CPP",       // 0xD8
		"AliasObj1200",             // 0xD9
		"Cvtpgd1800",               // 0xDA
		"Cvtres1200",               // 0xDB
		"Export1200",               // 0xDC
		"Implib1200",               // 0xDD
		"Linker1200",               // 0xDE
		"Masm1200",                 // 0xDF
		"Utc1800_C",                // 0xE0
		"Utc1800_CPP",              // 0xE1
		"Utc1800_CVTCIL_C",         // 0xE2
		"Utc1800_CVTCIL_CPP",       // 0xE3
		"Utc1800_LTCG_C",           // 0xE4
		"Utc1800_LTCG_CPP",         // 0xE5
		"Utc1800_LTCG_MSIL",        // 0xE6
		"Utc1800_POGO_I_C",         // 0xE7
		"Utc1800_POGO_I_CPP",       // 0xE8
		"Utc1800_POGO_O_C",         // 0xE9
		"Utc1800_POGO_O_CPP",       // 0xEA
		"AliasObj1210",             // 0xEB
		"Cvtpgd1810",               // 0xEC
		"Cvtres1210",               // 0xED
		"Export1210",               // 0xEE
		"Implib1210",               // 0xEF
		"Linker1210",               // 0xF0
		"Masm1210",                 // 0xF1
		"Utc1810_C",                // 0xF2
		"Utc1810_CPP",              // 0xF3
		"Utc1810_CVTCIL_C",         // 0xF4
		"Utc1810_CVTCIL_CPP",       // 0xF5
		"Utc1810_LTCG_C",           // 0xF6
		"Utc1810_LTCG_CPP",         // 0xF7
		"Utc1810_LTCG_MSIL",        // 0xF8
		"Utc1810_POGO_I_C",         // 0xF9
		"Utc1810_POGO_I_CPP",       // 0xFA
		"Utc1810_POGO_O_C",         // 0xFB
		"Utc1810_POGO_O_CPP",       // 0xFC
		"AliasObj1400",             // 0xFD
		"Cvtpgd1900",               // 0xFE
		"Cvtres1400",               // 0xFF
		"Export1400",               // 0x100
		"Implib1400",               // 0x101
		"Linker1400",               // 0x102
		"Masm1400",                 // 0x103
		"Utc1900_C",                // 0x104
		"Utc1900_CPP",              // 0x105
		"Utc1900_CVTCIL_C",         // 0x106
		"Utc1900_CVTCIL_CPP",       // 0x107
		"Utc1900_LTCG_C",           // 0x108
		"Utc1900_LTCG_CPP",         // 0x109
		"Utc1900_LTCG_MSIL",        // 0x10A
		"Utc1900_POGO_I_C",         // 0x10B
		"Utc1900_POGO_I_CPP",       // 0x10C
		"Utc1900_POGO_O_C",         // 0x10D
		"Utc1900_POGO_O_CPP"        // 0x10E
	};

	// Array of visualStudioNameIndex -> name of Visual Studio
	const std::vector<std::string> visualStudioNames =
	{
		".NET Framework",               //  0
		".NET Core",                    //  1
		"Visual Studio 5.0 CvtRes.exe", //  2
		"Visual C++ 5.0",               //  3
		"Visual Studio 6.0",            //  4
		"Visual Basic 6.0",             //  5
		"Visual C++ 6.0",               //  6
		"Visual Studio 6.0 MASM",       //  7
		"Visual C++ 2002",              //  8
		"Visual C++ 2003",              //  9
		"Visual Studio 2005",           // 10
		"Visual Studio 2008",           // 11
		"Visual Studio 2010",           // 12
		"Visual C++ 2012",              // 13
		"Visual Studio 2012 MASM",      // 14
		"Visual C++ 2013",              // 15
		"Visual Studio 2013",           // 16
		"Visual C++ 2015",              // 17
		"Visual Studio 2015",           // 18
		"Visual C++ 2017",              // 19
		"Visual Studio 2017",           // 20
		"Visual C++ 2019",              // 21
		"Visual Studio 2019"            // 22
	};

	// Array of index -> Visual Studio Version
	const std::vector<std::string> visualStudioNames2 =
	{
		"Visual Studio 2003 v7.10",
		"Visual Studio 2005 v8.0",
		"Visual Studio 2008 v9.0",
		"",
		"Visual Studio 2010 v10.0",
		"Visual Studio 2010 v10.10",
		"Visual Studio 2012 v11.0",
		"Visual Studio 2013 v12.0",
		"Visual Studio 2013 v12.10",
		"Visual Studio 2015+"
	};

	// Key: Build number from RichHeader
	// Value: Pair of { visualStudioNameIndex, visualStudioVersionString }
 const std::unordered_map<size_t, std::pair<size_t, std::string>> visualStudioVersionMap
	{
		{  2204, {  0, "1.0 beta 1"             } }, //   0
		{  2914, {  0, "1.0 beta 2"             } }, //   1
		{  3512, {  0, "1.0 RC3"                } }, //   2
		{  3705, {  0, "1.0"                    } }, //   3
		{  4322, {  0, "1.1"                    } }, //   4
		{ 21213, {  0, "1.2 pre-alpha"          } }, //   5
		{ 30703, {  0, "1.2 alpha",             } }, //   6
		{ 40301, {  0, "2.0"                    } }, //   7
		{ 40426, {  0, "2.0"                    } }, //   8
		{ 40607, {  0, "2.0"                    } }, //   9
		{ 40903, {  0, "2.0"                    } }, //  10
		{ 41115, {  0, "2.0"                    } }, //  11
		{ 50110, {  0, "2.0"                    } }, //  12
		{ 50215, {  0, "2.0"                    } }, //  13
		{ 50601, {  0, "2.0"                    } }, //  14
		{ 50710, {  0, "4.5"                    } }, //  15
		{ 50932, {  0, "4.5.1"                  } }, //  16
		{ 50938, {  0, "4.5.1"                  } }, //  17
		{ 51090, {  0, "4.5.2"                  } }, //  18
		{ 51209, {  0, "4.5.2"                  } }, //  19
		{ 51641, {  0, "4.5.1"                  } }, //  20
		{ 51651, {  0, "4.5.2"                  } }, //  21
		{  1055, {  0, "4.6"                    } }, //  22
		{ 23902, {  1, "5.0"                    } }, //  23
		{  1668, {  2, "5.0"                    } }, //  24
		{  1720, {  2, "5.0"                    } }, //  25
		{  1735, {  2, "5.0"                    } }, //  26
		{  1803, {  2, "5.0"                    } }, //  27
		{  2080, {  2, "5.0"                    } }, //  28
		{  2090, {  2, "5.0"                    } }, //  29
		{  7008, {  3, "5.0"                    } }, //  30
		{  7022, {  3, "5.0 SP0"                } }, //  31
		{  7132, {  3, "5.2 SP1"                } }, //  32
		{  7274, {  3, "5.10 SP3"               } }, //  33
		{  7303, {  3, "5.10 SP3"               } }, //  34
		{  8022, {  3, "5.12"                   } }, //  35
		{  8034, {  3, "5.12"                   } }, //  36
		{  8078, {  3, "5.12"                   } }, //  37
		{  8124, {  3, "5.12"                   } }, //  38
		{  8152, {  3, "5.12"                   } }, //  39
		{  9049, {  3, "5.12"                   } }, //  40
		{  7291, {  4, "6.0"                    } }, //  41
		{  8041, {  5, "5.0"                    } }, //  42
		{  8047, {  6, "6.0"                    } }, //  43
		{  8167, {  4, "6.0"                    } }, //  44
		{  8168, {  4, "6.0"                    } }, //  45
		{  8169, {  4, "6.0"                    } }, //  46
		{  8349, {  6, "6.0"                    } }, //  47
		{  8350, {  6, "6.0"                    } }, //  48
		{  8397, {  6, "6.0"                    } }, //  49
		{  8447, {  6, "6.0 SP3"                } }, //  50
		{  8495, {  4, "6.0 SP3"                } }, //  51
		{  8569, {  6, "6.0 SP3"                } }, //  52
		{  8755, {  6, "6.0 SP3"                } }, //  53
		{  8769, {  6, "6.0 SP3"                } }, //  54
		{  8783, {  5, "5.0"                    } }, //  55
		{  8797, {  6, "6.0 SP4"                } }, //  56
		{  8798, {  6, "6.0 SP4"                } }, //  57
		{  8799, {  6, "6.0 SP4"                } }, //  58
		{  8804, {  6, "6.0 SP4"                } }, //  59
		{  8877, {  4, "6.0 SP4"                } }, //  60
		{  8943, {  6, "6.0 SP5 Processor Pack" } }, //  61
		{  8964, {  4, "6.0 SP5"                } }, //  62
		{  8966, {  6, "6.0 SP5"                } }, //  63
		{  9044, {  6, "6.0 SP5 Processor Pack" } }, //  64
		{  9738, {  4, "6.0 SP6"                } }, //  65
		{  9782, {  4, "6.0 SP6"                } }, //  66
		{  7299, {  7, "6.13 SP1"               } }, //  67
		{  8444, {  7, "6.14 SP3"               } }, //  68
		{  8803, {  7, "6.15 SP4"               } }, //  69
		{  8905, {  7, "6.15 SP4"               } }, //  70
		{  8491, {  8, "7.0"                    } }, //  71
		{  8800, {  8, "7.0"                    } }, //  72
		{  8830, {  8, "7.0"                    } }, //  73
		{  9030, {  8, "7.0 beta 1"             } }, //  74
		{  9037, {  8, "7.0"                    } }, //  75
		{  9043, {  8, "7.0"                    } }, //  76
		{  9111, {  8, "7.0"                    } }, //  77
		{  9162, {  8, "7.0"                    } }, //  78
		{  9177, {  8, "7.0"                    } }, //  79
		{  9178, {  8, "7.0"                    } }, //  80
		{  9210, {  8, "7.0 XP DDK"             } }, //  81
		{  9254, {  8, "7.0 beta 2"             } }, //  82
		{  9372, {  8, "7.0 RC1"                } }, //  83
		{  9466, {  8, "7.0"                    } }, //  84
		{  9955, {  8, "7.0 SP1"                } }, //  85
		{  2035, {  9, "7.10 beta"              } }, //  86
		{  2067, {  9, "7.10 beta"              } }, //  87
		{  2179, {  9, "7.10"                   } }, //  88
		{  2190, {  9, "7.10"                   } }, //  89
		{  2197, {  9, "7.10"                   } }, //  90
		{  2241, {  9, "7.10"                   } }, //  91
		{  3052, {  9, "7.10 Free Toolkit"      } }, //  92
		{  3077, {  9, "7.10"                   } }, //  93
		{  3088, {  9, "7.10"                   } }, //  94
		{  3310, {  9, "7.10"                   } }, //  95
		{  4017, {  9, "7.10"                   } }, //  96
		{  4031, {  9, "7.10 SDK"               } }, //  97
		{  4035, {  9, "7.10 SDK"               } }, //  98
		{  6030, {  9, "7.10 SP1"               } }, //  99
		{  6101, {  9, "7.10 SP1"               } }, // 100
		{ 30120, { 10, "8.0"                    } }, // 101
		{ 30701, { 10, "8.0"                    } }, // 102
		{ 31008, { 10, "8.0"                    } }, // 103
		{ 40310, { 10, "8.0 SDK"                } }, // 104
		{ 41204, { 10, "8.0"                    } }, // 105
		{ 50327, { 10, "8.0"                    } }, // 106
		{ 50608, { 10, "8.0"                    } }, // 107
		{ 50706, { 10, "8.0"                    } }, // 108
		{ 50727, { 10, "8.0"                    } }, // 109
		{ 60516, { 10, "8.0"                    } }, // 110
		{ 61001, { 10, "8.0 SP1 MFC Update"     } }, // 111
		{ 20413, { 11, "9.0"                    } }, // 112
		{ 21022, { 11, "9.0"                    } }, // 113
		{ 30718, { 11, "9.0"                    } }, // 114
		{ 30729, { 11, "9.0"                    } }, // 115
		{ 20115, { 12, "10.0"                   } }, // 116
		{ 21202, { 12, "10.0"                   } }, // 117
		{ 30311, { 12, "10.0"                   } }, // 118
		{ 30314, { 12, "10.0"                   } }, // 119
		{ 30319, { 12, "10.0"                   } }, // 120
		{ 30414, { 12, "10.0"                   } }, // 121
		{ 30716, { 12, "10.10 SP1"              } }, // 122
		{ 31118, { 12, "10.10 SP1"              } }, // 123
		{ 40219, { 12, "10.10 SP1"              } }, // 124
		{ 41118, { 13, "11.0"                   } }, // 125
		{ 50307, { 13, "11.0"                   } }, // 126
		{ 50323, { 13, "11.0"                   } }, // 127
		{ 50413, { 13, "11.0"                   } }, // 128
		{ 50522, { 13, "11.0"                   } }, // 129
		{ 50425, { 13, "11.0"                   } }, // 130
		{ 50503, { 13, "11.0"                   } }, // 131
		{ 50531, { 13, "11.0"                   } }, // 132
		{ 50612, { 13, "11.0"                   } }, // 133
		{ 50628, { 13, "11.0"                   } }, // 134
		{ 50709, { 13, "11.0"                   } }, // 135
		{ 50722, { 13, "11.0"                   } }, // 136
		{ 50727, { 13, "11.0"                   } }, // 137
		{ 50929, { 13, "11.0"                   } }, // 138
		{ 51016, { 13, "11.0"                   } }, // 139
		{ 51020, { 13, "11.0.1"                 } }, // 140
		{ 51106, { 13, "11.0.1"                 } }, // 141
		{ 51114, { 13, "11.0.2"                 } }, // 142
		{ 51204, { 13, "11.0.2"                 } }, // 143
		{ 60610, { 13, "11.0.3"                 } }, // 144
		{ 60930, { 14, "11.0"                   } }, // 145
		{ 60315, { 13, "11.0.2"                 } }, // 146
		{ 61030, { 13, "11.0.4"                 } }, // 147
		{ 61219, { 13, "11.0.5"                 } }, // 148
		{ 61232, { 13, "11.0"                   } }, // 149
		{ 65500, { 13, "11.0"                   } }, // 150
		{ 65501, { 13, "11.0"                   } }, // 151
		{ 20322, { 15, "12.0"                   } }, // 152
		{ 20403, { 15, "12.0"                   } }, // 153
		{ 20501, { 15, "12.0"                   } }, // 154
		{ 20617, { 15, "12.0"                   } }, // 155
		{ 20806, { 15, "12.0"                   } }, // 156
		{ 21005, { 15, "12.0 RTM"               } }, // 157
		{ 30102, { 15, "12.10"                  } }, // 158
		{ 40115, { 15, "12.10"                  } }, // 159
		{ 40116, { 15, "12.10"                  } }, // 160
		{ 40649, { 15, "12.0"                   } }, // 161
		{ 40660, { 15, "12.0"                   } }, // 162
		{ 40664, { 15, "12.0"                   } }, // 163
		{ 30110, { 16, "12.0.1"                 } }, // 164
		{ 30324, { 16, "12.0.2"                 } }, // 165
		{ 30501, { 16, "12.0.2"                 } }, // 166
		{ 30723, { 16, "12.0.3"                 } }, // 167
		{ 31101, { 16, "12.0.4"                 } }, // 168
		{ 40629, { 16, "12.0.5"                 } }, // 169
		{ 23007, { 17, "14.0"                   } }, // 170
		{ 23013, { 17, "14.0"                   } }, // 171
		{ 23026, { 17, "14.0"                   } }, // 172
		{ 23406, { 17, "14.0"                   } }, // 173
		{ 23524, { 17, "14.0"                   } }, // 174
		{ 23615, { 17, "14.0"                   } }, // 175
		{ 23506, { 17, "14.0.1"                 } }, // 176
		{ 23907, { 17, "14.0.1"                 } }, // 177
		{ 23917, { 17, "14.0 preview 2"         } }, // 178
		{ 23918, { 17, "14.0.2"                 } }, // 179
		{ 23927, { 17, "14.0.2"                 } }, // 180
		{ 24123, { 17, "14.0.3 RC"              } }, // 181
		{ 24210, { 17, "14.0.3"                 } }, // 182
		{ 24212, { 17, "14.0.3.b"               } }, // 183
		{ 24213, { 17, "14.0.3.d"               } }, // 184
		{ 24215, { 17, "14.0.3.d"               } }, // 185
		{ 24218, { 17, "14.0.3.d"               } }, // 186
		{ 24225, { 17, "14.0.3.d"               } }, // 187
		{ 24231, { 17, "14.0.3.d"               } }, // 188
		{ 24233, { 17, "14.0.3.d"               } }, // 189
		{ 24234, { 17, "14.0.3.d"               } }, // 190
		{ 24406, { 17, "14.0 preview 4"         } }, // 191
		{ 24425, { 17, "14.0 TFS Test VMs"      } }, // 192
		{ 22823, { 18, "14.0 RC"                } }, // 193
		{ 23107, { 18, "14.0"                   } }, // 194
		{ 24019, { 18, "14.0"                   } }, // 195
		{ 24116, { 18, "14.0"                   } }, // 196
		{ 24325, { 18, "14.0"                   } }, // 197
		{ 24610, { 18, "14.0"                   } }, // 198
		{ 24720, { 18, "14.0.1"                 } }, // 199
		{ 24723, { 18, "14.0.1.a"               } }, // 200
		{ 24728, { 18, "14.0.1.b"               } }, // 201
		{ 24730, { 18, "14.0.1.c"               } }, // 202
		{ 25025, { 18, "14.0"                   } }, // 203
		{ 25123, { 18, "14.0.2"                 } }, // 204
		{ 25125, { 18, "14.0.2"                 } }, // 205
		{ 25126, { 18, "14.0.2.a"               } }, // 206
		{ 25130, { 18, "14.0.2.b"               } }, // 207
		{ 25131, { 18, "14.0.2.b"               } }, // 208
		{ 25132, { 18, "14.0.2.c"               } }, // 209
		{ 25203, { 18, "14.0"                   } }, // 210
		{ 25224, { 18, "14.0"                   } }, // 211
		{ 25305, { 18, "14.0"                   } }, // 212
		{ 25420, { 18, "14.0.3"                 } }, // 213
		{ 25421, { 18, "14.0.3"                 } }, // 214
		{ 25422, { 18, "14.0.3.a"               } }, // 215
		{ 25424, { 18, "14.0.3.b"               } }, // 216
		{ 25425, { 18, "14.0.3.c"               } }, // 217
		{ 25431, { 18, "14.0.3.d"               } }, // 218
		{ 24629, { 19, "14.10 RC"               } }, // 219
		{ 25008, { 19, "14.10"                  } }, // 220
		{ 25017, { 19, "14.10"                  } }, // 221
		{ 25019, { 19, "14.10"                  } }, // 222
		{ 25508, { 19, "14.11"                  } }, // 223
		{ 25547, { 19, "14.11"                  } }, // 224
		{ 25711, { 19, "14.12"                  } }, // 225
		{ 26128, { 19, "14.12"                  } }, // 226
		{ 26131, { 19, "14.13"                  } }, // 227
		{ 26213, { 19, "14.13"                  } }, // 228
		{ 26706, { 19, "14.15"                  } }, // 229
		{ 26715, { 19, "14.15"                  } }, // 230
		{ 26726, { 19, "14.15"                  } }, // 231
		{ 27023, { 19, "14.16"                  } }, // 232
		{ 27024, { 19, "14.16"                  } }, // 233
		{ 27026, { 19, "14.16"                  } }, // 234
		{ 27027, { 19, "14.16"                  } }, // 235
		{ 27030, { 19, "14.16"                  } }, // 236
		{ 27031, { 19, "14.16"                  } }, // 237
		{ 27034, { 19, "14.16"                  } }, // 238
		{ 26304, { 20, "15.0.0 preview 1"       } }, // 239
		{ 26501, { 20, "15.0 Office tools"      } }, // 240
		{ 26504, { 20, "15.0"                   } }, // 241
		{ 26315, { 20, "15.0.0 preview 2"       } }, // 242
		{ 26323, { 20, "15.0.0 preview 3"       } }, // 243
		{ 26228, { 20, "15.0.x"                 } }, // 244
		{ 26403, { 20, "15.1.x"                 } }, // 245
		{ 26412, { 20, "15.2.0 preview 1"       } }, // 246
		{ 26419, { 20, "15.2.0 preview 2"       } }, // 247
		{ 26424, { 20, "15.2.0 preview 3"       } }, // 248
		{ 26430, { 20, "15.2.x"                 } }, // 249
		{ 26507, { 20, "15.3.0 preview 1"       } }, // 250
		{ 26510, { 20, "15.3.0 preview 1.1"     } }, // 251
		{ 26606, { 20, "15.3.0 preview 2"       } }, // 252
		{ 26608, { 20, "15.3.0 preview 2.1"     } }, // 253
		{ 26621, { 20, "15.3.0 preview 3"       } }, // 254
		{ 26711, { 20, "15.3.0 preview 4"       } }, // 255
		{ 26720, { 20, "15.3.0 preview 5"       } }, // 256
		{ 26724, { 20, "15.3.0 preview 6"       } }, // 257
		{ 26730, { 20, "15.3.x"                 } }, // 258
		{ 26732, { 20, "15.3.x"                 } }, // 259
		{ 26823, { 20, "15.4.0 preview 1"       } }, // 260
		{ 26906, { 20, "15.4.0 preview 2"       } }, // 261
		{ 26923, { 20, "15.4.0 preview 3"       } }, // 262
		{ 26929, { 20, "15.4.0 preview 4"       } }, // 263
		{ 27004, { 20, "15.4.x"                 } }, // 264
		{ 27009, { 20, "15.5.0 preview 1"       } }, // 265
		{ 27019, { 20, "15.5.0 preview 2"       } }, // 266
		{ 27102, { 20, "15.5.0 preview 3"       } }, // 267
		{ 27110, { 20, "15.5.0 preview 4"       } }, // 268
		{ 27128, { 20, "15.5.0 preview 5"       } }, // 269
		{ 27130, { 20, "15.5.x"                 } }, // 270
		{ 27205, { 20, "15.6.0 preview 1"       } }, // 271
		{ 27207, { 20, "15.0 MSI tools"         } }, // 272
		{ 27309, { 20, "15.6.0 preview 2"       } }, // 273
		{ 27323, { 20, "15.6.0 preview 3"       } }, // 274
		{ 27406, { 20, "15.6.0 preview 4"       } }, // 275
		{ 27413, { 20, "15.6.0 preview 5"       } }, // 276
		{ 27421, { 20, "15.6.0 preview 6"       } }, // 277
		{ 27428, { 20, "15.6.x"                 } }, // 278
		{ 27512, { 20, "15.7.0 preview 1"       } }, // 279
		{ 27520, { 20, "15.7.0 preview 2"       } }, // 280
		{ 27604, { 20, "15.7.0 preview 3"       } }, // 281
		{ 27617, { 20, "15.7.0 preview 4"       } }, // 282
		{ 27625, { 20, "15.7.0 preview 5"       } }, // 283
		{ 27701, { 20, "15.7.0 preview 6"       } }, // 284
		{ 27703, { 20, "15.7.x"                 } }, // 285
		{ 27705, { 20, "15.8.0 preview 1"       } }, // 286
		{ 27729, { 20, "15.8.0 preview 2"       } }, // 287
		{ 27825, { 20, "15.8.0 preview 3"       } }, // 288
		{ 27906, { 20, "15.8.0 preview 4"       } }, // 289
		{ 27924, { 20, "15.8.0 preview 5"       } }, // 290
		{ 28010, { 20, "15.8.x"                 } }, // 291
		{ 28016, { 20, "15.9.0 preview 1"       } }, // 292
		{ 28107, { 20, "15.9.0 preview 2"       } }, // 293
		{ 28128, { 20, "15.9.0 preview 3"       } }, // 294
		{ 28219, { 20, "15.9.0 preview 4"       } }, // 295
		{ 28302, { 20, "15.9.0 preview 5"       } }, // 296
		{ 28307, { 20, "15.9.x"                 } }, // 297
		{ 27706, { 21, "14.22"                  } }, // 298
		{ 27724, { 21, "14.22"                  } }, // 299
		{ 27807, { 21, "14.22"                  } }, // 300
		{ 27812, { 21, "14.22"                  } }, // 301
		{ 27821, { 21, "14.22"                  } }, // 302
		{ 27905, { 21, "14.22"                  } }, // 303
		{ 28117, { 21, "14.24"                  } }, // 304
		{ 28329, { 22, "16.0.0 preview 1"       } }, // 305
		{ 28408, { 22, "16.0.0 preview 1.1"     } }, // 306
		{ 28522, { 22, "16.0.0 preview 2"       } }, // 307
		{ 28529, { 22, "16.0.0 preview 2.1"     } }, // 308
		{ 28602, { 22, "16.0.0 preview 2.2"     } }, // 309
		{ 28608, { 22, "16.0.0 preview 3"       } }, // 310
		{ 28625, { 22, "16.0.0 preview 4"       } }, // 311
		{ 28701, { 22, "16.0.0 preview 4.1"     } }, // 312
		{ 28705, { 22, "16.0.0 preview 4.1.1"   } }, // 313
		{ 28711, { 22, "16.0.0 preview 4.2"     } }, // 314
		{ 28714, { 22, "16.0.0 preview 4.3"     } }, // 315
		{ 28721, { 22, "16.0.0 preview 4.4"     } }, // 316
		{ 28729, { 22, "16.0.0"                 } }, // 317
		{ 28803, { 22, "16.0.x"                 } }, // 318
		{ 28809, { 22, "16.1.0 preview 1"       } }, // 319
		{ 28822, { 22, "16.1.0 preview 2"       } }, // 320
		{ 28902, { 22, "16.1.0 preview 3"       } }, // 321
		{ 28917, { 22, "16.1.0"                 } }, // 322
		{ 28922, { 22, "16.1.1"                 } }, // 323
		{ 29001, { 22, "16.1.2"                 } }, // 324
		{ 29009, { 22, "16.1.3"                 } }, // 325
		{ 29020, { 22, "16.1.4"                 } }, // 326
		{ 29025, { 22, "16.1.5"                 } }, // 327
		{ 29102, { 22, "16.1.6"                 } }, // 328
		{ 29006, { 22, "16.2.0 preview 2"       } }, // 329
		{ 29021, { 22, "16.2.0 preview 3"       } }, // 330
		{ 29111, { 22, "16.2.0 preview 4"       } }, // 331
		{ 29123, { 22, "16.2.0"                 } }, // 332
		{ 29201, { 22, "16.2.1"                 } }, // 333
		{ 29209, { 22, "16.2.2"                 } }, // 334
		{ 29215, { 22, "16.2.3"                 } }, // 335
		{ 29230, { 22, "16.2.4"                 } }, // 336
		{ 29306, { 22, "16.2.5"                 } }, // 337
		{ 29311, { 22, "16.3.0 preview 4"       } }, // 338
		{ 29318, { 22, "16.3.0"                 } }, // 339
		{ 29324, { 22, "16.3.1"                 } }, // 340
		{ 29326, { 22, "16.3.2"                 } }, // 341
		{ 29403, { 22, "16.3.3"                 } }, // 342
		{ 29409, { 22, "16.3.4"                 } }, // 343
		{ 29411, { 22, "16.3.5"                 } }, // 344
		{ 29418, { 22, "16.3.6"                 } }, // 345
		{ 29424, { 22, "16.3.7"                 } }, // 346
		{ 29503, { 22, "16.3.8"                 } }, // 347
		{ 29509, { 22, "16.3.9"                 } }, // 348
		{ 29319, { 22, "16.4.0 preview 1"       } }, // 349
		{ 29430, { 22, "16.4.0 preview 3"       } }, // 350
		{ 29505, { 22, "16.4.0 preview 4"       } }, // 351
		{ 29512, { 22, "16.4.0 preview 5"       } }, // 352
		{ 29519, { 22, "16.4.0"                 } }, // 353
		{ 29609, { 22, "16.4.1"                 } }, // 354
		{ 29521, { 22, "16.5.0 preview 1"       } }  // 355
	};

namespace
{
	std::string makeSignature(std::uint32_t value)
	{
		std::stringstream signature;
		signature << std::hex << std::setfill('0') << std::setw(2 * sizeof(std::uint32_t)) << std::uppercase << value;
		return signature.str();
	}

	std::string makeSignature(std::uint32_t first, std::uint32_t second)
	{
		return makeSignature(first) + makeSignature(second);
	}
}

	RichHeader::RichHeader()
	{
		init();
	}

	RichHeader::~RichHeader()
	{

	}

	void RichHeader::init()
	{
		headerIsValid = false;
		validStructure = false;
		key = 0;
		noOfIters = 0;
		decryptedHeader.clear();
		records.clear();
	}

	void RichHeader::setValidStructure()
	{
		validStructure = (decryptedHeader.size() >= 4);
	}

	void RichHeader::getUserFriendlyProductName(PELIB_IMAGE_RICH_HEADER_RECORD & record)
	{
		// Product ID can be mapped to Product name 1:1. Just check if the ID is in range.
		record.ProductName = (record.ProductId < productNames.size()) ? productNames[record.ProductId] : "Unknown";

		// We can very well match build number to a Visual Studio build.
		// Exclude Visual Studio 2005 (v8.0), which has the same build number like Visual Studio 2012 (v11.0)
		// If the product ID is above 0x83, then it's clearly Visual Studio 2012.
		if (!(record.ProductId >= 0x83 && record.ProductBuild == 50727))
		{
			auto search = visualStudioVersionMap.find(record.ProductBuild);

			if (search != visualStudioVersionMap.end())
			{
				std::string VisualStudioName;

				// Get the name of the Visual Studio from the name index
				if (search->second.first < visualStudioNames.size())
					VisualStudioName = visualStudioNames[search->second.first];
				record.VisualStudioName = VisualStudioName + " v" + search->second.second;
			}
		}

		// If the Visual Studio was not known yet, estimate its version from the ProductID range
		if (record.VisualStudioName.empty())
		{
			std::array<uint32_t, 10> ProductIdRange = { 0x5A, 0x6D, 0x83, 0x97, 0x98, 0xB5, 0xC7, 0xD9, 0xEB, 0xFD };

			// Find the group by the product ID
			for (int index = ProductIdRange.size() - 1; index >= 0; index--)
			{
				if (record.ProductId >= ProductIdRange[index])
				{
					if (index < 9)
					{
						record.VisualStudioName = visualStudioNames2[index];
					}
					else
					{
						if (record.ProductBuild < 26304)
						{
							record.VisualStudioName = "Visual Studio 2015";
						}
						else if (record.ProductBuild < 28329)
						{
							record.VisualStudioName = "Visual Studio 2017";
						}
						else
						{
							record.VisualStudioName = "Visual Studio 2019+";
						}
					}
					break;
				}
			}
		}
	}

	/**
	 * @brief Checks if the decrypted header looks valid, if it does
	 *        then it analyses the header contents and saves it
	 *        into this->records
	 * 
	 * @param ignoreInvalidKey 
	 * @return true - the header looks valid
	 * @return false - header isn't valid
	 */
	bool RichHeader::analyze(bool ignoreInvalidKey)
	{
		bool hValid = true;
		size_t decSize = decryptedHeader.size();
		if (decSize < 4)
		{
			return false;
		}
		// Check if the start is "DanS" with 3 NULL
		// DWORDS padding into 16 byte paragraph
		else if (decryptedHeader[0] != 0x536e6144 ||
				decryptedHeader[1] != 0 ||
				decryptedHeader[2] != 0 ||
				decryptedHeader[3] != 0)
		{
			if (ignoreInvalidKey)
			{
				hValid = false;
			}
			else
			{
				return false;
			}
		}

		// Remember whether the header is valid
		headerIsValid = hValid;

		// Parse all products and their counts
		for (size_t i = 4; i + 1 < decSize; i += 2)
		{
			PELIB_IMAGE_RICH_HEADER_RECORD record;

			record.ProductId = (std::uint16_t)(decryptedHeader[i] >> 0x10);
			record.ProductBuild = (std::uint16_t)(decryptedHeader[i] & 0xFFFF);
			record.Count = decryptedHeader[i + 1];
			record.Signature = makeSignature(decryptedHeader[i], decryptedHeader[i + 1]);

			getUserFriendlyProductName(record);

			records.push_back(record);
		}

		return true;
	}

	void RichHeader::read(InputBuffer& inputbuffer, std::size_t uiSize, bool ignoreInvalidKey)
	{
		init();
		std::vector<std::uint32_t> rich;

		for (std::size_t i = 0, e = uiSize / sizeof(std::uint32_t); i < e; ++i)
		{
			std::uint32_t actInput;
			inputbuffer >> actInput;
			rich.push_back(actInput);
		}

		std::uint32_t sign[] = {0x68636952}; // "Rich"
		auto lastPos = rich.end();

		// try to find signature of rich header and key for decryption
		do
		{
			// Find the Rich header ending marker "Rich"
			auto richSignature = find_end(rich.begin(), lastPos, sign, sign + 1);
			if (richSignature == lastPos || richSignature + 1 == rich.end())
			{
				break;
			}

			lastPos = richSignature;
			key = *(richSignature + 1);
			decryptedHeader.clear();
			++noOfIters;

			// Start analyzing from the end - "Rich" marker
			// and move upwards to decrypted "DanS" marker
			for (auto it = std::make_reverse_iterator(richSignature); it < rich.rend(); ++it)
			{
				std::uint32_t decrypted_dword = *it ^ key;
				decryptedHeader.push_back(decrypted_dword);
				// "DanS" - 0x536e6144 signals the start (end) of the rich header
				if (decrypted_dword == 0x536e6144)
				{
					// Set the offset to "DanS"
					this->offset = std::distance(it + 1, rich.rend()) * 4;
					// Because we are analysing bottom up, reverse the vector
					std::reverse(decryptedHeader.begin(), decryptedHeader.end());
					break;
				}
			}
			setValidStructure();
		} while (!analyze());

		if (ignoreInvalidKey && noOfIters)
		{
			analyze(true);
		}
	}

	int RichHeader::read(
			std::istream& inStream,
			std::size_t uiOffset,
			std::size_t uiSize,
			bool ignoreInvalidKey)
	{
		IStreamWrapper inStream_w(inStream);

		if (!inStream_w)
		{
			return ERROR_OPENING_FILE;
		}

		const auto ulFileSize = fileSize(inStream_w);
		if (ulFileSize < uiOffset + uiSize)
		{
			return ERROR_INVALID_FILE;
		}

		inStream_w.seekg(uiOffset, std::ios::beg);
		std::vector<unsigned char> tableDump;
		tableDump.resize(uiSize);
		inStream_w.read(reinterpret_cast<char*>(tableDump.data()), uiSize);
		InputBuffer ibBuffer(tableDump);
		read(ibBuffer, uiSize, ignoreInvalidKey);

		return ERROR_NONE;
	}

	bool RichHeader::isHeaderValid() const
	{
		return headerIsValid;
	}

	bool RichHeader::isStructureValid() const
	{
		return validStructure;
	}

	std::uint64_t RichHeader::getOffset() const
	{
		return offset;
	}

	std::size_t RichHeader::getNumberOfIterations() const
	{
		return noOfIters;
	}

	std::uint32_t RichHeader::getKey() const
	{
		return key;
	}

	const std::uint32_t* RichHeader::getDecryptedHeaderItem(std::size_t index) const
	{
		return (index < decryptedHeader.size()) ? &decryptedHeader[index] : nullptr;
	}

	std::string RichHeader::getDecryptedHeaderItemSignature(std::size_t index) const
	{
		const auto *dhI = getDecryptedHeaderItem(index);
		return dhI ? makeSignature(*dhI) : "";
	}

	std::string RichHeader::getDecryptedHeaderItemsSignature(std::initializer_list<std::size_t> indexes) const
	{
		std::string result;

		for (const auto index : indexes)
		{
			result += getDecryptedHeaderItemSignature(index);
		}

		return result;
	}

	std::vector<std::uint8_t> RichHeader::getDecryptedHeaderBytes() const
	{
		std::vector<std::uint8_t> result(decryptedHeader.size() * sizeof(std::uint32_t));
		std::memcpy(result.data(), reinterpret_cast<const std::uint8_t*>(decryptedHeader.data()), result.size());
		return result;
	}

	RichHeader::richHeaderIterator RichHeader::begin() const
	{
		return records.begin();
	}

	RichHeader::richHeaderIterator RichHeader::end() const
	{
		return records.end();
	}
}
