/**
 * @file include/retdec/pdbparser/pdb_info.h
 * @brief PDB info
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_PDBPARSER_PDB_INFO_H
#define RETDEC_PDBPARSER_PDB_INFO_H

#include "retdec/pdbparser/pdb_utils.h"

namespace retdec {
namespace pdbparser {

// pdb_info.h
// 06-25-2006 Sven B. Schreiber
// sbs@orgon.com

// =================================================================
// PDB INTERFACE VERSIONS
// =================================================================

#define PDBIntv41       920924
#define PDBIntv50       19960502
#define PDBIntv50a      19970116
#define PDBIntv60       19970116
#define PDBIntv61       19980914
#define PDBIntv69       19990511
#define PDBIntv70Dep    20000406
#define PDBIntv70       20001102

#define PDBIntv         PDBIntv70

#define PDBIntvAlt      PDBIntv50
#define PDBIntvAlt2     PDBIntv60
#define PDBIntvAlt3     PDBIntv69

// =================================================================
// PDB IMPLEMENTATION VERSIONS
// =================================================================

#define PDBImpvVC2      19941610
#define PDBImpvVC4      19950623
#define PDBImpvVC41     19950814
#define PDBImpvVC50     19960307
#define PDBImpvVC98     19970604
#define PDBImpvVC70Dep  19990604
#define PDBImpvVC70     20000404

#define PDBImpv         PDBImpvVC70

// =================================================================
// DBI IMPLEMENTATION VERSIONS
// =================================================================

#define DBIImpvV41        930803
#define DBIImpvV50      19960307
#define DBIImpvV60      19970606
#define DBIImpvV70      19990903

#define DBIImpv         DBIImpvV70

// =================================================================
// BASIC TYPES
// =================================================================

typedef enum _TYPE_ENUM_e
{
	T_NOTYPE = 0x00000000,
	T_ABS = 0x00000001,
	T_SEGMENT = 0x00000002,
	T_VOID = 0x00000003,

	T_HRESULT = 0x00000008,
	T_32PHRESULT = 0x00000408,
	T_64PHRESULT = 0x00000608,

	T_PVOID = 0x00000103,
	T_PFVOID = 0x00000203,
	T_PHVOID = 0x00000303,
	T_32PVOID = 0x00000403,
	T_32PFVOID = 0x00000503,
	T_64PVOID = 0x00000603,

	T_CURRENCY = 0x00000004,
	T_NBASICSTR = 0x00000005,
	T_FBASICSTR = 0x00000006,
	T_NOTTRANS = 0x00000007,
	T_BIT = 0x00000060,
	T_PASCHAR = 0x00000061,

	T_CHAR = 0x00000010,
	T_PCHAR = 0x00000110,
	T_PFCHAR = 0x00000210,
	T_PHCHAR = 0x00000310,
	T_32PCHAR = 0x00000410,
	T_32PFCHAR = 0x00000510,
	T_64PCHAR = 0x00000610,

	T_UCHAR = 0x00000020,
	T_PUCHAR = 0x00000120,
	T_PFUCHAR = 0x00000220,
	T_PHUCHAR = 0x00000320,
	T_32PUCHAR = 0x00000420,
	T_32PFUCHAR = 0x00000520,
	T_64PUCHAR = 0x00000620,

	T_RCHAR = 0x00000070,
	T_PRCHAR = 0x00000170,
	T_PFRCHAR = 0x00000270,
	T_PHRCHAR = 0x00000370,
	T_32PRCHAR = 0x00000470,
	T_32PFRCHAR = 0x00000570,
	T_64PRCHAR = 0x00000670,

	T_WCHAR = 0x00000071,
	T_PWCHAR = 0x00000171,
	T_PFWCHAR = 0x00000271,
	T_PHWCHAR = 0x00000371,
	T_32PWCHAR = 0x00000471,
	T_32PFWCHAR = 0x00000571,
	T_64PWCHAR = 0x00000671,

	T_INT1 = 0x00000068,
	T_PINT1 = 0x00000168,
	T_PFINT1 = 0x00000268,
	T_PHINT1 = 0x00000368,
	T_32PINT1 = 0x00000468,
	T_32PFINT1 = 0x00000568,
	T_64PINT1 = 0x00000668,

	T_UINT1 = 0x00000069,
	T_PUINT1 = 0x00000169,
	T_PFUINT1 = 0x00000269,
	T_PHUINT1 = 0x00000369,
	T_32PUINT1 = 0x00000469,
	T_32PFUINT1 = 0x00000569,
	T_64PUINT1 = 0x00000669,

	T_SHORT = 0x00000011,
	T_PSHORT = 0x00000111,
	T_PFSHORT = 0x00000211,
	T_PHSHORT = 0x00000311,
	T_32PSHORT = 0x00000411,
	T_32PFSHORT = 0x00000511,
	T_64PSHORT = 0x00000611,

	T_USHORT = 0x00000021,
	T_PUSHORT = 0x00000121,
	T_PFUSHORT = 0x00000221,
	T_PHUSHORT = 0x00000321,
	T_32PUSHORT = 0x00000421,
	T_32PFUSHORT = 0x00000521,
	T_64PUSHORT = 0x00000621,

	T_INT2 = 0x00000072,
	T_PINT2 = 0x00000172,
	T_PFINT2 = 0x00000272,
	T_PHINT2 = 0x00000372,
	T_32PINT2 = 0x00000472,
	T_32PFINT2 = 0x00000572,
	T_64PINT2 = 0x00000672,

	T_UINT2 = 0x00000073,
	T_PUINT2 = 0x00000173,
	T_PFUINT2 = 0x00000273,
	T_PHUINT2 = 0x00000373,
	T_32PUINT2 = 0x00000473,
	T_32PFUINT2 = 0x00000573,
	T_64PUINT2 = 0x00000673,

	T_LONG = 0x00000012,
	T_PLONG = 0x00000112,
	T_PFLONG = 0x00000212,
	T_PHLONG = 0x00000312,
	T_32PLONG = 0x00000412,
	T_32PFLONG = 0x00000512,
	T_64PLONG = 0x00000612,

	T_ULONG = 0x00000022,
	T_PULONG = 0x00000122,
	T_PFULONG = 0x00000222,
	T_PHULONG = 0x00000322,
	T_32PULONG = 0x00000422,
	T_32PFULONG = 0x00000522,
	T_64PULONG = 0x00000622,

	T_INT4 = 0x00000074,
	T_PINT4 = 0x00000174,
	T_PFINT4 = 0x00000274,
	T_PHINT4 = 0x00000374,
	T_32PINT4 = 0x00000474,
	T_32PFINT4 = 0x00000574,
	T_64PINT4 = 0x00000674,

	T_UINT4 = 0x00000075,
	T_PUINT4 = 0x00000175,
	T_PFUINT4 = 0x00000275,
	T_PHUINT4 = 0x00000375,
	T_32PUINT4 = 0x00000475,
	T_32PFUINT4 = 0x00000575,
	T_64PUINT4 = 0x00000675,

	T_QUAD = 0x00000013,
	T_PQUAD = 0x00000113,
	T_PFQUAD = 0x00000213,
	T_PHQUAD = 0x00000313,
	T_32PQUAD = 0x00000413,
	T_32PFQUAD = 0x00000513,
	T_64PQUAD = 0x00000613,

	T_UQUAD = 0x00000023,
	T_PUQUAD = 0x00000123,
	T_PFUQUAD = 0x00000223,
	T_PHUQUAD = 0x00000323,
	T_32PUQUAD = 0x00000423,
	T_32PFUQUAD = 0x00000523,
	T_64PUQUAD = 0x00000623,

	T_INT8 = 0x00000076,
	T_PINT8 = 0x00000176,
	T_PFINT8 = 0x00000276,
	T_PHINT8 = 0x00000376,
	T_32PINT8 = 0x00000476,
	T_32PFINT8 = 0x00000576,
	T_64PINT8 = 0x00000676,

	T_UINT8 = 0x00000077,
	T_PUINT8 = 0x00000177,
	T_PFUINT8 = 0x00000277,
	T_PHUINT8 = 0x00000377,
	T_32PUINT8 = 0x00000477,
	T_32PFUINT8 = 0x00000577,
	T_64PUINT8 = 0x00000677,

	T_OCT = 0x00000014,
	T_POCT = 0x00000114,
	T_PFOCT = 0x00000214,
	T_PHOCT = 0x00000314,
	T_32POCT = 0x00000414,
	T_32PFOCT = 0x00000514,
	T_64POCT = 0x00000614,

	T_UOCT = 0x00000024,
	T_PUOCT = 0x00000124,
	T_PFUOCT = 0x00000224,
	T_PHUOCT = 0x00000324,
	T_32PUOCT = 0x00000424,
	T_32PFUOCT = 0x00000524,
	T_64PUOCT = 0x00000624,

	T_INT16 = 0x00000078,
	T_PINT16 = 0x00000178,
	T_PFINT16 = 0x00000278,
	T_PHINT16 = 0x00000378,
	T_32PINT16 = 0x00000478,
	T_32PFINT16 = 0x00000578,
	T_64PINT16 = 0x00000678,

	T_UINT16 = 0x00000079,
	T_PUINT16 = 0x00000179,
	T_PFUINT16 = 0x00000279,
	T_PHUINT16 = 0x00000379,
	T_32PUINT16 = 0x00000479,
	T_32PFUINT16 = 0x00000579,
	T_64PUINT16 = 0x00000679,

	T_REAL32 = 0x00000040,
	T_PREAL32 = 0x00000140,
	T_PFREAL32 = 0x00000240,
	T_PHREAL32 = 0x00000340,
	T_32PREAL32 = 0x00000440,
	T_32PFREAL32 = 0x00000540,
	T_64PREAL32 = 0x00000640,

	T_REAL48 = 0x00000044,
	T_PREAL48 = 0x00000144,
	T_PFREAL48 = 0x00000244,
	T_PHREAL48 = 0x00000344,
	T_32PREAL48 = 0x00000444,
	T_32PFREAL48 = 0x00000544,
	T_64PREAL48 = 0x00000644,

	T_REAL64 = 0x00000041,
	T_PREAL64 = 0x00000141,
	T_PFREAL64 = 0x00000241,
	T_PHREAL64 = 0x00000341,
	T_32PREAL64 = 0x00000441,
	T_32PFREAL64 = 0x00000541,
	T_64PREAL64 = 0x00000641,

	T_REAL80 = 0x00000042,
	T_PREAL80 = 0x00000142,
	T_PFREAL80 = 0x00000242,
	T_PHREAL80 = 0x00000342,
	T_32PREAL80 = 0x00000442,
	T_32PFREAL80 = 0x00000542,
	T_64PREAL80 = 0x00000642,

	T_REAL128 = 0x00000043,
	T_PREAL128 = 0x00000143,
	T_PFREAL128 = 0x00000243,
	T_PHREAL128 = 0x00000343,
	T_32PREAL128 = 0x00000443,
	T_32PFREAL128 = 0x00000543,
	T_64PREAL128 = 0x00000643,

	T_CPLX32 = 0x00000050,
	T_PCPLX32 = 0x00000150,
	T_PFCPLX32 = 0x00000250,
	T_PHCPLX32 = 0x00000350,
	T_32PCPLX32 = 0x00000450,
	T_32PFCPLX32 = 0x00000550,
	T_64PCPLX32 = 0x00000650,

	T_CPLX64 = 0x00000051,
	T_PCPLX64 = 0x00000151,
	T_PFCPLX64 = 0x00000251,
	T_PHCPLX64 = 0x00000351,
	T_32PCPLX64 = 0x00000451,
	T_32PFCPLX64 = 0x00000551,
	T_64PCPLX64 = 0x00000651,

	T_CPLX80 = 0x00000052,
	T_PCPLX80 = 0x00000152,
	T_PFCPLX80 = 0x00000252,
	T_PHCPLX80 = 0x00000352,
	T_32PCPLX80 = 0x00000452,
	T_32PFCPLX80 = 0x00000552,
	T_64PCPLX80 = 0x00000652,

	T_CPLX128 = 0x00000053,
	T_PCPLX128 = 0x00000153,
	T_PFCPLX128 = 0x00000253,
	T_PHCPLX128 = 0x00000353,
	T_32PCPLX128 = 0x00000453,
	T_32PFCPLX128 = 0x00000553,
	T_64PCPLX128 = 0x00000653,

	T_BOOL08 = 0x00000030,
	T_PBOOL08 = 0x00000130,
	T_PFBOOL08 = 0x00000230,
	T_PHBOOL08 = 0x00000330,
	T_32PBOOL08 = 0x00000430,
	T_32PFBOOL08 = 0x00000530,
	T_64PBOOL08 = 0x00000630,

	T_BOOL16 = 0x00000031,
	T_PBOOL16 = 0x00000131,
	T_PFBOOL16 = 0x00000231,
	T_PHBOOL16 = 0x00000331,
	T_32PBOOL16 = 0x00000431,
	T_32PFBOOL16 = 0x00000531,
	T_64PBOOL16 = 0x00000631,

	T_BOOL32 = 0x00000032,
	T_PBOOL32 = 0x00000132,
	T_PFBOOL32 = 0x00000232,
	T_PHBOOL32 = 0x00000332,
	T_32PBOOL32 = 0x00000432,
	T_32PFBOOL32 = 0x00000532,
	T_64PBOOL32 = 0x00000632,

	T_BOOL64 = 0x00000033,
	T_PBOOL64 = 0x00000133,
	T_PFBOOL64 = 0x00000233,
	T_PHBOOL64 = 0x00000333,
	T_32PBOOL64 = 0x00000433,
	T_32PFBOOL64 = 0x00000533,
	T_64PBOOL64 = 0x00000633,

	T_NCVPTR = 0x000001F0,
	T_FCVPTR = 0x000002F0,
	T_HCVPTR = 0x000003F0,
	T_32NCVPTR = 0x000004F0,
	T_32FCVPTR = 0x000005F0,
	T_64NCVPTR = 0x000006F0
} TYPE_ENUM_e, *PTYPE_ENUM_e, **PPTYPE_ENUM_e;

// =================================================================
// TYPE INFO RECORD TAGS
// =================================================================

typedef enum _LEAF_ENUM_e
{
	LF_MODIFIER_16t = 0x00000001,
	LF_POINTER_16t = 0x00000002,
	LF_ARRAY_16t = 0x00000003,
	LF_CLASS_16t = 0x00000004,
	LF_STRUCTURE_16t = 0x00000005,
	LF_UNION_16t = 0x00000006,
	LF_ENUM_16t = 0x00000007,
	LF_PROCEDURE_16t = 0x00000008,
	LF_MFUNCTION_16t = 0x00000009,
	LF_VTSHAPE = 0x0000000A,
	LF_COBOL0_16t = 0x0000000B,
	LF_COBOL1 = 0x0000000C,
	LF_BARRAY_16t = 0x0000000D,
	LF_LABEL = 0x0000000E,
	LF_NULL = 0x0000000F,
	LF_NOTTRAN = 0x00000010,
	LF_DIMARRAY_16t = 0x00000011,
	LF_VFTPATH_16t = 0x00000012,
	LF_PRECOMP_16t = 0x00000013,
	LF_ENDPRECOMP = 0x00000014,
	LF_OEM_16t = 0x00000015,
	LF_TYPESERVER_ST = 0x00000016,

	LF_SKIP_16t = 0x00000200,
	LF_ARGLIST_16t = 0x00000201,
	LF_DEFARG_16t = 0x00000202,
	LF_LIST = 0x00000203,
	LF_FIELDLIST_16t = 0x00000204,
	LF_DERIVED_16t = 0x00000205,
	LF_BITFIELD_16t = 0x00000206,
	LF_METHODLIST_16t = 0x00000207,
	LF_DIMCONU_16t = 0x00000208,
	LF_DIMCONLU_16t = 0x00000209,
	LF_DIMVARU_16t = 0x0000020A,
	LF_DIMVARLU_16t = 0x0000020B,
	LF_REFSYM = 0x0000020C,

	LF_BCLASS_16t = 0x00000400,
	LF_VBCLASS_16t = 0x00000401,
	LF_IVBCLASS_16t = 0x00000402,
	LF_ENUMERATE_ST = 0x00000403,
	LF_FRIENDFCN_16t = 0x00000404,
	LF_INDEX_16t = 0x00000405,
	LF_MEMBER_16t = 0x00000406,
	LF_STMEMBER_16t = 0x00000407,
	LF_METHOD_16t = 0x00000408,
	LF_NESTTYPE_16t = 0x00000409,
	LF_VFUNCTAB_16t = 0x0000040A,
	LF_FRIENDCLS_16t = 0x0000040B,
	LF_ONEMETHOD_16t = 0x0000040C,
	LF_VFUNCOFF_16t = 0x0000040D,

	LF_TI16_MAX = 0x00001000,
	LF_MODIFIER = 0x00001001,
	LF_POINTER = 0x00001002,
	LF_ARRAY_ST = 0x00001003,
	LF_CLASS_ST = 0x00001004,
	LF_STRUCTURE_ST = 0x00001005,
	LF_UNION_ST = 0x00001006,
	LF_ENUM_ST = 0x00001007,
	LF_PROCEDURE = 0x00001008,
	LF_MFUNCTION = 0x00001009,
	LF_COBOL0 = 0x0000100A,
	LF_BARRAY = 0x0000100B,
	LF_DIMARRAY_ST = 0x0000100C,
	LF_VFTPATH = 0x0000100D,
	LF_PRECOMP_ST = 0x0000100E,
	LF_OEM = 0x0000100F,
	LF_ALIAS_ST = 0x00001010,
	LF_OEM2 = 0x00001011,

	LF_SKIP = 0x00001200,
	LF_ARGLIST = 0x00001201,
	LF_DEFARG_ST = 0x00001202,
	LF_FIELDLIST = 0x00001203,
	LF_DERIVED = 0x00001204,
	LF_BITFIELD = 0x00001205,
	LF_METHODLIST = 0x00001206,
	LF_DIMCONU = 0x00001207,
	LF_DIMCONLU = 0x00001208,
	LF_DIMVARU = 0x00001209,
	LF_DIMVARLU = 0x0000120A,

	LF_BCLASS = 0x00001400,
	LF_VBCLASS = 0x00001401,
	LF_IVBCLASS = 0x00001402,
	LF_FRIENDFCN_ST = 0x00001403,
	LF_INDEX = 0x00001404,
	LF_MEMBER_ST = 0x00001405,
	LF_STMEMBER_ST = 0x00001406,
	LF_METHOD_ST = 0x00001407,
	LF_NESTTYPE_ST = 0x00001408,
	LF_VFUNCTAB = 0x00001409,
	LF_FRIENDCLS = 0x0000140A,
	LF_ONEMETHOD_ST = 0x0000140B,
	LF_VFUNCOFF = 0x0000140C,
	LF_NESTTYPEEX_ST = 0x0000140D,
	LF_MEMBERMODIFY_ST = 0x0000140E,
	LF_MANAGED_ST = 0x0000140F,

	LF_ST_MAX = 0x00001500,
	LF_TYPESERVER = 0x00001501,
	LF_ENUMERATE = 0x00001502,
	LF_ARRAY = 0x00001503,
	LF_CLASS = 0x00001504,
	LF_STRUCTURE = 0x00001505,
	LF_UNION = 0x00001506,
	LF_ENUM = 0x00001507,
	LF_DIMARRAY = 0x00001508,
	LF_PRECOMP = 0x00001509,
	LF_ALIAS = 0x0000150A,
	LF_DEFARG = 0x0000150B,
	LF_FRIENDFCN = 0x0000150C,
	LF_MEMBER = 0x0000150D,
	LF_STMEMBER = 0x0000150E,
	LF_METHOD = 0x0000150F,
	LF_NESTTYPE = 0x00001510,
	LF_ONEMETHOD = 0x00001511,
	LF_NESTTYPEEX = 0x00001512,
	LF_MEMBERMODIFY = 0x00001513,
	LF_MANAGED = 0x00001514,
	LF_TYPESERVER2 = 0x00001515,

	LF_NUMERIC = 0x00008000,
	LF_CHAR = 0x00008000,
	LF_SHORT = 0x00008001,
	LF_USHORT = 0x00008002,
	LF_LONG = 0x00008003,
	LF_ULONG = 0x00008004,
	LF_REAL32 = 0x00008005,
	LF_REAL64 = 0x00008006,
	LF_REAL80 = 0x00008007,
	LF_REAL128 = 0x00008008,
	LF_QUADWORD = 0x00008009,
	LF_UQUADWORD = 0x0000800A,
	LF_REAL48 = 0x0000800B,
	LF_COMPLEX32 = 0x0000800C,
	LF_COMPLEX64 = 0x0000800D,
	LF_COMPLEX80 = 0x0000800E,
	LF_COMPLEX128 = 0x0000800F,
	LF_VARSTRING = 0x00008010,
	LF_OCTWORD = 0x00008017,
	LF_UOCTWORD = 0x00008018,
	LF_DECIMAL = 0x00008019,
	LF_DATE = 0x0000801A,
	LF_UTF8STRING = 0x0000801B,

	LF_PAD0 = 0x000000F0,
	LF_PAD1 = 0x000000F1,
	LF_PAD2 = 0x000000F2,
	LF_PAD3 = 0x000000F3,
	LF_PAD4 = 0x000000F4,
	LF_PAD5 = 0x000000F5,
	LF_PAD6 = 0x000000F6,
	LF_PAD7 = 0x000000F7,
	LF_PAD8 = 0x000000F8,
	LF_PAD9 = 0x000000F9,
	LF_PAD10 = 0x000000FA,
	LF_PAD11 = 0x000000FB,
	LF_PAD12 = 0x000000FC,
	LF_PAD13 = 0x000000FD,
	LF_PAD14 = 0x000000FE,
	LF_PAD15 = 0x000000FF
} LEAF_ENUM_e, *PLEAF_ENUM_e, **PPLEAF_ENUM_e;

// =================================================================
// SYMBOL RECORD TAGS
// =================================================================

typedef enum _SYM_ENUM_e
{
	S_COMPILE = 0x00000001,
	S_REGISTER_16t = 0x00000002,
	S_CONSTANT_16t = 0x00000003,
	S_UDT_16t = 0x00000004,
	S_SSEARCH = 0x00000005,
	S_END = 0x00000006,
	S_SKIP = 0x00000007,
	S_CVRESERVE = 0x00000008,
	S_OBJNAME_ST = 0x00000009,
	S_ENDARG = 0x0000000A,
	S_COBOLUDT_16t = 0x0000000B,
	S_MANYREG_16t = 0x0000000C,
	S_RETURN = 0x0000000D,
	S_ENTRYTHIS = 0x0000000E,

	S_BPREL16 = 0x00000100,
	S_LDATA16 = 0x00000101,
	S_GDATA16 = 0x00000102,
	S_PUB16 = 0x00000103,
	S_LPROC16 = 0x00000104,
	S_GPROC16 = 0x00000105,
	S_THUNK16 = 0x00000106,
	S_BLOCK16 = 0x00000107,
	S_WITH16 = 0x00000108,
	S_LABEL16 = 0x00000109,
	S_CEXMODEL16 = 0x0000010A,
	S_VFTABLE16 = 0x0000010B,
	S_REGREL16 = 0x0000010C,

	S_BPREL32_16t = 0x00000200,
	S_LDATA32_16t = 0x00000201,
	S_GDATA32_16t = 0x00000202,
	S_PUB32_16t = 0x00000203,
	S_LPROC32_16t = 0x00000204,
	S_GPROC32_16t = 0x00000205,
	S_THUNK32_ST = 0x00000206,
	S_BLOCK32_ST = 0x00000207,
	S_WITH32_ST = 0x00000208,
	S_LABEL32_ST = 0x00000209,
	S_CEXMODEL32 = 0x0000020A,
	S_VFTABLE32_16t = 0x0000020B,
	S_REGREL32_16t = 0x0000020C,
	S_LTHREAD32_16t = 0x0000020D,
	S_GTHREAD32_16t = 0x0000020E,
	S_SLINK32 = 0x0000020F,

	S_LPROCMIPS_16t = 0x00000300,
	S_GPROCMIPS_16t = 0x00000301,

	S_PROCREF_ST = 0x00000400,
	S_DATAREF_ST = 0x00000401,
	S_ALIGN = 0x00000402,
	S_LPROCREF_ST = 0x00000403,
	S_OEM = 0x00000404,

	S_TI16_MAX = 0x00001000,
	S_REGISTER_ST = 0x00001001,
	S_CONSTANT_ST = 0x00001002,
	S_UDT_ST = 0x00001003,
	S_COBOLUDT_ST = 0x00001004,
	S_MANYREG_ST = 0x00001005,
	S_BPREL32_ST = 0x00001006,
	S_LDATA32_ST = 0x00001007,
	S_GDATA32_ST = 0x00001008,
	S_PUB32_ST = 0x00001009,
	S_LPROC32_ST = 0x0000100A,
	S_GPROC32_ST = 0x0000100B,
	S_VFTABLE32 = 0x0000100C,
	S_REGREL32_ST = 0x0000100D,
	S_LTHREAD32_ST = 0x0000100E,
	S_GTHREAD32_ST = 0x0000100F,
	S_LPROCMIPS_ST = 0x00001010,
	S_GPROCMIPS_ST = 0x00001011,
	S_FRAMEPROC = 0x00001012,
	S_COMPILE2_ST = 0x00001013,
	S_MANYREG2_ST = 0x00001014,
	S_LPROCIA64_ST = 0x00001015,
	S_GPROCIA64_ST = 0x00001016,
	S_LOCALSLOT_ST = 0x00001017,
	S_PARAMSLOT_ST = 0x00001018,
	S_ANNOTATION = 0x00001019,
	S_GMANPROC_ST = 0x0000101A,
	S_LMANPROC_ST = 0x0000101B,
	S_RESERVED1 = 0x0000101C,
	S_RESERVED2 = 0x0000101D,
	S_RESERVED3 = 0x0000101E,
	S_RESERVED4 = 0x0000101F,
	S_LMANDATA_ST = 0x00001020,
	S_GMANDATA_ST = 0x00001021,
	S_MANFRAMEREL_ST = 0x00001022,
	S_MANREGISTER_ST = 0x00001023,
	S_MANSLOT_ST = 0x00001024,
	S_MANMANYREG_ST = 0x00001025,
	S_MANREGREL_ST = 0x00001026,
	S_MANMANYREG2_ST = 0x00001027,
	S_MANTYPREF = 0x00001028,
	S_UNAMESPACE_ST = 0x00001029,

	S_ST_MAX = 0x00001100,
	S_OBJNAME = 0x00001101,
	S_THUNK32 = 0x00001102,
	S_BLOCK32 = 0x00001103,
	S_WITH32 = 0x00001104,
	S_LABEL32 = 0x00001105,
	S_REGISTER = 0x00001106,
	S_CONSTANT = 0x00001107,
	S_UDT = 0x00001108,
	S_COBOLUDT = 0x00001109,
	S_MANYREG = 0x0000110A,
	S_BPREL32 = 0x0000110B,
	S_LDATA32 = 0x0000110C,
	S_GDATA32 = 0x0000110D,
	S_PUB32 = 0x0000110E,
	S_LPROC32 = 0x0000110F,
	S_GPROC32 = 0x00001110,
	S_REGREL32 = 0x00001111,
	S_LTHREAD32 = 0x00001112,
	S_GTHREAD32 = 0x00001113,
	S_LPROCMIPS = 0x00001114,
	S_GPROCMIPS = 0x00001115,
	S_COMPILE2 = 0x00001116,
	S_MANYREG2 = 0x00001117,
	S_LPROCIA64 = 0x00001118,
	S_GPROCIA64 = 0x00001119,
	S_LOCALSLOT = 0x0000111A,
	S_SLOT = 0x0000111A,
	S_PARAMSLOT = 0x0000111B,
	S_LMANDATA = 0x0000111C,
	S_GMANDATA = 0x0000111D,
	S_MANFRAMEREL = 0x0000111E,
	S_MANREGISTER = 0x0000111F,
	S_MANSLOT = 0x00001120,
	S_MANMANYREG = 0x00001121,
	S_MANREGREL = 0x00001122,
	S_MANMANYREG2 = 0x00001123,
	S_UNAMESPACE = 0x00001124,
	S_PROCREF = 0x00001125,
	S_DATAREF = 0x00001126,
	S_LPROCREF = 0x00001127,
	S_ANNOTATIONREF = 0x00001128,
	S_TOKENREF = 0x00001129,
	S_GMANPROC = 0x0000112A,
	S_LMANPROC = 0x0000112B,
	S_TRAMPOLINE = 0x0000112C,
	S_MANCONSTANT = 0x0000112D,
	S_RECTYPE_LAST = 0x0000112D,
	S_RECTYPE_MAX = 0x0000112E
} SYM_ENUM_e, *PSYM_ENUM_e, **PPSYM_ENUM_e;

// =================================================================
// CALLING CONVENTIONS
// =================================================================

typedef enum _CV_call_e
{
	CV_CALL_NEAR_C = 0x00000000,
	CV_CALL_FAR_C = 0x00000001,
	CV_CALL_NEAR_PASCAL = 0x00000002,
	CV_CALL_FAR_PASCAL = 0x00000003,
	CV_CALL_NEAR_FAST = 0x00000004,
	CV_CALL_FAR_FAST = 0x00000005,
	CV_CALL_SKIPPED = 0x00000006,
	CV_CALL_NEAR_STD = 0x00000007,
	CV_CALL_FAR_STD = 0x00000008,
	CV_CALL_NEAR_SYS = 0x00000009,
	CV_CALL_FAR_SYS = 0x0000000A,
	CV_CALL_THISCALL = 0x0000000B,
	CV_CALL_MIPSCALL = 0x0000000C,
	CV_CALL_GENERIC = 0x0000000D,
	CV_CALL_ALPHACALL = 0x0000000E,
	CV_CALL_PPCCALL = 0x0000000F,
	CV_CALL_SHCALL = 0x00000010,
	CV_CALL_ARMCALL = 0x00000011,
	CV_CALL_AM33CALL = 0x00000012,
	CV_CALL_TRICALL = 0x00000013,
	CV_CALL_SH5CALL = 0x00000014,
	CV_CALL_M32RCALL = 0x00000015,
	CV_CALL_RESERVED = 0x00000016
} CV_call_e, *PCV_call_e, **PPCV_call_e;

// =================================================================
// POINTER TYPES
// =================================================================

typedef enum _CV_ptrtype_e
{
	CV_PTR_NEAR = 0x00000000,
	CV_PTR_FAR = 0x00000001,
	CV_PTR_HUGE = 0x00000002,
	CV_PTR_BASE_SEG = 0x00000003,
	CV_PTR_BASE_VAL = 0x00000004,
	CV_PTR_BASE_SEGVAL = 0x00000005,
	CV_PTR_BASE_ADDR = 0x00000006,
	CV_PTR_BASE_SEGADDR = 0x00000007,
	CV_PTR_BASE_TYPE = 0x00000008,
	CV_PTR_BASE_SELF = 0x00000009,
	CV_PTR_NEAR32 = 0x0000000A,
	CV_PTR_FAR32 = 0x0000000B,
	CV_PTR_64 = 0x0000000C,
	CV_PTR_UNUSEDPTR = 0x0000000D
} CV_ptrtype_e, *PCV_ptrtype_e, **PPCV_ptrtype_e;

// =================================================================
// POINTER MODES
// =================================================================

typedef enum _CV_ptrmode_e
{
	CV_PTR_MODE_PTR = 0x00000000,
	CV_PTR_MODE_REF = 0x00000001,
	CV_PTR_MODE_PMEM = 0x00000002,
	CV_PTR_MODE_PMFUNC = 0x00000003,
	CV_PTR_MODE_RESERVED = 0x00000004
} CV_ptrmode_e, *PCV_ptrmode_e, **PPCV_ptrmode_e;

// =================================================================
// ACCESS PROTECTION MODES
// =================================================================

typedef enum _CV_access_e
{
	CV_private = 0x00000001, CV_protected = 0x00000002, CV_public = 0x00000003
} CV_access_e, *PCV_access_e, **PPCV_access_e;

// =================================================================
// METHOD PROPERTIES
// =================================================================

typedef enum _CV_methodprop_e
{
	CV_MTvanilla = 0x00000000,
	CV_MTvirtual = 0x00000001,
	CV_MTstatic = 0x00000002,
	CV_MTfriend = 0x00000003,
	CV_MTintro = 0x00000004,
	CV_MTpurevirt = 0x00000005,
	CV_MTpureintro = 0x00000006
} CV_methodprop_e, *PCV_methodprop_e, **PPCV_methodprop_e;

// =================================================================
// CODEVIEW STRUCTURES
// =================================================================

#pragma pack (1)

// -----------------------------------------------------------------

typedef struct _NB10I
{
		/*000*/
		PDB_DWORD dwSig;
		/*004*/
		PDB_DWORD dwOffset;
		/*008*/
		PDB_DWORD sig;
		/*00C*/
		PDB_DWORD age;
		/*010*/
		PDB_BYTE szPdb[MAX_PATH];  // PDB file name
		/*114*/
} NB10I, *PNB10I, **PPNB10I;

#define NB10I_ sizeof (NB10I)

// -----------------------------------------------------------------

typedef struct _RSDSI
{
		/*000*/
		PDB_DWORD dwSig;
		/*004*/
		PDB_GUID guidSig;
		/*014*/
		PDB_DWORD age;
		/*018*/
		PDB_BYTE szPdb[3 * MAX_PATH];
		/*324*/} RSDSI, *PRSDSI, **PPRSDSI;

#define RSDSI_ sizeof (RSDSI)

// -----------------------------------------------------------------

typedef union _CV
{
		/*000*/
		PDB_DWORD dwSig;
		/*000*/
		NB10I nb10i;
		/*000*/
		RSDSI rsdsi;
		/*324*/} CV, *PCV, **PPCV;

#define CV_ sizeof (CV)

// -----------------------------------------------------------------

#pragma pack ()

// =================================================================
// MSF STRUCTURES
// =================================================================

#pragma pack (1)

// -----------------------------------------------------------------

typedef struct _SI_PERSIST
{
		/*000*/
		PDB_LONG cb;  // number of bytes
		/*004*/
		PDB_LONG mpspnpn;
		/*008*/} SI_PERSIST, *PSI_PERSIST, **PPSI_PERSIST;

#define SI_PERSIST_ sizeof (SI_PERSIST)

// -----------------------------------------------------------------

typedef struct _PG
{
		/*0000*/
		PDB_BYTE rgb[0x1000];  // page data
		/*1000*/
} PG, *PPG, **PPPG;

#define PG_ sizeof (PG)

// -----------------------------------------------------------------

typedef union _XMSF_HDR
{
		struct
		{
				/*0000*/
				PDB_BYTE szMagic[0x2C];
				/*002C*/
				PDB_LONG cbPg;
				/*0030*/
				PDB_WORD pnFpm;
				/*0032*/
				PDB_WORD pnMac;
				/*0034*/
				SI_PERSIST siSt;
				/*003C*/
				PDB_WORD mpspnpn[0x141];
				/*02BE*/};
		/*0000*/
		PG pg;
		/*1000*/} XMSF_HDR, *PXMSF_HDR, **PPXMSF_HDR;

#define XMSF_HDR_ sizeof (XMSF_HDR)

// -----------------------------------------------------------------

typedef union _BIGMSF_HDR
{
		struct
		{
				/*0000*/
				PDB_BYTE szMagic[0x1E];
				/*001E*/
				PDB_WORD reserved;
				/*0020*/
				PDB_LONG cbPg;
				/*0024*/
				PDB_DWORD pnFpm;
				/*0028*/
				PDB_DWORD pnMac;
				/*002C*/
				SI_PERSIST siSt;
				/*0034*/
				PDB_DWORD mpspnpnSt[0x49];
				/*0158*/};
		/*0000*/
		PG pg;
		/*1000*/} BIGMSF_HDR, *PBIGMSF_HDR, **PPBIGMSF_HDR;

#define BIGMSF_HDR_ sizeof (BIGMSF_HDR)

// -----------------------------------------------------------------

typedef struct _FPM
{
		/*000*/
		PDB_DWORD iwMac;
		/*004*/
		PDB_DWORD iwRover;
		/*008*/
		PDB_LONG cbPg;
		/*00C*/
		PDB_BOOLEAN fBigMsf;
		/*00D*/
		PDB_BYTE reserved1;  // padding
		/*00E*/
		PDB_WORD reserved2;  // padding
		/*010*/
		struct
		/*010*/
		{
				/*010*/
				PDB_DWORD rgt;
				/*014*/
				PDB_DWORD itMac;
				/*018*/
				PDB_DWORD itMax;
				/*01C*/} rgw;
		/*01C*/
		PDB_DWORD wFill;
		/*020*/} FPM, *PFPM, **PPFPM;

#define FPM_ sizeof (FPM)

// -----------------------------------------------------------------

#pragma pack ()

// =================================================================
// PDB INFO STRUCTURES (STREAM #1)
// =================================================================

#pragma pack (1)

// -----------------------------------------------------------------

#define GUID_SIG70 \
	{0x33DED1D8, 0x5D57, 0x40D0, \
	{0xA5, 0xE2, 0xF1, 0x71, 0x96, 0x98, 0x07, 0x21}}

// -----------------------------------------------------------------

typedef struct _PDBInfo
{
		/*000*/
		PDB_DWORD impv;
		/*004*/
		PDB_DWORD sig;
		/*008*/
		PDB_DWORD age;
		/*00C*/} PDBInfo, *PPDBInfo, **PPPDBInfo;

#define PDBInfo_ sizeof (PDBInfo)

// -----------------------------------------------------------------

typedef struct _PDBInfo70
{
		/*000*/
		PDBInfo pdbinfo;
		/*00C*/
		PDB_GUID sig70;
		/*01C*/} PDBInfo70, *PPDBInfo70, **PPPDBInfo70;

#define PDBInfo70_ sizeof (PDBInfo70)

// -----------------------------------------------------------------

#pragma pack ()

// =================================================================
// TPI STRUCTURES (STREAM #2)
// =================================================================

#pragma pack (1)

// -----------------------------------------------------------------

typedef struct _OffCb
{
		/*000*/
		PDB_LONG off;
		/*004*/
		PDB_LONG cb;
		/*008*/} OffCb, *POffCb, **PPOffCb;

#define OffCb_ sizeof (OffCb)

// -----------------------------------------------------------------

typedef struct _TpiHash
{
		/*000*/
		PDB_WORD sn;  // stream #
		/*002*/
		PDB_WORD snPad;  // padding
		/*004*/
		PDB_LONG cbHashKey;
		/*008*/
		PDB_LONG cHashBuckets;
		/*00C*/
		OffCb offcbHashVals;
		/*014*/
		OffCb offcbTiOff;
		/*01C*/
		OffCb offcbHashAdj;
		/*024*/} TpiHash, *PTpiHash, **PPTpiHash;

#define TpiHash_ sizeof (TpiHash)

// -----------------------------------------------------------------

typedef struct _HDR  // TPI stream header
{
		/*000*/
		PDB_DWORD vers;  // implementation version
		/*004*/
		PDB_LONG cbHdr;  // header size
		/*008*/
		PDB_DWORD tiMin;  // type index base  (0x1000..0xFFFFFF)
		/*00C*/
		PDB_DWORD tiMac;  // type index limit (0x1000..0xFFFFFF)
		/*010*/
		PDB_DWORD cbGprec;  // size of follow-up data
		/*014*/
		TpiHash tpihash;
		/*038*/} HDR, *PHDR, **PPHDR;

#define HDR_ sizeof (HDR)

// -----------------------------------------------------------------

typedef struct _OHDR
{
		/*000*/
		PDB_BYTE szMagic[0x2C];  // magic string
		/*02C*/
		PDB_DWORD vers;  // implementation version
		/*030*/
		PDB_DWORD sig;  // signature
		/*034*/
		PDB_DWORD age;  // file age
		/*038*/
		PDB_WORD tiMin;  // type index base
		/*03A*/
		PDB_WORD tiMac;  // type index limit
		/*03C*/
		PDB_LONG cb;  // size
		/*040*/
} OHDR, *POHDR, **PPOHDR;

#define OHDR_ sizeof (OHDR)

// -----------------------------------------------------------------

typedef struct _CV_prop_t
{
		/*000.0*/
		PDB_WORD packed :1;
		/*000.1*/
		PDB_WORD ctor :1;
		/*000.2*/
		PDB_WORD ovlops :1;
		/*000.3*/
		PDB_WORD isnested :1;
		/*000.4*/
		PDB_WORD cnested :1;
		/*000.5*/
		PDB_WORD opassign :1;
		/*000.6*/
		PDB_WORD opcast :1;
		/*000.7*/
		PDB_WORD fwdref :1;
		/*001.0*/
		PDB_WORD scoped :1;
		/*001.1*/
		PDB_WORD reserved :7;
		/*002*/} CV_prop_t, *PCV_prop_t, **PPCV_prop_t;

#define CV_prop_t_ sizeof (CV_prop_t)

// -----------------------------------------------------------------

typedef struct _CV_fldattr_t
{
		/*000.0*/
		PDB_WORD access :2;  // CV_access_e
		/*000.2*/
		PDB_WORD mprop :3;  // CV_methodprop_e
		/*000.5*/
		PDB_WORD pseudo :1;
		/*000.6*/
		PDB_WORD noinherit :1;
		/*000.7*/
		PDB_WORD noconstruct :1;
		/*001.0*/
		PDB_WORD compgenx :1;
		/*001.1*/
		PDB_WORD unused :7;
		/*002*/} CV_fldattr_t, *PCV_fldattr_t, **PPCV_fldattr_t;

#define CV_fldattr_t_ sizeof (CV_fldattr_t)

// -----------------------------------------------------------------

typedef struct _lfModifier  // const-modifier
{
		/*000*/
		PDB_WORD leaf;  // LF_MODIFIER
		/*002*/
		PDB_DWORD utype;  // underlying type
		/*006*/
		PDB_BYTE data[];  // ...
		/*006*/
} lfModifier, *PlfModifier, **PPlfModifier;

#define lfModifier_ sizeof (lfModifier)

// -----------------------------------------------------------------

typedef struct _lfArray  // array
{
		/*000*/
		PDB_WORD leaf;  // LF_ARRAY
		/*002*/
		PDB_DWORD elemtype;  // element type index
		/*006*/
		PDB_DWORD idxtype;  // indexing type index
		/*00A*/
		PDB_BYTE data[];  // size in bytes
		/*00A*/
} lfArray, *PlfArray, **PPlfArray;

#define lfArray_ sizeof (lfArray)

// -----------------------------------------------------------------

typedef struct _lfBitfield  // bitfield structure
{
		/*000*/
		PDB_WORD leaf;  // LF_BITFIELD
		/*002*/
		PDB_DWORD type;  // base type index
		/*006*/
		PDB_BYTE length;  // number of bits
		/*007*/
		PDB_BYTE position;  // bit offset of bit 0
		/*008*/
} lfBitfield, *PlfBitfield, **PPlfBitfield;

#define lfBitfield_ sizeof (lfBitfield)

// -----------------------------------------------------------------

typedef struct _lfClass  // class or structure
{
		/*000*/
		PDB_WORD leaf;  // LF_CLASS, LF_STRUCTURE
		/*002*/
		PDB_WORD count;  // number of members
		/*004*/
		CV_prop_t property;  // type properties
		/*006*/
		PDB_DWORD field;  // LF_FIELD descriptor index
		/*00A*/
		PDB_DWORD derived;
		/*00E*/
		PDB_DWORD vshape;
		/*012*/
		PDB_BYTE data[];  // size and name
		/*012*/
} lfClass, *PlfClass, **PPlfClass;

#define lfClass_ sizeof (lfClass)

// -----------------------------------------------------------------

typedef lfClass lfStructure, *PlfStructure, **PPlfStructure;
#define lfStructure_ sizeof (lfStructure)

// -----------------------------------------------------------------

typedef struct _lfUnion  // union
{
		/*000*/
		PDB_WORD leaf;  // LF_UNION
		/*002*/
		PDB_WORD count;  // number of members
		/*004*/
		CV_prop_t property;  // type properties
		/*006*/
		PDB_DWORD field;  // LF_FIELD descriptor index
		/*00A*/
		PDB_BYTE data[];  // size and name
		/*00A*/
} lfUnion, *PlfUnion, **PPlfUnion;

#define lfUnion_ sizeof (lfUnion)

// -----------------------------------------------------------------

typedef struct _lfEnum  // enumeration
{
		/*000*/
		PDB_WORD leaf;  // LF_ENUM
		/*002*/
		PDB_WORD count;  // number of members
		/*004*/
		CV_prop_t property;  // type properties
		/*006*/
		PDB_DWORD utype;  // underlying type
		/*00A*/
		PDB_DWORD field;  // LF_FIELD descriptor index
		/*00E*/
		PDB_BYTE Name[];  // name
		/*00E*/
} lfEnum, *PlfEnum, **PPlfEnum;

#define lfEnum_ sizeof (lfEnum)

// -----------------------------------------------------------------

typedef struct _lfPointer  // pointer to type
{
		/*000*/
		struct lfPointerBody
		/*000*/
		{
				/*000*/
				PDB_WORD leaf;  // LF_POINTER
				/*002*/
				PDB_DWORD utype;  // underlying type
				/*006*/
				struct lfPointerAttr
				/*006*/
				{
						/*006.0*/
						PDB_DWORD ptrtype :5;  // pointer type
						/*006.5*/
						PDB_DWORD ptrmode :3;  // pointer mode
						/*007.0*/
						PDB_DWORD isflat32 :1;  // 0:32 pointer
						/*007.1*/
						PDB_DWORD isvolatile :1;  // volatile pointer
						/*007.2*/
						PDB_DWORD isconst :1;  // constant pointer
						/*007.3*/
						PDB_DWORD isunaligned :1;  // unaligned pointer
						/*007.4*/
						PDB_DWORD isrestrict :1;  // restricted pointer
						/*007.5*/
						PDB_DWORD unused :19;  // currently unused
						/*00A*/
				} attr;
				/*00A*/} body;
		/*00A*/
		union
		/*00A*/
		{
				/*00A*/
				struct
				/*00A*/
				{
						/*00A*/
						PDB_DWORD pmclass;
						/*00E*/
						PDB_WORD pmenum;
						/*010*/} pm;
				/*00A*/
				PDB_WORD bseg;
				/*00A*/
				struct
				/*00A*/
				{
						/*00A*/
						PDB_DWORD index;
						/*00E*/
						PDB_BYTE name[];
						/*00E*/} btype;
				/*010*/} pbase;
		/*010*/} lfPointer, *PlfPointer, **PPlfPointer;

#define lfPointer_ sizeof (lfPointer)

// -----------------------------------------------------------------

typedef struct _lfProc  // procedure
{
		/*000*/
		PDB_WORD leaf;  // LF_PROCEDURE
		/*002*/
		PDB_DWORD rvtype;  // return value type
		/*006*/
		PDB_BYTE calltype;  // calling convention (CV_call_e)
		/*007*/
		PDB_BYTE reserved;  // currently not used
		/*008*/
		PDB_WORD parmcount;  // number of parameters
		/*00A*/
		PDB_DWORD arglist;  // argument list type
		/*00E*/
} lfProc, *PlfProc, **PPlfProc;

#define lfProc_ sizeof (lfProc)

// -----------------------------------------------------------------

typedef struct _lfMFunc  // member function
{
		/*000*/
		PDB_WORD leaf;  // LF_MFUNCTION
		/*002*/
		PDB_DWORD rvtype;  // return value type
		/*006*/
		PDB_DWORD classtype;  // containing class type
		/*00A*/
		PDB_DWORD thistype;  // this-pointer type
		/*00E*/
		PDB_BYTE calltype;  // calling convention (CV_call_e)
		/*00F*/
		PDB_BYTE reserved;  // currently not used
		/*010*/
		PDB_WORD parmcount;  // number of parameters
		/*012*/
		PDB_DWORD arglist;  // argument list type
		/*016*/
		PDB_LONG thisadjust;  // this-adjuster
		/*01A*/
} lfMFunc, *PlfMFunc, **PPlfMFunc;

#define lfMFunc_ sizeof (lfMFunc)

// -----------------------------------------------------------------

typedef struct _lfArgList  // procedure argument list
{
		/*000*/
		PDB_WORD leaf;  // LF_ARGLIST
		/*002*/
		PDB_DWORD count;  // number of arguments
		/*006*/
		PDB_DWORD arg[];  // argument types
		/*006*/
} lfArgList, *PlfArgList, **PPlfArgList;

#define lfArgList_ sizeof (lfArgList)

// -----------------------------------------------------------------

typedef struct _lfVTShape  // virtual function table shape
{
		/*000*/
		PDB_WORD leaf;  // LF_VTSHAPE
		/*002*/
		PDB_WORD count;  // number of VFT entries
		/*004*/
		PDB_BYTE desc[];  // 4-bit descriptor list
		/*004*/
} lfVTShape, *PlfVTShape, **PPlfVTShape;

#define lfVTShape_ sizeof (lfVTShape)

// -----------------------------------------------------------------

typedef struct _lfEnumerate  // enumeration member
{
		/*000*/
		PDB_WORD leaf;  // LF_ENUMERATE
		/*002*/
		CV_fldattr_t attr;
		/*004*/
		PDB_BYTE value[];
		/*004*/} lfEnumerate, *PlfEnumerate, **PPlfEnumerate;

#define lfEnumerate_ sizeof (lfEnumerate)

// -----------------------------------------------------------------

typedef struct _lfMember  // non-static data member
{
		/*000*/
		PDB_WORD leaf;  // LF_MEMBER
		/*002*/
		CV_fldattr_t attr;
		/*004*/
		PDB_DWORD index;
		/*008*/
		PDB_BYTE offset[];
		/*00^8*/} lfMember, *PlfMember, **PPlfMember;

#define lfMember_ sizeof (lfMember)

// -----------------------------------------------------------------

typedef struct _lfBClass  // base class field
{
		/*000*/
		PDB_WORD leaf;  // LF_BCLASS
		/*002*/
		CV_fldattr_t attr;
		/*004*/
		PDB_DWORD index;
		/*008*/
		PDB_BYTE offset[];
		/*008*/} lfBClass, *PlfBClass, **PPlfBClass;

#define lfBClass_ sizeof (lfBClass)

// -----------------------------------------------------------------

typedef struct _lfVFuncTab  // virtual function table pointer
{
		/*000*/
		PDB_WORD leaf;  // LF_VFUNCTAB
		/*002*/
		PDB_WORD pad0;  // padding
		/*004*/
		PDB_DWORD type;  // VFT pointer type
		/*008*/
} lfVFuncTab, *PlfVFuncTab, **PPlfVFuncTab;

#define lfVFuncTab_ sizeof (lfVFuncTab)

// -----------------------------------------------------------------

typedef struct _lfOneMethod  // non-overloaded method
{
		/*000*/
		PDB_WORD leaf;  // LF_ONEMETHOD
		/*002*/
		CV_fldattr_t attr;
		/*004*/
		PDB_DWORD index;
		/*008*/
		PDB_DWORD vbaseoff[];  // VFT base offset, if present
		/*008*/
} lfOneMethod, *PlfOneMethod, **PPlfOneMethod;

#define lfOneMethod_ sizeof (lfOneMethod)

// -----------------------------------------------------------------

typedef struct _lfMethod  // overloaded method list
{
		/*000*/
		PDB_WORD leaf;  // LF_METHOD
		/*002*/
		PDB_WORD count;  // number of occurrences
		/*004*/
		PDB_DWORD mList;  // LF_METHODLIST descriptor index
		/*008*/
		PDB_BYTE Name[];
		/*008*/} lfMethod, *PlfMethod, **PPlfMethod;

#define lfMethod_ sizeof (lfMethod)

// -----------------------------------------------------------------

typedef struct _lfNestType  // nested type definition
{
		/*000*/
		PDB_WORD leaf;  // LF_NESTTYPE
		/*002*/
		PDB_WORD pad0;
		/*004*/
		PDB_DWORD index;
		/*008*/
		PDB_BYTE Name[];
		/*008*/} lfNestType, *PlfNestType, **PPlfNestType;

#define lfNestType_ sizeof (lfNestType)

// -----------------------------------------------------------------

typedef union _lfSubRecord
{
		/*000*/
		PDB_WORD leaf;  // LF_*
		/*000*/
		lfEnumerate Enumerate;  // LF_ENUMERATE
		/*000*/
		lfMember Member;  // LF_MEMBER
		/*000*/
		lfBClass BClass;  // LF_BCLASS
		/*000*/
		lfVFuncTab VFuncTab;  // LF_VFUNCTAB
		/*000*/
		lfOneMethod OneMethod;  // LF_ONEMETHOD
		/*000*/
		lfMethod Method;  // LF_METHOD
		/*000*/
		lfNestType NestType;  // LF_NESTTYPE
} lfSubRecord, *PlfSubRecord, **PPlfSubRecord;

#define lfSubRecord_ sizeof (lfSubRecord)

// -----------------------------------------------------------------

typedef struct _lfFieldList  // struct/union/enum members
{
		/*000*/
		PDB_WORD leaf;  // LF_FIELDLIST
		/*002*/
		lfSubRecord SubRecord;
		/*002*/} lfFieldList, *PlfFieldList, **PPlfFieldList;

#define lfFieldList_ sizeof (lfFieldList)

// -----------------------------------------------------------------

typedef union _lfRecord
{
		/*000*/
		PDB_WORD leaf;  // LF_*
		/*000*/
		lfArray Array;  // LF_ARRAY
		/*000*/
		lfBitfield Bitfield;  // LF_BITFIELD
		/*000*/
		lfClass Class;  // LF_CLASS
		/*000*/
		lfStructure Structure;  // LF_STRUCTURE
		/*000*/
		lfUnion Union;  // LF_UNION
		/*000*/
		lfEnum Enum;  // LF_ENUM
		/*000*/
		lfPointer Pointer;  // LF_POINTER
		/*000*/
		lfProc Proc;  // LF_PROCEDURE
		/*000*/
		lfMFunc MFunc;  // LF_MFUNCTION
		/*000*/
		lfModifier Modifier;  // LF_MODIFIER
		/*000*/
		lfArgList ArgList;  // LF_ARGLIST
		/*000*/
		lfVTShape VTShape;  // LF_VTSHAPE
		/*000*/
		lfFieldList FieldList;  // LF_FIELDLIST
} lfRecord, *PlfRecord, **PPlfRecord;

#define lfRecord_ sizeof (lfRecord)

// -----------------------------------------------------------------

#pragma pack ()

// =================================================================
// DBI STRUCTURES (STREAM #3)
// =================================================================

#pragma pack (1)

// -----------------------------------------------------------------

#define hdrSignature 0xFFFFFFFF
#define hdrVersion     19990903

// -----------------------------------------------------------------

typedef struct _DBIHdr
{
		/*000*/
		PDB_WORD snGSSyms;  // stream #
		/*002*/
		PDB_WORD snPSSyms;  // stream #
		/*004*/
		PDB_WORD snSymRecs;  // stream #
		/*006*/
		PDB_WORD reserved;  // padding
		/*008*/
		PDB_LONG cbGpModi;
		/*00C*/
		PDB_LONG cbSC;
		/*010*/
		PDB_LONG cbSecMap;
		/*014*/
		PDB_LONG cbFileInfo;
		/*018*/} DBIHdr, *PDBIHdr, **PPDBIHdr;

#define DBIHdr_ sizeof (DBIHdr)

// -----------------------------------------------------------------

typedef struct _NewDBIHdr
{
		/*000*/
		PDB_DWORD verSignature;
		/*004*/
		PDB_DWORD verHdr;
		/*008*/
		PDB_DWORD age;
		/*00C*/
		PDB_WORD snGSSyms;  // stream #
		/*00E*/
		PDB_WORD usVerPdbDllMajMin;
		/*010*/
		PDB_WORD snPSSyms;  // stream #
		/*012*/
		PDB_WORD usVerPdbDllBuild;
		/*014*/
		union
		/*014*/
		{
				/*014*/
				PDB_WORD snSymRecs;  // stream #
				/*014*/
				PDB_DWORD ulunusedPad2;
				/*018*/};
		/*018*/
		PDB_LONG cbGpModi;
		/*01C*/
		PDB_LONG cbSC;
		/*020*/
		PDB_LONG cbSecMap;
		/*024*/
		PDB_LONG cbFileInfo;
		/*028*/
		PDB_LONG cbTSMap;
		/*02C*/
		PDB_DWORD iMFC;
		/*030*/
		PDB_LONG cbDbgHdr;
		/*034*/
		PDB_LONG cbECInfo;
		/*038*/
		PDB_WORD flags;
		/*03A*/
		PDB_WORD wMachine;
		/*03C*/
		PDB_DWORD rgulReserved[1];
		/*040*/} NewDBIHdr, *PNewDBIHdr, **PPNewDBIHdr;

#define NewDBIHdr_ sizeof (NewDBIHdr)

// -----------------------------------------------------------------

typedef struct _ECInfo
{
		/*000*/
		PDB_DWORD niSrcFile;
		/*004*/
		PDB_DWORD niPdbFile;
		/*008*/} ECInfo, *PECInfo, **PPECInfo;

#define ECInfo_ sizeof (ECInfo)

// -----------------------------------------------------------------

typedef struct _SC40
{
		/*000*/
		PDB_WORD isect;
		/*002*/
		PDB_WORD reserved1;
		/*004*/
		PDB_LONG off;
		/*008*/
		PDB_LONG cb;
		/*00C*/
		PDB_DWORD dwCharacteristics;
		/*010*/
		PDB_WORD imod;
		/*012*/
		PDB_WORD reserved2;
		/*014*/} SC40, *PSC40, **PPSC40;

#define SC40_ sizeof (SC40)

// -----------------------------------------------------------------

typedef struct _SC
{
		/*000*/
		SC40 sc40;
		/*014*/
		PDB_DWORD dwDataCrc;
		/*018*/
		PDB_DWORD dwRelocCrc;
		/*01C*/} SC, *PSC, **PPSC;

#define SC_ sizeof (SC)

// -----------------------------------------------------------------

typedef struct _MODI
{
		/*000*/
		PDB_DWORD pmod;  // Mod *
		/*004*/
		SC sc;
		/*020*/
		struct
		/*020*/
		{
				/*020.0*/
				PDB_WORD fWritten :1;
				/*020.1*/
				PDB_WORD fECEnabled :1;
				/*020.2*/
				PDB_WORD unused :6;
				/*021.0*/
				PDB_WORD iTSM :8;
				/*022*/};
		/*022*/
		PDB_WORD sn;  // stream number
		/*024*/
		PDB_LONG cbSyms;  // number of symbols
		/*028*/
		PDB_LONG cbLines;  // number of lines
		/*02C*/
		PDB_LONG cbC13Lines;
		/*030*/
		PDB_WORD ifileMac;
		/*032*/
		PDB_WORD reserved;  // currently not used
		/*034*/
		PDB_LONG mpifileichFile;
		/*038*/
		ECInfo ecInfo;
		/*040*/
		PDB_BYTE rgch[];
		/*040*/} MODI, *PMODI, **PPMODI;

#define MODI_ sizeof (MODI)

// -----------------------------------------------------------------

#pragma pack ()

// =================================================================
// FPO STRUCTURES
// =================================================================

#pragma pack (1)

// -----------------------------------------------------------------

typedef struct PDB__FPO_DATA
{
		/*000*/
		PDB_DWORD ulOffStart;
		/*004*/
		PDB_DWORD cbProcSize;
		/*008*/
		PDB_DWORD cdwLocals;
		/*00C*/
		PDB_WORD cdwParams;
		struct
		{
				/*00E.0*/
				PDB_WORD cbProlog :8;
				/*00F.0*/
				PDB_WORD cbRegs :3;
				/*00F.3*/
				PDB_WORD fHasSEH :1;
				/*00F.4*/
				PDB_WORD fUseBP :1;
				/*00F.5*/
				PDB_WORD reserved :1;
				/*00F.6*/
				PDB_WORD cbFrame :2;
		};
		/*010*/} PDB_FPO_DATA, *PDB_PFPO_DATA, **PDB_PPFPO_DATA;

#define FPO_DATA_ sizeof (FPO_DATA)

// -----------------------------------------------------------------

#pragma pack ()

// =================================================================
// PSGSI STRUCTURES
// =================================================================

#pragma pack (1)

// -----------------------------------------------------------------

typedef struct _PSGSIHDR
{
		/*000*/
		PDB_LONG cbSymHash;
		/*004*/
		PDB_LONG cbAddrMap;
		/*008*/
		PDB_DWORD nThunks;
		/*00C*/
		PDB_LONG cbSizeOfThunk;
		/*010*/
		PDB_WORD isectThunkTable;
		/*012*/
		PDB_WORD reserved;  // padding
		/*014*/
		PDB_LONG offThunkTable;
		/*018*/
		PDB_DWORD nSects;
		/*01C*/} PSGSIHDR, *PPSGSIHDR, **PPPSGSIHDR;

#define PSGSIHDR_ sizeof (PSGSIHDR)

// -----------------------------------------------------------------

typedef struct _GSIHashHdr
{
		/*000*/
		PDB_DWORD verSignature;
		/*004*/
		PDB_DWORD verHdr;
		/*008*/
		PDB_LONG cbHr;
		/*00C*/
		PDB_LONG cbBuckets;
		/*010*/} GSIHashHdr, *PGSIHashHdr, **PPGSIHashHdr;

#define GSIHashHdr_ sizeof (GSIHashHdr)

// -----------------------------------------------------------------

#pragma pack ()

// =================================================================
// SYMBOL RECORDS
// =================================================================

#pragma pack (1)

// -----------------------------------------------------------------

typedef enum _CV_PUBSYMFLAGS_e
{
	cvpsfNone = 0x00000000,
	cvpsfCode = 0x00000001,
	cvpsfFunction = 0x00000002,
	cvpsfManaged = 0x00000004,
	cvpsfMSIL = 0x00000008
} CV_PUBSYMFLAGS_e, *PCV_PUBSYMFLAGS_e, **PPCV_PUBSYMFLAGS_e;

// -----------------------------------------------------------------

typedef union _CV_GENERIC_FLAG
{
		/*000.0*/
		PDB_WORD cstyle :1;
		/*000.1*/
		PDB_WORD rsclean :1;
		/*000.2*/
		PDB_WORD unused :14;
		/*002*/} CV_GENERIC_FLAG, *PCV_GENERIC_FLAG, **PPCV_GENERIC_FLAG;

#define CV_GENERIC_FLAG_ sizeof (CV_GENERIC_FLAG)

// -----------------------------------------------------------------

typedef union _CV_PUBSYMFLAGS
{
		/*000*/
		PDB_DWORD grfFlags;  // CV_PUBSYMFLAGS_e
		/*000*/
		struct
		/*000*/
		{
				/*000.0*/
				PDB_DWORD fCode :1;
				/*000.1*/
				PDB_DWORD fFunction :1;
				/*000.2*/
				PDB_DWORD fManaged :1;
				/*000.3*/
				PDB_DWORD fMSIL :1;
				/*000.4*/
				PDB_DWORD reserved :28;
				/*004*/};
		/*004*/} CV_PUBSYMFLAGS, *PCV_PUBSYMFLAGS, **PPCV_PUBSYMFLAGS;

#define CV_PUBSYMFLAGS_ sizeof (CV_PUBSYMFLAGS)

// -----------------------------------------------------------------

typedef union _CV_PROCFLAGS
{
		/*000*/
		PDB_BYTE bAll;
		/*000*/
		PDB_BYTE grfAll;
		/*000*/
		struct
		/*000*/
		{
				/*000.0*/
				PDB_BYTE CV_PFLAG_NOFPO :1;
				/*000.1*/
				PDB_BYTE CV_PFLAG_INT :1;
				/*000.2*/
				PDB_BYTE CV_PFLAG_FAR :1;
				/*000.3*/
				PDB_BYTE CV_PFLAG_NEVER :1;
				/*000.4*/
				PDB_BYTE CV_PFLAG_NOTREACHED :1;
				/*000.5*/
				PDB_BYTE CV_PFLAG_CUST_CALL :1;
				/*000.6*/
				PDB_BYTE CV_PFLAG_NOINLINE :1;
				/*000.7*/
				PDB_BYTE unused :1;
				/*001*/};
		/*001*/} CV_PROCFLAGS, *PCV_PROCFLAGS, **PPCV_PROCFLAGS;

#define CV_PROCFLAGS_ sizeof (CV_PROCFLAGS)

// -----------------------------------------------------------------

typedef struct _CV_LVARFLAGS
{
		/*000.0*/
		PDB_WORD fIsParam :1;
		/*000.1*/
		PDB_WORD fAddrTaken :1;
		/*000.2*/
		PDB_WORD fCompGenx :1;
		/*000.3*/
		PDB_WORD unused :13;
		/*002*/} CV_LVARFLAGS, *PCV_LVARFLAGS, **PPCV_LVARFLAGS;

#define CV_LVARFLAGS_ sizeof (CV_LVARFLAGS)

// -----------------------------------------------------------------

typedef struct _CV_lvar_attr
{
		/*000*/
		PDB_DWORD off;
		/*004*/
		PDB_WORD seg;
		/*006*/
		CV_LVARFLAGS flags;
		/*008*/} CV_lvar_attr, *PCV_lvar_attr, **PPCV_lvar_attr;

#define CV_lvar_attr_ sizeof (CV_lvar_attr)

// -----------------------------------------------------------------

typedef struct _ALIGNSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
} ALIGNSYM, *PALIGNSYM, **PPALIGNSYM;

#define ALIGNSYM_ sizeof (ALIGNSYM)

// -----------------------------------------------------------------

typedef struct _ANNOTATIONSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD off;
		/*008*/
		PDB_WORD seg;
		/*00A*/
		PDB_WORD csz;
		/*00C*/
		PDB_BYTE rgsz[1];
		/*00D*/} ANNOTATIONSYM, *PANNOTATIONSYM, **PPANNOTATIONSYM;

#define ANNOTATIONSYM_ sizeof (ANNOTATIONSYM)

// -----------------------------------------------------------------

typedef struct _ATTRMANYREGSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD typind;
		/*008*/
		CV_lvar_attr attr;
		/*010*/
		PDB_BYTE count;
		/*011*/
		PDB_BYTE reg[1];
		/*012*/} ATTRMANYREGSYM, *PATTRMANYREGSYM, **PPATTRMANYREGSYM;

#define ATTRMANYREGSYM_ sizeof (ATTRMANYREGSYM)

// -----------------------------------------------------------------

typedef struct _ATTRMANYREGSYM2
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD typind;
		/*008*/
		CV_lvar_attr attr;
		/*010*/
		PDB_WORD count;
		/*012*/
		PDB_WORD reg[1];
		/*014*/} ATTRMANYREGSYM2, *PATTRMANYREGSYM2, **PPATTRMANYREGSYM2;

#define ATTRMANYREGSYM2_ sizeof (ATTRMANYREGSYM2)

// -----------------------------------------------------------------

typedef struct _ATTRREGREL
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD off;
		/*008*/
		PDB_DWORD typind;
		/*00C*/
		PDB_WORD reg;
		/*00E*/
		CV_lvar_attr attr;
		/*016*/
		PDB_BYTE name[1];
		/*017*/} ATTRREGREL, *PATTRREGREL, **PPATTRREGREL;

#define ATTRREGREL_ sizeof (ATTRREGREL)

// -----------------------------------------------------------------

typedef struct _ATTRREGSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD typind;
		/*008*/
		CV_lvar_attr attr;
		/*010*/
		PDB_WORD reg;
		/*012*/
		PDB_BYTE name[1];
		/*013*/} ATTRREGSYM, *PATTRREGSYM, **PPATTRREGSYM;

#define ATTRREGSYM_ sizeof (ATTRREGSYM)

// -----------------------------------------------------------------

typedef struct _ATTRSLOTSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD iSlot;
		/*008*/
		PDB_DWORD typind;
		/*00C*/
		CV_lvar_attr attr;
		/*014*/
		PDB_BYTE name[1];
		/*015*/} ATTRSLOTSYM, *PATTRSLOTSYM, **PPATTRSLOTSYM;

#define ATTRSLOTSYM_ sizeof (ATTRSLOTSYM)

// -----------------------------------------------------------------

typedef struct _BLOCKSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/} BLOCKSYM, *PBLOCKSYM, **PPBLOCKSYM;

#define BLOCKSYM_ sizeof (BLOCKSYM)

// -----------------------------------------------------------------

typedef struct _BLOCKSYM16
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/
		PDB_WORD len;
		/*00E*/
		PDB_WORD off;
		/*010*/
		PDB_WORD seg;
		/*012*/
		PDB_BYTE name[1];
		/*013*/} BLOCKSYM16, *PBLOCKSYM16, **PPBLOCKSYM16;

#define BLOCKSYM16_ sizeof (BLOCKSYM16)

// -----------------------------------------------------------------

typedef struct _BLOCKSYM32
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/
		PDB_DWORD len;
		/*010*/
		PDB_DWORD off;
		/*014*/
		PDB_WORD seg;
		/*016*/
		PDB_BYTE name[1];
		/*017*/} BLOCKSYM32, *PBLOCKSYM32, **PPBLOCKSYM32;

#define BLOCKSYM32_ sizeof (BLOCKSYM32)

// -----------------------------------------------------------------

typedef struct _BPRELSYM16
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_SHORT off;
		/*006*/
		PDB_WORD typind;
		/*008*/
		PDB_BYTE name[1];
		/*009*/} BPRELSYM16, *PBPRELSYM16, **PPBPRELSYM16;

#define BPRELSYM16_ sizeof (BPRELSYM16)

// -----------------------------------------------------------------

typedef struct _BPRELSYM32
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_LONG off;
		/*008*/
		PDB_DWORD typind;
		/*00C*/
		PDB_BYTE name[1];
		/*00D*/} BPRELSYM32, *PBPRELSYM32, **PPBPRELSYM32;

#define BPRELSYM32_ sizeof (BPRELSYM32)

// -----------------------------------------------------------------

typedef struct _BPRELSYM32_16t
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_LONG off;
		/*008*/
		PDB_WORD typind;
		/*00A*/
		PDB_BYTE name[1];
		/*00B*/} BPRELSYM32_16t, *PBPRELSYM32_16t, **PPBPRELSYM32_16t;

#define BPRELSYM32_16t_ sizeof (BPRELSYM32_16t)

// -----------------------------------------------------------------

typedef struct _CEXMSYM16
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_WORD off;
		/*006*/
		PDB_WORD seg;
		/*008*/
		PDB_WORD model;
		/*00A*/
		union
		/*00A*/
		{
				/*00A*/
				struct
				/*00A*/
				{
						/*00A*/
						PDB_WORD pcdtable;
						/*00C*/
						PDB_WORD pcdspi;
						/*00E*/} pcode;
				/*00A*/
				struct
				/*00A*/
				{
						/*00A*/
						PDB_WORD subtype;
						/*00C*/
						PDB_WORD flag;
						/*00E*/} cobol;
				/*00E*/};
		/*00E*/} CEXMSYM16, *PCEXMSYM16, **PPCEXMSYM16;

#define CEXMSYM16_ sizeof (CEXMSYM16)

// -----------------------------------------------------------------

typedef struct _CEXMSYM32
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD off;
		/*008*/
		PDB_WORD seg;
		/*00A*/
		PDB_WORD model;
		/*00C*/
		union
		/*00C*/
		{
				/*00C*/
				struct
				/*00C*/
				{
						/*00C*/
						PDB_DWORD pcdtable;
						/*010*/
						PDB_DWORD pcdspi;
						/*014*/} pcode;
				/*00C*/
				struct
				/*00C*/
				{
						/*00C*/
						PDB_WORD subtype;
						/*00E*/
						PDB_WORD flag;
						/*010*/} cobol;
				/*00C*/
				struct
				/*00C*/
				{
						/*00C*/
						PDB_DWORD calltableOff;
						/*010*/
						PDB_WORD calltableSeg;
						/*012*/} pcode32Mac;
				/*014*/};
		/*014*/} CEXMSYM32, *PCEXMSYM32, **PPCEXMSYM32;

#define CEXMSYM32_ sizeof (CEXMSYM32)

// -----------------------------------------------------------------

typedef struct _CFLAGSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_BYTE machine;
		struct
		{
				/*005.0*/
				PDB_BYTE language :8;
				/*006.0*/
				PDB_BYTE pcode :1;
				/*006.1*/
				PDB_BYTE floatprec :2;
				/*006.3*/
				PDB_BYTE floatpkg :2;
				/*006.5*/
				PDB_BYTE ambdata :3;
				/*007.0*/
				PDB_BYTE ambcode :3;
				/*007.3*/
				PDB_BYTE mode32 :1;
				/*007.4*/
				PDB_BYTE pad :4;
		} flags;
		/*008*/
		PDB_BYTE ver[];
		/*009*/} CFLAGSYM, *PCFLAGSYM, **PPCFLAGSYM;

#define CFLAGSYM_ sizeof (CFLAGSYM)

// -----------------------------------------------------------------

typedef struct _COMPILESYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		struct
		/*004*/
		{
				/*004.0*/
				PDB_DWORD iLanguage :8;
				/*004.0*/
				PDB_DWORD fEC :1;
				/*004.0*/
				PDB_DWORD fNoDbgInfo :1;
				/*004.0*/
				PDB_DWORD fLTCG :1;
				/*004.0*/
				PDB_DWORD fNoDataAlign :1;
				/*004.0*/
				PDB_DWORD fManagedPresent :1;
				/*004.0*/
				PDB_DWORD pad :19;
		} flags;
		/*008*/
		PDB_WORD machine;
		/*00A*/
		PDB_WORD verFEMajor;
		/*00C*/
		PDB_WORD verFEMinor;
		/*00E*/
		PDB_WORD verFEBuild;
		/*010*/
		PDB_WORD verMajor;
		/*012*/
		PDB_WORD verMinor;
		/*014*/
		PDB_WORD verBuild;
		/*016*/
		PDB_BYTE verSt[1];
		/*017*/} COMPILESYM, *PCOMPILESYM, **PPCOMPILESYM;

#define COMPILESYM_ sizeof (COMPILESYM)

// -----------------------------------------------------------------

typedef struct _CONSTSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD typind;
		/*008*/
		PDB_WORD value;
		/*00A*/
		PDB_BYTE name[];
		/*00A*/} CONSTSYM, *PCONSTSYM, **PPCONSTSYM;

#define CONSTSYM_ sizeof (CONSTSYM)

// -----------------------------------------------------------------

typedef struct _CONSTSYM_16t
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_WORD typind;
		/*006*/
		PDB_WORD value;
		/*008*/
		PDB_BYTE name[];
		/*008*/} CONSTSYM_16t, *PCONSTSYM_16t, **PPCONSTSYM_16t;

#define CONSTSYM_16t_ sizeof (CONSTSYM_16t)

// -----------------------------------------------------------------

typedef struct _DATASYM16
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_WORD off;
		/*006*/
		PDB_WORD seg;
		/*008*/
		PDB_WORD typind;
		/*00A*/
		PDB_BYTE name[1];
		/*00B*/} DATASYM16, *PDATASYM16, **PPDATASYM16;

#define DATASYM16_ sizeof (DATASYM16)

// -----------------------------------------------------------------

typedef struct _DATASYM32
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD typind;
		/*008*/
		PDB_LONG off;
		/*00C*/
		PDB_WORD seg;
		/*00E*/
		PDB_BYTE name[1];
		/*00F*/} DATASYM32, *PDATASYM32, **PPDATASYM32;

#define DATASYM32_ sizeof (DATASYM32)

// -----------------------------------------------------------------

typedef struct _ENTRYTHISSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_BYTE thissym;
		/*005*/} ENTRYTHISSYM, *PENTRYTHISSYM, **PPENTRYTHISSYM;

#define ENTRYTHISSYM_ sizeof (ENTRYTHISSYM)

// -----------------------------------------------------------------

typedef struct _FRAMEPROCSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD cbFrame;
		/*008*/
		PDB_DWORD cbPad;
		/*00C*/
		PDB_DWORD offPad;
		/*010*/
		PDB_DWORD cbSaveRegs;
		/*014*/
		PDB_DWORD offExHdlr;
		/*018*/
		PDB_WORD sectExHdlr;
		struct
		{
				/*01A.0*/
				PDB_DWORD fHasAlloca :1;
				/*01A.1*/
				PDB_DWORD fHasSetJmp :1;
				/*01A.2*/
				PDB_DWORD fHasLongJmp :1;
				/*01A.3*/
				PDB_DWORD fHasInlAsm :1;
				/*01A.4*/
				PDB_DWORD fHasEH :1;
				/*01A.5*/
				PDB_DWORD fInlSpec :1;
				/*01A.6*/
				PDB_DWORD fHasSEH :1;
				/*01A.7*/
				PDB_DWORD pad :25;
		} flags;
		/*01E*/} FRAMEPROCSYM, *PFRAMEPROCSYM, **PPFRAMEPROCSYM;

#define FRAMEPROCSYM_ sizeof (FRAMEPROCSYM)

// -----------------------------------------------------------------

typedef struct _FRAMERELSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_LONG off;
		/*008*/
		PDB_DWORD typind;
		/*00C*/
		CV_lvar_attr attr;
		/*014*/
		PDB_BYTE name[1];
		/*015*/} FRAMERELSYM, *PFRAMERELSYM, **PPFRAMERELSYM;

#define FRAMERELSYM_ sizeof (FRAMERELSYM)

// -----------------------------------------------------------------

typedef struct _LABELSYM16
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_WORD off;
		/*006*/
		PDB_WORD seg;
		/*008*/
		CV_PROCFLAGS flags;
		/*009*/
		PDB_BYTE name[1];
		/*00A*/} LABELSYM16, *PLABELSYM16, **PPLABELSYM16;

#define LABELSYM16_ sizeof (LABELSYM16)

// -----------------------------------------------------------------

typedef struct _LABELSYM32
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD off;
		/*008*/
		PDB_WORD seg;
		/*00A*/
		CV_PROCFLAGS flags;
		/*00B*/
		PDB_BYTE name[1];
		/*00C*/} LABELSYM32, *PLABELSYM32, **PPLABELSYM32;

#define LABELSYM32_ sizeof (LABELSYM32)

// -----------------------------------------------------------------

typedef struct _MANPROCSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/
		PDB_DWORD pNext;
		/*010*/
		PDB_DWORD len;
		/*014*/
		PDB_DWORD DbgStart;
		/*018*/
		PDB_DWORD DbgEnd;
		/*01C*/
		PDB_DWORD token;
		/*020*/
		PDB_DWORD off;
		/*024*/
		PDB_WORD seg;
		/*026*/
		CV_PROCFLAGS flags;
		/*027*/
		PDB_WORD retReg;
		/*029*/
		PDB_BYTE name[1];
		/*02A*/} MANPROCSYM, *PMANPROCSYM, **PPMANPROCSYM;

#define MANPROCSYM_ sizeof (MANPROCSYM)

// -----------------------------------------------------------------

typedef struct _MANPROCSYMMIPS
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/
		PDB_DWORD pNext;
		/*010*/
		PDB_DWORD len;
		/*014*/
		PDB_DWORD DbgStart;
		/*018*/
		PDB_DWORD DbgEnd;
		/*01C*/
		PDB_DWORD regSave;
		/*020*/
		PDB_DWORD fpSave;
		/*024*/
		PDB_DWORD intOff;
		/*028*/
		PDB_DWORD fpOff;
		/*02C*/
		PDB_DWORD token;
		/*030*/
		PDB_DWORD off;
		/*034*/
		PDB_WORD seg;
		/*036*/
		PDB_BYTE retReg;
		/*037*/
		PDB_BYTE frameReg;
		/*038*/
		PDB_BYTE name[1];
		/*039*/} MANPROCSYMMIPS, *PMANPROCSYMMIPS, **PPMANPROCSYMMIPS;

#define MANPROCSYMMIPS_ sizeof (MANPROCSYMMIPS)

// -----------------------------------------------------------------

typedef struct _MANTYPREF
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD typind;
		/*008*/} MANTYPREF, *PMANTYPREF, **PPMANTYPREF;

#define MANTYPREF_ sizeof (MANTYPREF)

// -----------------------------------------------------------------

typedef struct _MANYREGSYM_16t
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_WORD typind;
		/*006*/
		PDB_BYTE count;
		/*007*/
		PDB_BYTE reg[1];
		/*008*/} MANYREGSYM_16t, *PMANYREGSYM_16t, **PPMANYREGSYM_16t;

#define MANYREGSYM_16t_ sizeof (MANYREGSYM_16t)

// -----------------------------------------------------------------

typedef struct _MANYREGSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD typind;
		/*008*/
		PDB_BYTE count;
		/*009*/
		PDB_BYTE reg[1];
		/*00A*/} MANYREGSYM, *PMANYREGSYM, **PPMANYREGSYM;

#define MANYREGSYM_ sizeof (MANYREGSYM)

// -----------------------------------------------------------------

typedef struct _MANYREGSYM2
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD typind;
		/*008*/
		PDB_WORD count;
		/*00A*/
		PDB_WORD reg[1];
		/*00C*/} MANYREGSYM2, *PMANYREGSYM2, **PPMANYREGSYM2;

#define MANYREGSYM2_ sizeof (MANYREGSYM2)

// -----------------------------------------------------------------

typedef struct _OBJNAMESYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD signature;
		/*008*/
		PDB_BYTE name[1];
		/*009*/} OBJNAMESYM, *POBJNAMESYM, **PPOBJNAMESYM;

#define OBJNAMESYM_ sizeof (OBJNAMESYM)

// -----------------------------------------------------------------

typedef struct _OEMSYMBOL
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_BYTE idOem[16];
		/*014*/
		PDB_DWORD typind;
		/*018*/
		PDB_DWORD rgl[];
		/*018*/} OEMSYMBOL, *POEMSYMBOL, **PPOEMSYMBOL;

#define OEMSYMBOL_ sizeof (OEMSYMBOL)

// -----------------------------------------------------------------

typedef struct _PROCSYM16
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/
		PDB_DWORD pNext;
		/*010*/
		PDB_WORD len;
		/*012*/
		PDB_WORD DbgStart;
		/*014*/
		PDB_WORD DbgEnd;
		/*016*/
		PDB_WORD off;
		/*018*/
		PDB_WORD seg;
		/*01A*/
		PDB_WORD typind;
		/*01C*/
		CV_PROCFLAGS flags;
		/*01D*/
		PDB_BYTE name[1];
		/*01E*/} PROCSYM16, *PPROCSYM16, **PPPROCSYM16;

#define PROCSYM16_ sizeof (PROCSYM16)

// -----------------------------------------------------------------

typedef struct _PROCSYM32
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/
		PDB_DWORD pNext;
		/*010*/
		PDB_DWORD len;
		/*014*/
		PDB_DWORD DbgStart;
		/*018*/
		PDB_DWORD DbgEnd;
		/*01C*/
		PDB_DWORD typind;
		/*020*/
		PDB_DWORD off;
		/*024*/
		PDB_WORD seg;
		/*026*/
		CV_PROCFLAGS flags;
		/*027*/
		PDB_BYTE name[1];
		/*028*/} PROCSYM32, *PPROCSYM32, **PPPROCSYM32;

#define PROCSYM32_ sizeof (PROCSYM32)

// -----------------------------------------------------------------

typedef struct _PROCSYM32_16t
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/
		PDB_DWORD pNext;
		/*010*/
		PDB_DWORD len;
		/*014*/
		PDB_DWORD DbgStart;
		/*018*/
		PDB_DWORD DbgEnd;
		/*01C*/
		PDB_DWORD off;
		/*020*/
		PDB_WORD seg;
		/*022*/
		PDB_WORD typind;
		/*024*/
		CV_PROCFLAGS flags;
		/*025*/
		PDB_BYTE name[1];
		/*026*/} PROCSYM32_16t, *PPROCSYM32_16t, **PPPROCSYM32_16t;

#define PROCSYM32_16t_ sizeof (PROCSYM32_16t)

// -----------------------------------------------------------------

typedef struct _PROCSYMIA64
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/
		PDB_DWORD pNext;
		/*010*/
		PDB_DWORD len;
		/*014*/
		PDB_DWORD DbgStart;
		/*018*/
		PDB_DWORD DbgEnd;
		/*01C*/
		PDB_DWORD typind;
		/*020*/
		PDB_DWORD off;
		/*024*/
		PDB_WORD seg;
		/*026*/
		PDB_WORD retReg;
		/*028*/
		CV_PROCFLAGS flags;
		/*029*/
		PDB_BYTE name[1];
		/*02A*/} PROCSYMIA64, *PPROCSYMIA64, **PPPROCSYMIA64;

#define PROCSYMIA64_ sizeof (PROCSYMIA64)

// -----------------------------------------------------------------

typedef struct _PROCSYMMIPS
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/
		PDB_DWORD pNext;
		/*010*/
		PDB_DWORD len;
		/*014*/
		PDB_DWORD DbgStart;
		/*018*/
		PDB_DWORD DbgEnd;
		/*01C*/
		PDB_DWORD regSave;
		/*020*/
		PDB_DWORD fpSave;
		/*024*/
		PDB_DWORD intOff;
		/*028*/
		PDB_DWORD fpOff;
		/*02C*/
		PDB_DWORD typinf;
		/*030*/
		PDB_DWORD off;
		/*034*/
		PDB_WORD seg;
		/*036*/
		PDB_BYTE retReg;
		/*037*/
		PDB_BYTE frameReg;
		/*038*/
		PDB_BYTE name[1];
		/*039*/} PROCSYMMIPS, *PPROCSYMMIPS, **PPPROCSYMMIPS;

#define PROCSYMMIPS_ sizeof (PROCSYMMIPS)

// -----------------------------------------------------------------

typedef struct _PROCSYMMIPS_16t
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/
		PDB_DWORD pNext;
		/*010*/
		PDB_DWORD len;
		/*014*/
		PDB_DWORD DbgStart;
		/*018*/
		PDB_DWORD DbgEnd;
		/*01C*/
		PDB_DWORD regSave;
		/*020*/
		PDB_DWORD fpSave;
		/*024*/
		PDB_DWORD intOff;
		/*028*/
		PDB_DWORD fpOff;
		/*02C*/
		PDB_DWORD off;
		/*030*/
		PDB_WORD seg;
		/*032*/
		PDB_WORD typind;
		/*034*/
		PDB_BYTE retReg;
		/*035*/
		PDB_BYTE frameReg;
		/*036*/
		PDB_BYTE name[1];
		/*037*/} PROCSYMMIPS_16t, *PPROCSYMMIPS_16t, **PPPROCSYMMIPS_16t;

#define PROCSYMMIPS_16t_ sizeof (PROCSYMMIPS_16t)

// -----------------------------------------------------------------

typedef struct _PUBSYM32
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		CV_PUBSYMFLAGS pubsymflags;
		/*008*/
		PDB_DWORD off;
		/*00C*/
		PDB_WORD seg;
		/*00E*/
		PDB_BYTE name[1];
		/*00F*/} PUBSYM32, *PPUBSYM32, **PPPUBSYM32;

#define PUBSYM32_ sizeof (PUBSYM32)

// -----------------------------------------------------------------

typedef struct _REFSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD sumName;
		/*008*/
		PDB_DWORD ibSym;
		/*00C*/
		PDB_WORD imod;
		/*00E*/
		PDB_WORD usFill;
		/*010*/} REFSYM, *PREFSYM, **PPREFSYM;

#define REFSYM_ sizeof (REFSYM)

// -----------------------------------------------------------------

typedef struct _REFSYM2
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD sumName;
		/*008*/
		PDB_DWORD ibSym;
		/*00C*/
		PDB_WORD imod;
		/*00E*/
		PDB_BYTE name[1];
		/*00F*/} REFSYM2, *PREFSYM2, **PPREFSYM2;

#define REFSYM2_ sizeof (REFSYM2)

// -----------------------------------------------------------------

typedef struct _REGREL16
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_WORD off;
		/*006*/
		PDB_WORD reg;
		/*008*/
		PDB_WORD typind;
		/*00A*/
		PDB_BYTE name[1];
		/*00B*/} REGREL16, *PREGREL16, **PPREGREL16;

#define REGREL16_ sizeof (REGREL16)

// -----------------------------------------------------------------

typedef struct _REGREL32_16t
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD off;
		/*008*/
		PDB_WORD reg;
		/*00A*/
		PDB_WORD typind;
		/*00C*/
		PDB_BYTE name[1];
		/*00D*/} REGREL32_16t, *PREGREL32_16t, **PPREGREL32_16t;

#define REGREL32_16t_ sizeof (REGREL32_16t)

// -----------------------------------------------------------------

typedef struct _REGREL32
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_LONG off;  // offset is signed
		/*008*/
		PDB_DWORD typind;
		/*00C*/
		PDB_WORD reg;
		/*00E*/
		PDB_BYTE name[1];
		/*00F*/} REGREL32, *PREGREL32, **PPREGREL32;

#define REGREL32_ sizeof (REGREL32)

// -----------------------------------------------------------------

typedef struct _REGSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD typind;
		/*008*/
		PDB_WORD reg;
		/*00A*/
		PDB_BYTE name[1];
		/*00B*/} REGSYM, *PREGSYM, **PPREGSYM;

#define REGSYM_ sizeof (REGSYM)

// -----------------------------------------------------------------

typedef struct _REGSYM_16t
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_WORD typind;
		/*006*/
		PDB_WORD reg;
		/*008*/
		PDB_BYTE name[1];
		/*009*/} REGSYM_16t, *PREGSYM_16t, **PPREGSYM_16t;

#define REGSYM_16t_ sizeof (REGSYM_16t)

// -----------------------------------------------------------------

typedef struct _RETURNSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		CV_GENERIC_FLAG flags;
		/*006*/
		PDB_BYTE style;
		/*007*/} RETURNSYM, *PRETURNSYM, **PPRETURNSYM;

#define RETURNSYM_ sizeof (RETURNSYM)

// -----------------------------------------------------------------

typedef struct _SEARCHSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD startsym;
		/*008*/
		PDB_WORD seg;
		/*00A*/} SEARCHSYM, *PSEARCHSYM, **PPSEARCHSYM;

#define SEARCHSYM_ sizeof (SEARCHSYM)

// -----------------------------------------------------------------

typedef struct _SLINK32
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD framesize;
		/*008*/
		PDB_LONG off;
		/*00C*/
		PDB_WORD reg;
		/*00E*/} SLINK32, *PSLINK32, **PPSLINK32;

#define SLINK32_ sizeof (SLINK32)

// -----------------------------------------------------------------

typedef struct _SLOTSYM32
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD iSlot;
		/*008*/
		PDB_DWORD typind;
		/*00C*/
		PDB_BYTE name[1];
		/*00D*/} SLOTSYM32, *PSLOTSYM32, **PPSLOTSYM32;

#define SLOTSYM32_ sizeof (SLOTSYM32)

// -----------------------------------------------------------------

typedef struct _SYMTYPE
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_BYTE data[];
		/*004*/} SYMTYPE, *PSYMTYPE, **PPSYMTYPE;

#define SYMTYPE_ sizeof (SYMTYPE)

// -----------------------------------------------------------------

typedef struct _THREADSYM32_16t
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD off;
		/*008*/
		PDB_WORD seg;
		/*00A*/
		PDB_WORD typind;
		/*00C*/
		PDB_BYTE name[1];
		/*00D*/} THREADSYM32_16t, *PTHREADSYM32_16t, **PPTHREADSYM32_16t;

#define THREADSYM32_16t_ sizeof (THREADSYM32_16t)

// -----------------------------------------------------------------

typedef struct _THUNKSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/
		PDB_DWORD pNext;
		/*010*/} THUNKSYM, *PTHUNKSYM, **PPTHUNKSYM;

#define THUNKSYM_ sizeof (THUNKSYM)

// -----------------------------------------------------------------

typedef struct _THUNKSYM16
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/
		PDB_DWORD pNext;
		/*010*/
		PDB_WORD off;
		/*012*/
		PDB_WORD seg;
		/*014*/
		PDB_WORD len;
		/*016*/
		PDB_BYTE ord;
		/*017*/
		PDB_BYTE name[1];
		/*018*/
		PDB_BYTE variant[];
		/*018*/} THUNKSYM16, *PTHUNKSYM16, **PPTHUNKSYM16;

#define THUNKSYM16_ sizeof (THUNKSYM16)

// -----------------------------------------------------------------

typedef struct _THUNKSYM32
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/
		PDB_DWORD pNext;
		/*010*/
		PDB_DWORD off;
		/*014*/
		PDB_WORD seg;
		/*016*/
		PDB_WORD len;
		/*018*/
		PDB_BYTE ord;
		/*019*/
		PDB_BYTE name[1];
		/*01A*/
		PDB_BYTE variant[];
		/*01A*/} THUNKSYM32, *PTHUNKSYM32, **PPTHUNKSYM32;

#define THUNKSYM32_ sizeof (THUNKSYM32)

// -----------------------------------------------------------------

typedef struct _TRAMPOLINESYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_WORD trampType;
		/*006*/
		PDB_WORD cbThunk;
		/*008*/
		PDB_DWORD offThunk;
		/*00C*/
		PDB_DWORD offTarget;
		/*010*/
		PDB_WORD sectThunk;
		/*012*/
		PDB_WORD sectTarget;
		/*014*/} TRAMPOLINESYM, *PTRAMPOLINESYM, **PPTRAMPOLINESYM;

#define TRAMPOLINESYM_ sizeof (TRAMPOLINESYM)

// -----------------------------------------------------------------

typedef struct _UDTSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD typind;
		/*008*/
		PDB_BYTE name[1];
		/*009*/} UDTSYM, *PUDTSYM, **PPUDTSYM;

#define UDTSYM_ sizeof (UDTSYM)

// -----------------------------------------------------------------

typedef struct _UDTSYM_16t
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_WORD typind;
		/*006*/
		PDB_BYTE name[1];
		/*007*/} UDTSYM_16t, *PUDTSYM_16t, **PPUDTSYM_16t;

#define UDTSYM_16t_ sizeof (UDTSYM_16t)

// -----------------------------------------------------------------

typedef struct _UNAMESPACE
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_BYTE name[1];
		/*005*/} UNAMESPACE, *PUNAMESPACE, **PPUNAMESPACE;

#define UNAMESPACE_ sizeof (UNAMESPACE)

// -----------------------------------------------------------------

typedef struct _VPATHSYM16
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_WORD off;
		/*006*/
		PDB_WORD seg;
		/*008*/
		PDB_WORD root;
		/*00A*/
		PDB_WORD path;
		/*00C*/} VPATHSYM16, *PVPATHSYM16, **PPVPATHSYM16;

#define VPATHSYM16_ sizeof (VPATHSYM16)

// -----------------------------------------------------------------

typedef struct _VPATHSYM32
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD root;
		/*008*/
		PDB_DWORD path;
		/*00C*/
		PDB_DWORD off;
		/*010*/
		PDB_WORD seg;
		/*012*/} VPATHSYM32, *PVPATHSYM32, **PPVPATHSYM32;

#define VPATHSYM32_ sizeof (VPATHSYM32)

// -----------------------------------------------------------------

typedef struct _VPATHSYM32_16t
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD off;
		/*008*/
		PDB_WORD seg;
		/*00A*/
		PDB_WORD root;
		/*00C*/
		PDB_WORD path;
		/*00E*/} VPATHSYM32_16t, *PVPATHSYM32_16t, **PPVPATHSYM32_16t;

#define VPATHSYM32_16t_ sizeof (VPATHSYM32_16t)

// -----------------------------------------------------------------

typedef struct _WITHSYM16
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/
		PDB_WORD len;
		/*00E*/
		PDB_WORD off;
		/*010*/
		PDB_WORD seg;
		/*012*/
		PDB_BYTE expr[1];
		/*013*/} WITHSYM16, *PWITHSYM16, **PPWITHSYM16;

#define WITHSYM16_ sizeof (WITHSYM16)

// -----------------------------------------------------------------

typedef struct _WITHSYM32
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD pParent;
		/*008*/
		PDB_DWORD pEnd;
		/*00C*/
		PDB_DWORD len;
		/*010*/
		PDB_DWORD off;
		/*014*/
		PDB_WORD seg;
		/*016*/
		PDB_BYTE expr[1];
		/*017*/} WITHSYM32, *PWITHSYM32, **PPWITHSYM32;

#define WITHSYM32_ sizeof (WITHSYM32)

// -----------------------------------------------------------------

typedef struct _OMAP_DATA
{
		/*000*/
		PDB_DWORD rva;  // relative virtual address
		/*004*/
		PDB_DWORD rvaTo;  // converted relative virtual address
		/*008*/
} OMAP_DATA, *POMAP_DATA, **PPOMAP_DATA;

#define OMAP_DATA_ sizeof (OMAP_DATA)

// -----------------------------------------------------------------

typedef union _SYM
{
		ALIGNSYM Sym;
		ANNOTATIONSYM Annotation;
		ATTRMANYREGSYM AttrManyReg;
		ATTRMANYREGSYM2 AttrManyReg2;
		ATTRREGREL AttrRegRel;
		ATTRREGSYM AttrReg;
		ATTRSLOTSYM AttrSlot;
		BLOCKSYM Block;
		BLOCKSYM16 Block16;
		BLOCKSYM32 Block32;
		BPRELSYM16 BpRel16;
		BPRELSYM32 BpRel32;
		BPRELSYM32_16t BpRel32_16t;
		CEXMSYM16 Cexm16;
		CEXMSYM32 Cexm32;
		CFLAGSYM CFlag;
		COMPILESYM Compile;
		CONSTSYM Const;
		CONSTSYM_16t Const_16t;
		DATASYM16 Data16;
		DATASYM32 Data32;
		ENTRYTHISSYM EntryThis;
		FRAMEPROCSYM FrameProc;
		FRAMERELSYM FrameRel;
		LABELSYM16 Label16;
		LABELSYM32 Label32;
		MANPROCSYM ManProc;
		MANPROCSYMMIPS ManProcMips;
		MANTYPREF ManTypRef;
		MANYREGSYM_16t ManyReg_16t;
		MANYREGSYM ManyReg;
		MANYREGSYM2 ManyReg2;
		OBJNAMESYM ObjName;
		OEMSYMBOL Oem;
		PROCSYM16 Proc16;
		PROCSYM32 Proc32;
		PROCSYM32_16t Proc32_16t;
		PROCSYMIA64 ProcIA64;
		PROCSYMMIPS ProcMips;
		PROCSYMMIPS_16t ProcMips_16t;
		PUBSYM32 Pub32;
		REFSYM Ref;
		REFSYM2 Ref2;
		REGREL16 RegRel16;
		REGREL32_16t RegRel32_16t;
		REGREL32 RegRel32;
		REGSYM Reg;
		REGSYM_16t Reg_16t;
		RETURNSYM Return;
		SEARCHSYM Search;
		SLINK32 Slink32;
		SLOTSYM32 Slot32;
		SYMTYPE SymType;
		THREADSYM32_16t Thread_16t;
		THUNKSYM Thunk;
		THUNKSYM16 Thunk16;
		THUNKSYM32 Thunk32;
		TRAMPOLINESYM Trampoline;
		UDTSYM Udt;
		UDTSYM_16t Udt_16t;
		UNAMESPACE UNameSpace;
		VPATHSYM16 VPath16;
		VPATHSYM32 VPath32;
		VPATHSYM32_16t VPath32_16t;
		WITHSYM16 With16;
		WITHSYM32 With32;
} SYM, *PSYM;

// =================================================================
// SYMBOLS WITH NOT FULLY KNOWN STRUCTURE
// =================================================================

typedef struct _MANSLOTSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD unknown1;
		/*008*/
		PDB_DWORD unknown2;
		/*00C*/
		PDB_DWORD unknown3;
		/*010*/
		PDB_DWORD unknown4;
		/*014*/
		PDB_BYTE name[1];
		/*015*/} MANSLOTSYM;

typedef struct _SECTIONSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_WORD seg;
		/*006*/
		PDB_WORD unknown1;
		/*008*/
		PDB_DWORD off;
		/*00C*/
		PDB_DWORD len;
		/*010*/
		PDB_DWORD unknown2;
		/*014*/
		PDB_BYTE name[1];
		/*015*/} SECTIONSYM;

typedef struct _COFFGROUPSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD len;
		/*008*/
		PDB_DWORD unknown1;
		/*00C*/
		PDB_DWORD off;
		/*010*/
		PDB_WORD seg;
		/*012*/
		PDB_BYTE name[1];
		/*013*/} COFFGROUPSYM;

typedef struct _EXPORTSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_WORD unknown1;
		/*006*/
		PDB_WORD unknown2;
		/*008*/
		PDB_BYTE name[1];
		/*009*/} EXPORTSYM;

typedef struct _CALLSITEINFOSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD unknown1;
		/*008*/
		PDB_DWORD unknown2;
		/*00C*/
		PDB_DWORD unknown3;
		/*00D*/} CALLSITEINFOSYM;

typedef struct _FRAMECOOKIESYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD unknown1;
		/*008*/
		PDB_DWORD unknown2;
		/*009*/} FRAMECOOKIESYM;

typedef struct _COMPILE3SYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD unknown1;
		/*008*/
		PDB_WORD unknown2;
		/*00A*/
		PDB_DWORD unknown3;
		/*00E*/
		PDB_DWORD unknown4;
		/*012*/
		PDB_DWORD unknown5;
		/*016*/
		PDB_DWORD unknown6;
		/*01A*/
		PDB_BYTE name[1];
		/*01B*/} COMPILE3SYM;

typedef struct _LOCALSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD unknown1;
		/*008*/
		PDB_WORD unknown2;
		/*00A*/
		PDB_BYTE name[1];
		/*00B*/} LOCALSYM;

typedef struct _DEFRANGE_REGISTERSYM
{
		/*000*/
		PDB_WORD reclen;  // record length
		/*002*/
		PDB_WORD rectyp;  // record type
		/*004*/
		PDB_DWORD unknown1;
		/*008*/
		PDB_DWORD unknown2;
		/*00C*/
		PDB_WORD unknown3;
		/*00E*/
		PDB_WORD unknown4;
		/*010*/} DEFRANGE_REGISTERSYM;

// =================================================================
// BIG SYMBOL RECORDS
// =================================================================

typedef struct _LineInfoRecord
{
		/*000*/
		PDB_DWORD off;
		/*004*/
		PDB_WORD line;
		/*006*/
		PDB_WORD unknown1;  // 0x80
		/*008*/
} LineInfoRecord;

typedef struct _LineInfoHeader
{
		/*000*/
		PDB_DWORD rectyp;  // 0xF2
		/*004*/
		PDB_DWORD reclen;
		/*008*/
		PDB_DWORD off;
		/*00C*/
		PDB_DWORD seg;
		/*010*/
		PDB_DWORD len;
		/*014*/
		PDB_DWORD unknown1;
		/*018*/
		PDB_DWORD num_records;  // Number of line info records
		/*01C*/
		PDB_DWORD unknown2;
		/*020*/
		LineInfoRecord records[];
		/*020*/} LineInfoHeader;

#pragma pack ()

// =================================================================
// END OF FILE
// =================================================================

} // namespace pdbparser
} // namespace retdec

#endif
