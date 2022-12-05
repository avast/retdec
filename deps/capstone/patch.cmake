
set(file "arch/PowerPC/PPCInstPrinter.c")
set(full_path "${capstone_path}/${file}")

file(READ "${full_path}" content)

string(REPLACE
    "cr = getBICR(MCOperand_getReg(MCInst_getOperand(MI, 1)));\n\t\t\tif (cr > PPC_CR0) {"
    "cr = getBICR(MCOperand_getReg(MCInst_getOperand(MI, 1)));\n// RetDec fix\n\t\t\tif (cr >= PPC_CR0) {"
    new_content
    "${content}"
)

string(REPLACE
    "static void printS16ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)\n{\n\tif (MCOperand_isImm(MCInst_getOperand(MI, OpNo))) {\n\t\tunsigned short Imm = (unsigned short)MCOperand_getImm(MCInst_getOperand(MI, OpNo));\n        if (Imm > HEX_THRESHOLD)\n            SStream_concat(O, \"0x%x\", Imm);\n        else\n            SStream_concat(O, \"%u\", Imm);\n"
    "static void printS16ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)\n{\n\tif (MCOperand_isImm(MCInst_getOperand(MI, OpNo))) {\n// RetDec fix\n\t\tshort Imm = (short)MCOperand_getImm(MCInst_getOperand(MI, OpNo));\n\t\tSStream_concat(O, \"%d\", Imm);\n"
    new_content2
    "${new_content}"
)

if("${new_content2}" STREQUAL "${content}")
    message(STATUS "-- Patching: ${full_path} skipped")
else()
    message(STATUS "-- Patching: ${full_path} patched")
    file(WRITE "${full_path}" "${new_content2}")
endif()
