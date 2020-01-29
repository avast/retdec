
set(file "arch/PowerPC/PPCInstPrinter.c")
set(full_path "${capstone_path}/${file}")

file(READ "${full_path}" content)

string(REPLACE
    "cr = getBICR(MCOperand_getReg(MCInst_getOperand(MI, 1)));\n\t\t\tif (cr > PPC_CR0) {"
    "cr = getBICR(MCOperand_getReg(MCInst_getOperand(MI, 1)));\n// RetDec fix\n\t\t\tif (cr >= PPC_CR0) {"
    new_content
    "${content}"
)

if("${new_content}" STREQUAL "${content}")
    message("-- Patching: ${full_path} skipped")
else()
    message("-- Patching: ${full_path} patched")
    file(WRITE "${full_path}" "${new_content}")
endif()
