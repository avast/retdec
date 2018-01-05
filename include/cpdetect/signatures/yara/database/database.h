/**
 * @file include/cpdetec/signatures/yara/database/database.h
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_SIGNATURES_YARA_DATABASE_DATABASE_H
#define CPDETECT_SIGNATURES_YARA_DATABASE_DATABASE_H

#include <vector>

namespace cpdetect {

const std::vector<const char*>* getArmElfDatabase();
const std::vector<const char*>* getMipsElfDatabase();
const std::vector<const char*>* getPowerPcElfDatabase();
const std::vector<const char*>* getX86ElfDatabase();
const std::vector<const char*>* getArmMachODatabase();
const std::vector<const char*>* getMipsMachODatabase();
const std::vector<const char*>* getPowerPcMachODatabase();
const std::vector<const char*>* getX86MachODatabase();
const std::vector<const char*>* getFatMachoDatabase();
const std::vector<const char*>* getArmPeDatabase();
const std::vector<const char*>* getMipsPeDatabase();
const std::vector<const char*>* getPowerPcPeDatabase();
const std::vector<const char*>* getX86PeDatabase();
const std::vector<const char*>* getArmDatabase();
const std::vector<const char*>* getMipsDatabase();
const std::vector<const char*>* getPowerPcDatabase();
const std::vector<const char*>* getX86Database();

} // namespace cpdetect

#endif
