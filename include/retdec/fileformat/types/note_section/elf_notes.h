/**
 * @file include/retdec/fileformat/types/note_section/elf_note.cpp
 * @brief Class for ELF note section (segment).
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_NOTE_SECTION_ELF_NOTE_H
#define RETDEC_FILEFORMAT_TYPES_NOTE_SECTION_ELF_NOTE_H

#include <string>
#include <vector>

#include "retdec/fileformat/types/sec_seg/sec_seg.h"

namespace retdec {
namespace fileformat {

/**
 * Class for one ELF note section or segment entry
 */
class ElfNote
{
    private:
        std::size_t type;   ///< owner specific type
        std::string name;   ///< interpreted name (owner)

    public:
        /// Setters
        /// @{
        void setType(const std::size_t& type);
        void setName(const std::string& name);
        /// @}

        /// Getters
        /// @{
        std::string getName() const;
        std::size_t getType() const;
        /// @}

        /// Query methods
        /// @{
        bool isEmptyNote() const;
        /// @}
};

/**
 * Class describing one ELF note section or segment
 */
class ElfNotes
{
    private:
        const SecSeg* secSeg;       ///< associated section or segment
        std::vector<ElfNote> notes; ///< notes in segment or section

    public:
        /// Ctors and dtors
        /// @{
        ElfNotes(const SecSeg* assocSecSeg);
        ~ElfNotes();
        /// @}

        /// Notes methods
        /// @{
        void addNote(const ElfNote& note);
        std::vector<ElfNote> getNotes() const;
        /// @}

        /// Getters
        /// @{
        std::string getSectionName() const;
        std::size_t getSecSegOffset() const;
        std::size_t getSecSegLength() const;
        /// @}

        /// Query methods
        /// @{
        bool isNamedSection() const;
        /// @}
};



} // namespace fileformat
} // namespace retdec

#endif
