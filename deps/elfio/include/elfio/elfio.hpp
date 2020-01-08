/*
Copyright (C) 2001-2015 by Serge Lamikhov-Center

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef ELFIO_HPP
#define ELFIO_HPP

#ifdef _MSC_VER
#pragma warning ( push )
#pragma warning(disable:4996)
#pragma warning(disable:4355)
#pragma warning(disable:4244)
#endif

#include <string>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <vector>
#include <deque>
#include <iterator>
#include <typeinfo>

#include <elfio/elf_types.hpp>
#include <elfio/elfio_utils.hpp>
#include <elfio/elfio_header.hpp>
#include <elfio/elfio_section.hpp>
#include <elfio/elfio_segment.hpp>
#include <elfio/elfio_strings.hpp>

#define ELFIO_HEADER_ACCESS_GET( TYPE, FNAME ) \
TYPE                                           \
get_##FNAME() const                            \
{                                              \
    return header->get_##FNAME();              \
}

#define ELFIO_HEADER_ACCESS_GET_SET( TYPE, FNAME ) \
TYPE                                               \
get_##FNAME() const                                \
{                                                  \
    return header->get_##FNAME();                  \
}                                                  \
void                                               \
set_##FNAME( TYPE val )                            \
{                                                  \
    header->set_##FNAME( val );                    \
}                                                  \

namespace ELFIO {

//------------------------------------------------------------------------------
class elfio
{
  public:
//------------------------------------------------------------------------------
    elfio() : sections( this ), segments( this )
    {
        real_file_length = 0;
        header           = 0;
        current_file_pos = 0;
        create( ELFCLASS32, ELFDATA2LSB );
    }

//------------------------------------------------------------------------------
    ~elfio()
    {
        clean();
    }

//------------------------------------------------------------------------------
    void create( unsigned char file_class, unsigned char encoding )
    {
        clean();
        convertor.setup( encoding );
        header = create_header( file_class, encoding );
        create_mandatory_sections();
    }

//------------------------------------------------------------------------------
    std::istream* get_istream()
    {
        return iStream;
    }

//------------------------------------------------------------------------------
    bool load( const std::string& file_name )
    {
        ifStream.open( file_name.c_str(), std::ios::in | std::ios::binary | std::ios::ate );
        if ( !ifStream.is_open() ) {
            return false;
        }

        return load(ifStream);
    }

//------------------------------------------------------------------------------
    bool load( std::istream &stream )
    {
        if ( !stream ) {
            return false;
        }

        iStream = &stream;
        stream.seekg( 0, std::ios::end );
        real_file_length = stream.tellg();
        clean();

        unsigned char e_ident[EI_NIDENT];

        // Read ELF file signature
        stream.seekg( 0 );
        stream.read( reinterpret_cast<char*>( &e_ident ), sizeof( e_ident ) );

        // Is it ELF file?
        if ( stream.gcount() != sizeof( e_ident ) ||
             e_ident[EI_MAG0] != ELFMAG0    ||
             e_ident[EI_MAG1] != ELFMAG1    ||
             e_ident[EI_MAG2] != ELFMAG2    ||
             e_ident[EI_MAG3] != ELFMAG3 ) {
            return false;
        }

        std::vector<unsigned char> file_classes;
        if ( ( e_ident[EI_CLASS] != ELFCLASS64 ) &&
             ( e_ident[EI_CLASS] != ELFCLASS32 )) {
            file_classes.push_back( ELFCLASS64 );
            file_classes.push_back( ELFCLASS32 );
        }
        else {
            file_classes.push_back( e_ident[EI_CLASS] );
        }

        convertor.setup( e_ident[EI_DATA] );

        for ( const auto file_class : file_classes ) {
            header = create_header( file_class, e_ident[EI_DATA] );
            if ( 0 == header ) {
                continue;
            }
            if ( !header->load( stream ) ) {
                clean();
                continue;
            }
            if ( file_classes.size() > 1 ) {
                if ( ( file_class == ELFCLASS32 && !is_in_range( header->get_section_entry_size(), sizeof( Elf32_Shdr ), sizeof( Elf64_Shdr ) - 1)) ||
                     ( file_class == ELFCLASS64 && header->get_section_entry_size() < sizeof( Elf64_Shdr ))) {
                    clean();
                    continue;
                }
            }

            load_sections( stream );
            if ( stream.eof() ) {
                stream.clear();
                stream.seekg( 0 );
                if ( !stream.good() ) {
                    clean();
                    continue;
                }
            }
            load_segments( stream );
            return true;
        }

        return false;
    }

//------------------------------------------------------------------------------
    bool save( const std::string& file_name )
    {
        std::ofstream f( file_name.c_str(), std::ios::out | std::ios::binary );

        if ( !f ) {
            return false;
        }

        bool is_still_good = true;

        // Define layout specific header fields
        // The position of the segment table is fixed after the header.
        // The position of the section table is variable and needs to be fixed
        // before saving.
        header->set_segments_num( segments.size() );
        header->set_segments_offset( segments.size() ? header->get_header_size() : 0 );
        header->set_sections_num( sections.size() );
        header->set_sections_offset( 0 );

        // Layout the first section right after the segment table
        current_file_pos = header->get_header_size() +
                    header->get_segment_entry_size() * header->get_segments_num();

        is_still_good = layout_segments_and_their_sections();
        is_still_good = is_still_good && layout_sections_without_segments();
        is_still_good = is_still_good && layout_section_table();

        is_still_good = is_still_good && save_header( f );
        is_still_good = is_still_good && save_sections( f );
        is_still_good = is_still_good && save_segments( f );

        f.close();

        return is_still_good;
    }

//------------------------------------------------------------------------------
    // ELF header access functions
    ELFIO_HEADER_ACCESS_GET( unsigned char, class              );
    ELFIO_HEADER_ACCESS_GET( unsigned char, elf_version        );
    ELFIO_HEADER_ACCESS_GET( unsigned char, encoding           );
    ELFIO_HEADER_ACCESS_GET( Elf_Word,      version            );
    ELFIO_HEADER_ACCESS_GET( Elf_Half,      header_size        );
    ELFIO_HEADER_ACCESS_GET( Elf_Half,      section_entry_size );
    ELFIO_HEADER_ACCESS_GET( Elf_Half,      segment_entry_size );

    ELFIO_HEADER_ACCESS_GET_SET( unsigned char, os_abi                 );
    ELFIO_HEADER_ACCESS_GET_SET( unsigned char, abi_version            );
    ELFIO_HEADER_ACCESS_GET_SET( Elf_Half,      type                   );
    ELFIO_HEADER_ACCESS_GET_SET( Elf_Half,      machine                );
    ELFIO_HEADER_ACCESS_GET_SET( Elf_Word,      flags                  );
    ELFIO_HEADER_ACCESS_GET_SET( Elf64_Addr,    entry                  );
    ELFIO_HEADER_ACCESS_GET_SET( Elf64_Off,     sections_num           );
    ELFIO_HEADER_ACCESS_GET_SET( Elf64_Off,     sections_offset        );
    ELFIO_HEADER_ACCESS_GET_SET( Elf64_Off,     segments_num           );
    ELFIO_HEADER_ACCESS_GET_SET( Elf64_Off,     segments_offset        );
    ELFIO_HEADER_ACCESS_GET_SET( Elf_Half,      section_name_str_index );

//------------------------------------------------------------------------------
    const endianess_convertor& get_convertor() const
    {
        return convertor;
    }

//------------------------------------------------------------------------------
    Elf_Xword get_default_entry_size( Elf_Word section_type ) const
    {
        switch( section_type ) {
        case SHT_RELA:
            if ( header->get_class() == ELFCLASS64 ) {
                return sizeof( Elf64_Rela );
            }
            else {
                return sizeof( Elf32_Rela );
            }
        case SHT_REL:
            if ( header->get_class() == ELFCLASS64 ) {
                return sizeof( Elf64_Rel );
            }
            else {
                return sizeof( Elf32_Rel );
            }
        case SHT_SYMTAB:
            if ( header->get_class() == ELFCLASS64 ) {
                return sizeof( Elf64_Sym );
            }
            else {
                return sizeof( Elf32_Sym );
            }
        case SHT_DYNAMIC:
            if ( header->get_class() == ELFCLASS64 ) {
                return sizeof( Elf64_Dyn );
            }
            else {
                return sizeof( Elf32_Dyn );
            }
        default:
            return 0;
        }
    }

//------------------------------------------------------------------------------
  private:
//------------------------------------------------------------------------------
    void clean()
    {
        delete header;
        header = 0;

        std::vector<section*>::const_iterator it;
        for ( it = sections_.begin(); it != sections_.end(); ++it ) {
            delete *it;
        }
        sections_.clear();

        std::vector<segment*>::const_iterator it1;
        for ( it1 = segments_.begin(); it1 != segments_.end(); ++it1 ) {
            delete *it1;
        }
        segments_.clear();
    }

//------------------------------------------------------------------------------
    elf_header* create_header( unsigned char file_class, unsigned char encoding )
    {
        elf_header* new_header = 0;

        if ( file_class == ELFCLASS64 ) {
            new_header = new elf_header_impl< Elf64_Ehdr >( &convertor,
                                                            encoding );
        }
        else if ( file_class == ELFCLASS32 ) {
            new_header = new elf_header_impl< Elf32_Ehdr >( &convertor,
                                                            encoding );
        }
        else {
            return 0;
        }

        return new_header;
    }

//------------------------------------------------------------------------------
    section* create_section()
    {
        section*      new_section;
        unsigned char file_class = get_class();

        if ( file_class == ELFCLASS64 ) {
            new_section = new section_impl<Elf64_Shdr>( &convertor, real_file_length );
        }
        else if ( file_class == ELFCLASS32 ) {
            new_section = new section_impl<Elf32_Shdr>( &convertor, real_file_length );
        }
        else {
            return 0;
        }

        new_section->set_index( (Elf_Half)sections_.size() );
        sections_.push_back( new_section );

        return new_section;
    }

//------------------------------------------------------------------------------
    segment* create_segment()
    {
        segment*      new_segment;
        unsigned char file_class = header->get_class();

        if ( file_class == ELFCLASS64 ) {
            new_segment = new segment_impl<Elf64_Phdr>( &convertor, real_file_length );
        }
        else if ( file_class == ELFCLASS32 ) {
            new_segment = new segment_impl<Elf32_Phdr>( &convertor, real_file_length );
        }
        else {
            return 0;
        }

        new_segment->set_index( (Elf_Half)segments_.size() );
        segments_.push_back( new_segment );

        return new_segment;
    }

//------------------------------------------------------------------------------
    void create_mandatory_sections()
    {
        // Create null section without calling to 'add_section' as no string
        // section containing section names exists yet
        section* sec0 = create_section();
        sec0->set_index( 0 );
        sec0->set_name( "" );
        sec0->set_name_string_offset( 0 );

        set_section_name_str_index( 1 );
        section* shstrtab = sections.add( ".shstrtab" );
        shstrtab->set_type( SHT_STRTAB );
        shstrtab->set_addr_align( 1 );
    }

//------------------------------------------------------------------------------
    Elf_Half load_sections( std::istream& stream )
    {
        Elf_Half  entry_size = header->get_section_entry_size();
        Elf_Half  num        = header->get_sections_num();
        Elf64_Off offset     = header->get_sections_offset();

        if ( offset >= real_file_length ) {
            return 0;
        }

        for ( Elf_Half i = 0; i < num && offset + i * entry_size < real_file_length; ++i ) {
            section* sec = create_section();
            if ( 0 == sec ) {
                continue;
            }
            sec->load( stream, (std::streamoff)offset + i * entry_size );
            sec->set_index( i );
            // To mark that the section is not permitted to reassign address
            // during layout calculation
            sec->set_address( sec->get_address() );
        }

        Elf_Half shstrndx = get_section_name_str_index();

        if ( SHN_UNDEF != shstrndx ) {
            string_section_accessor str_reader( sections[shstrndx] );
            for ( Elf_Half i = 0; i < sections.size(); ++i ) {
                Elf_Word offset = sections[i]->get_name_string_offset();
                // DECOMPILER BEGIN
                sections[i]->set_name( str_reader.get_string( offset ) );
                // DECOMPILER END
            }
        }

        return sections_.size();
    }

//------------------------------------------------------------------------------
    bool load_segments( std::istream& stream )
    {
        Elf_Half  entry_size = header->get_segment_entry_size();
        Elf_Half  num        = header->get_segments_num();
        Elf64_Off offset     = header->get_segments_offset();

        if ( offset >= real_file_length ) {
            return false;
        }

        for ( Elf_Half i = 0; i < num && offset + i * entry_size < real_file_length; ++i ) {
            segment* seg;
            unsigned char file_class = header->get_class();

            if ( file_class == ELFCLASS64 ) {
                seg = new segment_impl<Elf64_Phdr>( &convertor, real_file_length );
            }
            else if ( file_class == ELFCLASS32 ) {
                seg = new segment_impl<Elf32_Phdr>( &convertor, real_file_length );
            }
            else {
                return false;
            }

            seg->load( stream, (std::streamoff)offset + i * entry_size );
            seg->set_index( i );

            // Add sections to the segments (similar to readelfs algorithm)
            Elf64_Off segBaseOffset = seg->get_offset();
            Elf64_Off segEndOffset  = segBaseOffset + seg->get_file_size();
            Elf64_Off segVBaseAddr = seg->get_virtual_address();
            Elf64_Off segVEndAddr  = segVBaseAddr + seg->get_memory_size();
            for( Elf_Half j = 0; j < sections.size(); ++j ) {
                const section* psec = sections[j];

                // SHF_ALLOC sections are matched based on the virtual address
                // otherwise the file offset is matched
                if( psec->get_flags() & SHF_ALLOC
                      ? (segVBaseAddr <= psec->get_address()
                          && psec->get_address() + psec->get_size()
                           <= segVEndAddr)
                      : (segBaseOffset <= psec->get_offset()
                          && psec->get_offset() + psec->get_size()
                           <= segEndOffset)) {
                      seg->add_section_index( psec->get_index(),
                                              psec->get_addr_align() );
                }
            }

            // Add section into the segments' container
            segments_.push_back( seg );
        }

        return true;
    }

//------------------------------------------------------------------------------
    bool save_header( std::ofstream& f )
    {
        return header->save( f );
    }

//------------------------------------------------------------------------------
    bool save_sections( std::ofstream& f )
    {
        for ( unsigned int i = 0; i < sections_.size(); ++i ) {
            section *sec = sections_.at(i);

            std::streampos headerPosition =
                (std::streamoff)header->get_sections_offset() +
                header->get_section_entry_size() * sec->get_index();

            sec->save(f,headerPosition,sec->get_offset());
        }
        return true;
    }

//------------------------------------------------------------------------------
    bool save_segments( std::ofstream& f )
    {
        for ( unsigned int i = 0; i < segments_.size(); ++i ) {
            segment *seg = segments_.at(i);

            std::streampos headerPosition = header->get_segments_offset()  +
                header->get_segment_entry_size()*seg->get_index();

            seg->save( f, headerPosition, seg->get_offset() );
        }
        return true;
    }

//------------------------------------------------------------------------------
    bool is_section_without_segment( unsigned int section_index )
    {
        bool found = false;

        for ( unsigned int j = 0; !found && ( j < segments.size() ); ++j ) {
            for ( unsigned int k = 0;
                  !found && ( k < segments[j]->get_sections_num() );
                  ++k ) {
                found = segments[j]->get_section_index_at( k ) == section_index;
            }
        }

        return !found;
    }

//------------------------------------------------------------------------------
    bool is_subsequence_of( segment* seg1, segment* seg2 )
    {
        // Return 'true' if sections of seg1 are a subset of sections in seg2
        const std::vector<Elf_Half>& sections1 = seg1->get_sections();
        const std::vector<Elf_Half>& sections2 = seg2->get_sections();

        bool found = false;
        if ( sections1.size() <  sections2.size() ) {
            found = std::includes( sections2.begin(), sections2.end(),
                                   sections1.begin(), sections1.end() );
        }

        return found;
    }

//------------------------------------------------------------------------------
    std::vector<segment*> get_ordered_segments( )
    {
        std::vector<segment*> res;
        std::deque<segment*>  worklist;

        res.reserve(segments.size());
        std::copy( segments_.begin(), segments_.end(),
                   std::back_inserter( worklist )) ;

        // Bring the segments which start at address 0 to the front
        size_t nextSlot = 0;
        for( size_t i = 0; i < worklist.size(); ++i ) {
            if( i != nextSlot && worklist[i]->is_offset_initialized()
                && worklist[i]->get_offset() == 0 ) {
                std::swap(worklist[i],worklist[nextSlot]);
                ++nextSlot;
            }
        }

        while ( !worklist.empty() ) {
            segment *seg = worklist.front();
            worklist.pop_front();

            size_t i = 0;
            for ( ; i < worklist.size(); ++i ) {
                if ( is_subsequence_of( seg, worklist[i] ) ) {
                    break;
                }
            }

            if ( i < worklist.size() )
                worklist.push_back(seg);
            else
                res.push_back(seg);
        }

        return res;
    }

//------------------------------------------------------------------------------
    bool layout_sections_without_segments( )
    {
        for ( unsigned int i = 0; i < sections_.size(); ++i ) {
            if ( is_section_without_segment( i ) ) {
                section *sec = sections_[i];

                Elf_Xword section_align = sec->get_addr_align();
                if ( section_align > 1 && current_file_pos % section_align != 0 ) {
                    current_file_pos += section_align -
                                            current_file_pos % section_align;
                }

                if ( 0 != sec->get_index() )
                  sec->set_offset(current_file_pos);

                if ( SHT_NOBITS != sec->get_type() &&
                     SHT_NULL   != sec->get_type() ) {
                    current_file_pos += sec->get_size();
                }
            }
        }

        return true;
    }

//------------------------------------------------------------------------------
    bool layout_segments_and_their_sections( )
    {
        std::vector<segment*>  worklist;
        std::vector<bool>      section_generated(sections.size(),false);

        // Get segments in a order in where segments which contain a
        // sub sequence of other segments are located at the end
        worklist = get_ordered_segments();

        for ( unsigned int i = 0; i < worklist.size(); ++i ) {
            Elf_Xword segment_memory   = 0;
            Elf_Xword segment_filesize = 0;
            Elf_Xword seg_start_pos    = current_file_pos;
            segment* seg               = worklist[i];

            // Special case: PHDR segment
            // This segment contains the program headers but no sections
            if ( seg->get_type() == PT_PHDR && seg->get_sections_num() == 0 ) {
                seg_start_pos = header->get_segments_offset();
                segment_memory = segment_filesize =
                    header->get_segment_entry_size() * header->get_segments_num();
            }
            // Special case:
            // Segments which start with the NULL section and have further sections
            else if ( seg->get_sections_num() > 1
                      && sections[seg->get_section_index_at( 0 )]->get_type() == SHT_NULL ) {
                seg_start_pos = 0;
                if ( seg->get_sections_num() ) {
                    segment_memory = segment_filesize = current_file_pos;
                }
            }
            // New segments with not generated sections
            // have to be aligned
            else if ( seg->get_sections_num()
                     && !section_generated[seg->get_section_index_at( 0 )] ) {
                Elf64_Off cur_page_alignment = current_file_pos % seg->get_align();
                Elf64_Off req_page_alignment = seg->get_virtual_address() % seg->get_align();
                Elf64_Off error              = req_page_alignment - cur_page_alignment;

                current_file_pos += ( seg->get_align() + error ) % seg->get_align();
                seg_start_pos = current_file_pos;
            }
            else if ( seg->get_sections_num() ) {
                seg_start_pos = sections[seg->get_section_index_at( 0 )]->get_offset();
            }

            // Write segment's data
            for ( unsigned int j = 0; j < seg->get_sections_num(); ++j ) {
                Elf_Half index = seg->get_section_index_at( j );

                section* sec = sections[ index ];

                // The NULL section is always generated
                if ( SHT_NULL == sec->get_type()) {
                    section_generated[index] = true;
                    continue;
                }

                Elf_Xword secAlign = 0;
                // Fix up the alignment
                if ( !section_generated[index] && sec->is_address_initialized()
                    && SHT_NOBITS != sec->get_type()
                    && SHT_NULL != sec->get_type() ) {
                    // Align the sections based on the virtual addresses
                    // when possible (this is what matters for execution)
                    Elf64_Off req_offset = sec->get_address() - seg->get_virtual_address();
                    Elf64_Off cur_offset = current_file_pos - seg_start_pos;
                    secAlign             = req_offset - cur_offset;
                }
                else if (!section_generated[index]) {
                    // If no address has been specified then only the section
                    // alignment constraint has to be matched
					Elf_Xword align = sec->get_addr_align();
					if (align == 0) {
						align = 1;
					}
                    Elf64_Off error = current_file_pos % align;
                    secAlign = ( align - error ) % align;
                }
                else {
                    // Alignment for already generated sections
                    secAlign = sec->get_offset() - seg_start_pos - segment_filesize;
                }

                // Determine the segment file and memory sizes
                // Special case .tbss section (NOBITS) in non TLS segment
                if ( (sec->get_flags() & SHF_ALLOC)
                    && !( (sec->get_flags() & SHF_TLS) && (seg->get_type() != PT_TLS)
                          && ( SHT_NOBITS == sec->get_type())) )
                    segment_memory += sec->get_size() + secAlign;
                if ( SHT_NOBITS != sec->get_type() && SHT_NULL != sec->get_type() )
                    segment_filesize += sec->get_size() + secAlign;

                // Nothing to be done when generating nested segments
                if(section_generated[index]) {
                    continue;
                }

                current_file_pos += secAlign;

                // Set the section addresses when missing
                if ( !sec->is_address_initialized() )
                    sec->set_address( seg->get_virtual_address()
                                      + current_file_pos - seg_start_pos);

                if ( 0 != sec->get_index() )
                  sec->set_offset(current_file_pos);

                if ( SHT_NOBITS != sec->get_type() && SHT_NULL != sec->get_type() )
                  current_file_pos += sec->get_size();
                section_generated[index] = true;
            }

            seg->set_file_size( segment_filesize );
            seg->set_memory_size( segment_memory );
            seg->set_offset(seg_start_pos);
        }

        return true;
    }

//------------------------------------------------------------------------------
    bool layout_section_table()
    {
        // Simply place the section table at the end for now
        Elf64_Off alignmentError = current_file_pos % 4;
        current_file_pos += ( 4 - alignmentError ) % 4;
        header->set_sections_offset(current_file_pos);
        return true;
    }

//------------------------------------------------------------------------------
  public:
    friend class Sections;
    class Sections {
      public:
//------------------------------------------------------------------------------
        Sections( elfio* parent_ ) :
            parent( parent_ )
        {
        }

//------------------------------------------------------------------------------
        Elf_Half size() const
        {
            return (Elf_Half)parent->sections_.size();
        }

//------------------------------------------------------------------------------
        section* operator[]( std::size_t index ) const
        {
            section* sec = 0;

            if ( index < parent->sections_.size() ) {
                sec = parent->sections_[index];
            }

            return sec;
        }

//------------------------------------------------------------------------------
        section* operator[]( const std::string& name ) const
        {
            section* sec = 0;

            std::vector<section*>::const_iterator it;
            for ( it = parent->sections_.begin();
                  it != parent->sections_.end();
                  ++it ) {
                if ( (*it)->get_name() == name ) {
                    sec = *it;
                    break;
                }
            }

            return sec;
        }

//------------------------------------------------------------------------------
        section* add( const std::string& name )
        {
            section* new_section = parent->create_section();
            new_section->set_name( name );

            Elf_Half str_index = parent->get_section_name_str_index();
            section* string_table( parent->sections_[str_index] );
            string_section_accessor str_writer( string_table );
            Elf_Word pos = str_writer.add_string( name );
            new_section->set_name_string_offset( pos );

            return new_section;
        }

//------------------------------------------------------------------------------
        std::vector<section*>::iterator begin() {
            return parent->sections_.begin();
        }

//------------------------------------------------------------------------------
        std::vector<section*>::iterator end() {
            return parent->sections_.end();
        }

//------------------------------------------------------------------------------
      private:
        elfio* parent;
    } sections;

//------------------------------------------------------------------------------
  public:
    friend class Segments;
    class Segments {
      public:
//------------------------------------------------------------------------------
        Segments( elfio* parent_ ) :
            parent( parent_ )
        {
        }

//------------------------------------------------------------------------------
        Elf_Half size() const
        {
            return (Elf_Half)parent->segments_.size();
        }

//------------------------------------------------------------------------------
        segment* operator[]( std::size_t index ) const
        {
            return parent->segments_[index];
        }

//------------------------------------------------------------------------------
        segment* add()
        {
            return parent->create_segment();
        }

//------------------------------------------------------------------------------
        std::vector<segment*>::iterator begin() {
            return parent->segments_.begin();
        }

//------------------------------------------------------------------------------
        std::vector<segment*>::iterator end() {
            return parent->segments_.end();
        }

//------------------------------------------------------------------------------
      private:
        elfio* parent;
    } segments;

//------------------------------------------------------------------------------
  private:
    size_t                real_file_length;
    elf_header*           header;
    std::ifstream         ifStream;
    std::istream*         iStream;
    std::vector<section*> sections_;
    std::vector<segment*> segments_;
    endianess_convertor   convertor;

    Elf_Xword current_file_pos;
};

} // namespace ELFIO

#include <elfio/elfio_symbols.hpp>
#include <elfio/elfio_note.hpp>
#include <elfio/elfio_relocation.hpp>
#include <elfio/elfio_dynamic.hpp>

#ifdef _MSC_VER
#pragma warning ( pop )
#endif

#endif // ELFIO_HPP
