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

#ifndef ELFIO_SEGMENT_HPP
#define ELFIO_SEGMENT_HPP

#include <iostream>
#include <vector>

namespace ELFIO {

class segment
{
    friend class elfio;
  public:
    virtual ~segment() {};

    ELFIO_GET_ACCESS_DECL    ( Elf_Half,   index            );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Word,   type             );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Word,   flags            );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Xword,  align            );
    ELFIO_GET_SET_ACCESS_DECL( Elf64_Addr, virtual_address  );
    ELFIO_GET_SET_ACCESS_DECL( Elf64_Addr, physical_address );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Xword,  file_size        );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Xword,  memory_size      );
    ELFIO_GET_ACCESS_DECL( Elf64_Off, offset );

    virtual Elf_Xword   get_data_size() const = 0;
    virtual const char* get_data() const      = 0;

    virtual Elf_Half add_section_index( Elf_Half index, Elf_Xword addr_align ) = 0;
    virtual Elf_Half get_sections_num()                                  const = 0;
    virtual Elf_Half get_section_index_at( Elf_Half num )                const = 0;
    virtual bool is_offset_initialized()                                 const = 0;

  protected:
    ELFIO_SET_ACCESS_DECL( Elf64_Off, offset );
    ELFIO_SET_ACCESS_DECL( Elf_Half,  index  );

    virtual const std::vector<Elf_Half>& get_sections() const               = 0;
    virtual void load( std::istream& stream, std::streampos header_offset ) = 0;
    virtual void save( std::ostream& f,      std::streampos header_offset,
                                             std::streampos data_offset )   = 0;

  public:
    virtual void load( std::istream& stream, size_t data_offset, size_t data_size ) = 0;
};

//------------------------------------------------------------------------------
template< class T >
class segment_impl : public segment
{
  public:
//------------------------------------------------------------------------------
    segment_impl( endianess_convertor* convertor_, size_t file_length_ ) :
        convertor( convertor_ ), file_length( file_length_ )
    {
        is_offset_set = false;
        std::fill_n( reinterpret_cast<char*>( &ph ), sizeof( ph ), '\0' );
        data      = 0;
        data_size = 0;
    }

//------------------------------------------------------------------------------
    virtual ~segment_impl()
    {
        delete [] data;
    }

//------------------------------------------------------------------------------
    // Section info functions
    ELFIO_GET_SET_ACCESS( Elf_Word,   type,             ph.p_type   );
    ELFIO_GET_SET_ACCESS( Elf_Word,   flags,            ph.p_flags  );
    ELFIO_GET_SET_ACCESS( Elf_Xword,  align,            ph.p_align  );
    ELFIO_GET_SET_ACCESS( Elf64_Addr, virtual_address,  ph.p_vaddr  );
    ELFIO_GET_SET_ACCESS( Elf64_Addr, physical_address, ph.p_paddr  );
    ELFIO_GET_SET_ACCESS( Elf_Xword,  file_size,        ph.p_filesz );
    ELFIO_GET_SET_ACCESS( Elf_Xword,  memory_size,      ph.p_memsz  );
    ELFIO_GET_ACCESS( Elf64_Off, offset, ph.p_offset );

//------------------------------------------------------------------------------
    Elf_Half
    get_index() const
    {
        return index;
    }

//------------------------------------------------------------------------------
    Elf_Xword
    get_data_size() const
    {
        return data_size;
    }

//------------------------------------------------------------------------------
    const char*
    get_data() const
    {
        return data;
    }

//------------------------------------------------------------------------------
    Elf_Half
    add_section_index( Elf_Half sec_index, Elf_Xword addr_align )
    {
        sections.push_back( sec_index );
        if ( addr_align > get_align() ) {
            set_align( addr_align );
        }

        return (Elf_Half)sections.size();
    }

//------------------------------------------------------------------------------
    Elf_Half
    get_sections_num() const
    {
        return (Elf_Half)sections.size();
    }

//------------------------------------------------------------------------------
    Elf_Half
    get_section_index_at( Elf_Half num ) const
    {
        if ( num < sections.size() ) {
            return sections[num];
        }

        return -1;
    }

//------------------------------------------------------------------------------
  protected:
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
    void
    set_offset( Elf64_Off value )
    {
        ph.p_offset = value;
        ph.p_offset = (*convertor)( ph.p_offset );
        is_offset_set = true;
    }

//------------------------------------------------------------------------------
    bool
    is_offset_initialized() const
    {
        return is_offset_set;
    }

//------------------------------------------------------------------------------
    const std::vector<Elf_Half>&
    get_sections() const
    {
        return sections;
    }

//------------------------------------------------------------------------------
    void
    set_index( Elf_Half value )
    {
        index = value;
    }

//------------------------------------------------------------------------------
    void
    load( std::istream&  stream,
          std::streampos header_offset )
    {
        data = 0;
        data_size = 0;
        if ( header_offset >= file_length ) {
            return;
        }

        stream.seekg( header_offset );
        stream.read( reinterpret_cast<char*>( &ph ), sizeof( ph ) );
        is_offset_set = true;
        const size_t segmentOffset = (*convertor)( ph.p_offset );

        if ( PT_NULL != get_type() && 0 != get_file_size() &&
            segmentOffset < file_length ) {
            stream.seekg( segmentOffset );
            Elf_Xword size = std::min<Elf_Xword>( file_length - segmentOffset,
                get_file_size() );
            try {
                data = new char[size];
            } catch (const std::bad_alloc&) {
                data = 0;
                data_size = 0;
            }
            if ( 0 != data ) {
                stream.read( data, size );
                data_size = stream.gcount();
            }
        }
    }

//------------------------------------------------------------------------------
    void save( std::ostream&  f,
               std::streampos header_offset,
               std::streampos data_offset )
    {
        ph.p_offset = data_offset;
        ph.p_offset = (*convertor)(ph.p_offset);
        f.seekp( header_offset );
        f.write( reinterpret_cast<const char*>( &ph ), sizeof( ph ) );
    }

//------------------------------------------------------------------------------
  public:
//------------------------------------------------------------------------------
    void
    load( std::istream& stream,
          size_t        data_offset,
          size_t        size )
    {
        if ( PT_NULL != get_type() && 0 != size ) {
            stream.seekg( data_offset );
            is_offset_set = true;
            delete [] data;
            try {
                data = new char[size];
            } catch (const std::bad_alloc&) {
                data      = 0;
                data_size = 0;
            }
            if ( 0 != data ) {
                stream.read( data, size );
                data_size = stream.gcount();
            }
        }
    }

//------------------------------------------------------------------------------
  private:
    T                     ph;
    Elf_Half              index;
    char*                 data;
    Elf_Xword             data_size;
    std::vector<Elf_Half> sections;
    endianess_convertor*  convertor;
    bool                  is_offset_set;
    size_t                file_length;
};

} // namespace ELFIO

#endif // ELFIO_SEGMENT_HPP
