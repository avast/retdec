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

#ifndef ELFIO_SECTION_HPP
#define ELFIO_SECTION_HPP

#include <algorithm>
#include <string>
#include <iostream>

namespace ELFIO {

class section
{
    friend class elfio;
  public:
    virtual ~section() {};

    ELFIO_GET_ACCESS_DECL    ( Elf_Half,    index              );
    ELFIO_GET_SET_ACCESS_DECL( std::string, name               );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Word,    type               );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Xword,   flags              );
    ELFIO_GET_SET_ACCESS_DECL( Elf64_Off,   offset             );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Word,    info               );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Word,    link               );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Xword,   addr_align         );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Xword,   entry_size         );
    ELFIO_GET_SET_ACCESS_DECL( Elf64_Addr,  address            );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Xword,   size               );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Word,    name_string_offset );

    virtual Elf_Xword   get_data_size() const                           = 0;
    virtual const char* get_data() const                                = 0;
    virtual void        set_data( const char* pData, Elf_Word size )    = 0;
    virtual void        set_data( const std::string& data )             = 0;
    virtual void        append_data( const char* pData, Elf_Word size ) = 0;
    virtual void        append_data( const std::string& data )          = 0;

  protected:
    ELFIO_SET_ACCESS_DECL( Elf_Half,  index  );

    virtual void load( std::istream&  f,
                       std::streampos header_offset ) = 0;
    virtual void save( std::ostream&  f,
                       std::streampos header_offset,
                       std::streampos data_offset )   = 0;
    virtual bool is_address_initialized() const       = 0;

  public:
    virtual void load( std::istream& stream, size_t data_offset, size_t data_size ) = 0;
};

template< class T >
class section_impl : public section
{
  public:
//------------------------------------------------------------------------------
    section_impl( const endianess_convertor* convertor_, size_t file_length_ ) :
        convertor( convertor_ ), file_length( file_length_ )
    {
        std::fill_n( reinterpret_cast<char*>( &header ), sizeof( header ), '\0' );
        is_address_set = false;
        data           = 0;
        data_size      = 0;
    }

//------------------------------------------------------------------------------
    ~section_impl()
    {
        delete [] data;
    }

//------------------------------------------------------------------------------
    // Section info functions
    ELFIO_GET_SET_ACCESS( Elf_Word,   type,               header.sh_type      );
    ELFIO_GET_SET_ACCESS( Elf_Xword,  flags,              header.sh_flags     );
    ELFIO_GET_SET_ACCESS( Elf_Xword,  size,               header.sh_size      );
    ELFIO_GET_SET_ACCESS( Elf_Word,   link,               header.sh_link      );
    ELFIO_GET_SET_ACCESS( Elf_Word,   info,               header.sh_info      );
    ELFIO_GET_SET_ACCESS( Elf_Xword,  addr_align,         header.sh_addralign );
    ELFIO_GET_SET_ACCESS( Elf_Xword,  entry_size,         header.sh_entsize   );
    ELFIO_GET_SET_ACCESS( Elf_Word,   name_string_offset, header.sh_name      );
    ELFIO_GET_ACCESS    ( Elf64_Addr, address,            header.sh_addr      );
    ELFIO_GET_ACCESS    ( Elf64_Off,  offset,             header.sh_offset    );

//------------------------------------------------------------------------------
    Elf_Half
    get_index() const
    {
        return index;
    }

//------------------------------------------------------------------------------
    std::string
    get_name() const
    {
        return name;
    }

//------------------------------------------------------------------------------
    void
    set_name( std::string name_ )
    {
        name = name_;
    }

//------------------------------------------------------------------------------
    void
    set_address( Elf64_Addr value )
    {
        header.sh_addr = value;
        header.sh_addr = (*convertor)( header.sh_addr );
        is_address_set = true;
    }

//------------------------------------------------------------------------------
    bool
    is_address_initialized() const
    {
        return is_address_set;
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
    void
    set_data( const char* raw_data, Elf_Word size )
    {
        if ( get_type() != SHT_NOBITS ) {
            delete [] data;
            try {
                data = new char[size];
            } catch (const std::bad_alloc&) {
                data      = 0;
                data_size = 0;
                size      = 0;
            }
            if ( 0 != data && 0 != raw_data ) {
                data_size = size;
                std::copy( raw_data, raw_data + size, data );
            }
        }

        set_size( size );
    }

//------------------------------------------------------------------------------
    void
    set_data( const std::string& str_data )
    {
        return set_data( str_data.c_str(), (Elf_Word)str_data.size() );
    }

//------------------------------------------------------------------------------
    void
    append_data( const char* raw_data, Elf_Word size )
    {
        if ( get_type() != SHT_NOBITS ) {
            if ( get_size() + size < data_size ) {
                std::copy( raw_data, raw_data + size, data + get_size() );
            }
            else {
                data_size = 2*( data_size + size);
                char* new_data;
                try {
                    new_data = new char[data_size];
                } catch (const std::bad_alloc&) {
                    new_data = 0;
                    size     = 0;
                }
                if ( 0 != new_data ) {
                    std::copy( data, data + get_size(), new_data );
                    std::copy( raw_data, raw_data + size, new_data + get_size() );
                    delete [] data;
                    data = new_data;
                }
            }
            set_size( get_size() + size );
        }
    }

//------------------------------------------------------------------------------
    void
    append_data( const std::string& str_data )
    {
        return append_data( str_data.c_str(), (Elf_Word)str_data.size() );
    }

//------------------------------------------------------------------------------
    void
    load( std::istream& stream,
          size_t        data_offset,
          size_t        size )
    {
        if ( get_type() != SHT_NULL && get_type() != SHT_NOBITS && size != 0 ) {
            stream.seekg( data_offset );
            delete [] data;
            try {
                data = new char[size];
            } catch (const std::bad_alloc&) {
                data      = 0;
                data_size = 0;
                size      = 0;
            }
            if ( 0 != data ) {
                stream.read( data, size );
                data_size = stream.gcount();
            }
        }
    }

//------------------------------------------------------------------------------
  protected:
//------------------------------------------------------------------------------
    ELFIO_SET_ACCESS( Elf64_Off, offset, header.sh_offset );

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

        std::fill_n( reinterpret_cast<char*>( &header ), sizeof( header ), '\0' );
        stream.seekg( header_offset );
        const size_t headerSz = sizeof( header );
        const size_t remainingSz = file_length - header_offset;
        const size_t sz = std::min(headerSz, remainingSz);
        stream.read( reinterpret_cast<char*>( &header ), sz );
        const size_t section_offset = (*convertor)( header.sh_offset );
        if ( section_offset >= file_length ) {
            return;
        }

        Elf_Xword size = get_size();
        size = std::min<Elf_Xword>( file_length - section_offset, size );
        if ( 0 == data && SHT_NULL != get_type() && SHT_NOBITS != get_type() && 0 != size ) {
            try {
                data = new char[size];
            } catch (const std::bad_alloc&) {
                data      = 0;
                data_size = 0;
            }
            if ( 0 != size ) {
                stream.seekg( section_offset );
                stream.read( data, size );
                data_size = stream.gcount();
            }
        }
    }

//------------------------------------------------------------------------------
    void
    save( std::ostream&  f,
          std::streampos header_offset,
          std::streampos data_offset )
    {
        if ( 0 != get_index() ) {
            header.sh_offset = data_offset;
            header.sh_offset = (*convertor)( header.sh_offset );
        }

        save_header( f, header_offset );
        if ( get_type() != SHT_NOBITS && get_type() != SHT_NULL &&
             get_size() != 0 && data != 0 ) {
            save_data( f, data_offset );
        }
    }

//------------------------------------------------------------------------------
  private:
//------------------------------------------------------------------------------
    void
    save_header( std::ostream&  f,
                 std::streampos header_offset ) const
    {
        f.seekp( header_offset );
        f.write( reinterpret_cast<const char*>( &header ), sizeof( header ) );
    }

//------------------------------------------------------------------------------
    void
    save_data( std::ostream&  f,
               std::streampos data_offset ) const
    {
        f.seekp( data_offset );
        f.write( get_data(), get_size() );
    }

//------------------------------------------------------------------------------
  private:
    T                          header;
    Elf_Half                   index;
    std::string                name;
    char*                      data;
    Elf_Xword                  data_size;
    const endianess_convertor* convertor;
    bool                       is_address_set;
    size_t                     file_length;
};

} // namespace ELFIO

#endif // ELFIO_SECTION_HPP
