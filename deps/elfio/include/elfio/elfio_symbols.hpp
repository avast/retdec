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

#ifndef ELFIO_SYMBOLS_HPP
#define ELFIO_SYMBOLS_HPP

namespace ELFIO {

//------------------------------------------------------------------------------
class symbol_section_accessor
{
  public:
//------------------------------------------------------------------------------
    symbol_section_accessor( const elfio& elf_file_, section* symbol_section_ ) :
                             elf_file( elf_file_ ),
                             symbol_section( symbol_section_ )
    {
        find_hash_section();
    }

//------------------------------------------------------------------------------
    Elf_Xword
    get_symbols_num() const
    {
        Elf_Xword nRet = 0;
        if ( 0 != symbol_section && 0 != symbol_section->get_entry_size() ) {
            nRet = symbol_section->get_size() / symbol_section->get_entry_size();
        }

        return nRet;
    }

//------------------------------------------------------------------------------
    Elf_Xword
    get_loaded_symbols_num() const
    {
        Elf_Xword nRet = 0;
        if ( 0 != symbol_section && 0 != symbol_section->get_entry_size() ) {
            nRet = symbol_section->get_data_size() / symbol_section->get_entry_size();
        }

        return nRet;
    }

//------------------------------------------------------------------------------
    bool
    get_symbol( Elf_Xword      index,
                std::string&   name,
                Elf64_Addr&    value,
                Elf_Xword&     size,
                unsigned char& bind,
                unsigned char& type,
                Elf_Half&      section_index,
                unsigned char& other ) const
    {
        bool ret = false;

        if ( elf_file.get_class() == ELFCLASS32 ) {
            ret = generic_get_symbol<Elf32_Sym>( index, name, value, size, bind,
                                                 type, section_index, other );
        }
        else {
            ret = generic_get_symbol<Elf64_Sym>( index, name, value, size, bind,
                                                 type, section_index, other );
        }

        return ret;
    }

//------------------------------------------------------------------------------
    bool
    get_symbol( const std::string& name,
                Elf64_Addr&        value,
                Elf_Xword&         size,
                unsigned char&     bind,
                unsigned char&     type,
                Elf_Half&          section_index,
                unsigned char&     other ) const
    {
        bool ret = false;

        if ( 0 != get_hash_table_index() ) {
            Elf_Word nbucket = *(Elf_Word*)hash_section->get_data();
            Elf_Word nchain  = *(Elf_Word*)( hash_section->get_data() +
                                   sizeof( Elf_Word ) );
            Elf_Word val     = elf_hash( (const unsigned char*)name.c_str() );

            Elf_Word y   = *(Elf_Word*)( hash_section->get_data() +
                               ( 2 + val % nbucket ) * sizeof( Elf_Word ) );
            std::string   str;
            get_symbol( y, str, value, size, bind, type, section_index, other );
            while ( str != name && STN_UNDEF != y && y < nchain ) {
                y = *(Elf_Word*)( hash_section->get_data() +
                        ( 2 + nbucket + y ) * sizeof( Elf_Word ) );
                get_symbol( y, str, value, size, bind, type, section_index, other );
            }
            if (  str == name ) {
                ret = true;
            }
        }

        return ret;
    }

//------------------------------------------------------------------------------
    Elf_Word
    add_symbol( Elf_Word name, Elf64_Addr value, Elf_Xword size,
                unsigned char info, unsigned char other,
                Elf_Half shndx )
    {
        Elf_Word nRet;

        if ( symbol_section->get_size() == 0 ) {
            if ( elf_file.get_class() == ELFCLASS32 ) {
                nRet = generic_add_symbol<Elf32_Sym>( 0, 0, 0, 0, 0, 0 );
            }
            else {
                nRet = generic_add_symbol<Elf64_Sym>( 0, 0, 0, 0, 0, 0 );
            }
        }

        if ( elf_file.get_class() == ELFCLASS32 ) {
            nRet = generic_add_symbol<Elf32_Sym>( name, value, size, info, other,
                                                  shndx );
        }
        else {
            nRet = generic_add_symbol<Elf64_Sym>( name, value, size, info, other,
                                                  shndx );
        }

        return nRet;
    }

//------------------------------------------------------------------------------
    Elf_Word
    add_symbol( Elf_Word name, Elf64_Addr value, Elf_Xword size,
                unsigned char bind, unsigned char type, unsigned char other,
                Elf_Half shndx )
    {
        return add_symbol( name, value, size, ELF_ST_INFO( bind, type ), other, shndx );
    }

//------------------------------------------------------------------------------
    Elf_Word
    add_symbol( string_section_accessor& pStrWriter, const char* str,
                Elf64_Addr value, Elf_Xword size,
                unsigned char info, unsigned char other,
                Elf_Half shndx )
    {
        Elf_Word index = pStrWriter.add_string( str );
        return add_symbol( index, value, size, info, other, shndx );
    }

//------------------------------------------------------------------------------
    Elf_Word
    add_symbol( string_section_accessor& pStrWriter, const char* str,
                Elf64_Addr value, Elf_Xword size,
                unsigned char bind, unsigned char type, unsigned char other,
                Elf_Half shndx )
    {
        return add_symbol( pStrWriter, str, value, size, ELF_ST_INFO( bind, type ), other, shndx );
    }

//------------------------------------------------------------------------------
  private:
//------------------------------------------------------------------------------
    void
    find_hash_section()
    {
        if( 0 == symbol_section ) {
            return;
        }

        hash_section       = 0;
        hash_section_index = 0;
        Elf_Half nSecNo = elf_file.sections.size();
        for ( Elf_Half i = 0; i < nSecNo && 0 == hash_section_index; ++i ) {
            const section* sec = elf_file.sections[i];
            if ( sec->get_link() == symbol_section->get_index() ) {
                hash_section       = sec;
                hash_section_index = i;
            }
        }
    }

//------------------------------------------------------------------------------
    Elf_Half
    get_string_table_index() const
    {
        return (Elf_Half)symbol_section->get_link();
    }

//------------------------------------------------------------------------------
    Elf_Half
    get_hash_table_index() const
    {
        return hash_section_index;
    }

//------------------------------------------------------------------------------
    template< class T >
    bool
    generic_get_symbol( Elf_Xword index,
                        std::string& name, Elf64_Addr& value,
                        Elf_Xword& size,
                        unsigned char& bind, unsigned char& type,
                        Elf_Half& section_index,
                        unsigned char& other ) const
    {
        bool ret = false;

        if ( index < get_loaded_symbols_num() &&
                get_string_table_index() < elf_file.sections.size() &&
                index * symbol_section->get_entry_size() < symbol_section->get_data_size() ) {
            const T* pSym = reinterpret_cast<const T*>(
                symbol_section->get_data() +
                    index * symbol_section->get_entry_size() );
            if ( !pSym ) {
                return false;
            }

            const endianess_convertor& convertor = elf_file.get_convertor();

            section* string_section = elf_file.sections[get_string_table_index()];
            string_section_accessor str_reader( string_section );
            // DECOMPILER BEGIN
            name    = str_reader.get_string( convertor( pSym->st_name ) );
            // DECOMPILER END
            value   = convertor( pSym->st_value );
            size    = convertor( pSym->st_size );
            bind    = ELF_ST_BIND( pSym->st_info );
            type    = ELF_ST_TYPE( pSym->st_info );
            section_index = convertor( pSym->st_shndx );
            other   = pSym->st_other;

            ret = true;
        }

        return ret;
    }

//------------------------------------------------------------------------------
    template< class T >
    Elf_Word
    generic_add_symbol( Elf_Word name, Elf64_Addr value, Elf_Xword size,
                        unsigned char info, unsigned char other,
                        Elf_Half shndx )
    {
        const endianess_convertor& convertor = elf_file.get_convertor();

        T entry;
        entry.st_name  = convertor( name );
        entry.st_value = value;
        entry.st_value = convertor( entry.st_value );
        entry.st_size  = size;
        entry.st_size  = convertor( entry.st_size );
        entry.st_info  = convertor( info );
        entry.st_other = convertor( other );
        entry.st_shndx = convertor( shndx );

        symbol_section->append_data( reinterpret_cast<char*>( &entry ),
                                     sizeof( entry ) );

        Elf_Word nRet = symbol_section->get_size() / sizeof( entry ) - 1;

        return nRet;
    }

//------------------------------------------------------------------------------
  private:
    const elfio&   elf_file;
    section*       symbol_section;
    Elf_Half       hash_section_index;
    const section* hash_section;
};

} // namespace ELFIO

#endif // ELFIO_SYMBOLS_HPP
