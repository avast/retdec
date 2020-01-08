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

#ifndef ELFIO_DYNAMIC_HPP
#define ELFIO_DYNAMIC_HPP

namespace ELFIO {

//------------------------------------------------------------------------------
class dynamic_section_accessor
{
  public:
//------------------------------------------------------------------------------
    dynamic_section_accessor( const elfio& elf_file_, section* section_ ) :
                              elf_file( elf_file_ ),
                              dynamic_section( section_ )
    {
    }

//------------------------------------------------------------------------------
    Elf_Xword
    get_entries_num() const
    {
        Elf_Xword nRet = 0;

        if ( 0 != dynamic_section->get_entry_size() ) {
            nRet = dynamic_section->get_size() / dynamic_section->get_entry_size();
        }

        return nRet;
    }

//------------------------------------------------------------------------------
    Elf_Xword
    get_loaded_entries_num() const
    {
        Elf_Xword nRet = 0;

        if ( 0 != dynamic_section->get_entry_size() ) {
            nRet = dynamic_section->get_data_size() / dynamic_section->get_entry_size();
        }

        return nRet;
    }

//------------------------------------------------------------------------------
    bool
    get_entry( Elf_Xword    index,
               Elf_Xword&   tag,
               Elf_Xword&   value,
               std::string& str ) const
    {
        if ( index >= get_loaded_entries_num() ) {    // Is index valid
            return false;
        }

        if ( elf_file.get_class() == ELFCLASS32 ) {
            generic_get_entry_dyn< Elf32_Dyn >( index, tag, value );
        }
        else {
            generic_get_entry_dyn< Elf64_Dyn >( index, tag, value );
        }

        // If the tag may have a string table reference, prepare the string
        if ( ( tag == DT_NEEDED ||
               tag == DT_SONAME ||
               tag == DT_RPATH  ||
               tag == DT_RUNPATH ) &&
              get_string_table_index() &&
              get_string_table_index() < elf_file.sections.size() &&
              elf_file.sections[ get_string_table_index() ] )
        {
            string_section_accessor strsec =
                elf_file.sections[ get_string_table_index() ];
            // DECOMPILER BEGIN
            str = strsec.get_string( value );
            // DECOMPILER END
        }
        else {
            str.clear();
        }

        return true;
    }

//------------------------------------------------------------------------------
    void
    add_entry( Elf_Xword& tag,
               Elf_Xword& value )
    {
        if ( elf_file.get_class() == ELFCLASS32 ) {
            generic_add_entry< Elf32_Dyn >( tag, value );
        }
        else {
            generic_add_entry< Elf64_Dyn >( tag, value );
        }
    }

//------------------------------------------------------------------------------
    void
    add_entry( Elf_Xword&   tag,
               std::string& str )
    {
        string_section_accessor strsec =
            elf_file.sections[ get_string_table_index() ];
        Elf_Xword value = strsec.add_string( str );
        add_entry( tag, value );
    }

//------------------------------------------------------------------------------
  private:
//------------------------------------------------------------------------------
    Elf_Half
    get_string_table_index() const
    {
        return (Elf_Half)dynamic_section->get_link();
    }

//------------------------------------------------------------------------------
    template< class T >
    void
    generic_get_entry_dyn( Elf_Xword  index,
                           Elf_Xword& tag,
                           Elf_Xword& value ) const
    {
        const endianess_convertor& convertor = elf_file.get_convertor();

        // Check unusual case when dynamic section has no data
        if( dynamic_section->get_data() == 0 ||
            ( index + 1 ) * dynamic_section->get_entry_size() > dynamic_section->get_size() ) {
            tag   = DT_NULL;
            value = 0;
            return;
        }

        const T* pEntry = reinterpret_cast<const T*>(
                dynamic_section->get_data() +
                index * dynamic_section->get_entry_size() );
        tag = convertor( pEntry->d_tag );
        switch ( tag ) {
        case DT_NULL:
        case DT_SYMBOLIC:
        case DT_TEXTREL:
        case DT_BIND_NOW:
            value = 0;
            break;
        case DT_NEEDED:
        case DT_PLTRELSZ:
        case DT_RELASZ:
        case DT_RELAENT:
        case DT_STRSZ:
        case DT_SYMENT:
        case DT_SONAME:
        case DT_RPATH:
        case DT_RELSZ:
        case DT_RELENT:
        case DT_PLTREL:
        case DT_INIT_ARRAYSZ:
        case DT_FINI_ARRAYSZ:
        case DT_RUNPATH:
        case DT_FLAGS:
        case DT_PREINIT_ARRAYSZ:
            value = convertor( pEntry->d_un.d_val );
            break;
        case DT_PLTGOT:
        case DT_HASH:
        case DT_STRTAB:
        case DT_SYMTAB:
        case DT_RELA:
        case DT_INIT:
        case DT_FINI:
        case DT_REL:
        case DT_DEBUG:
        case DT_JMPREL:
        case DT_INIT_ARRAY:
        case DT_FINI_ARRAY:
        case DT_PREINIT_ARRAY:
        default:
            value = convertor( pEntry->d_un.d_ptr );
            break;
        }
    }

//------------------------------------------------------------------------------
    template< class T >
    void
    generic_add_entry( Elf_Xword tag, Elf_Xword value )
    {
        const endianess_convertor& convertor = elf_file.get_convertor();

        T entry;

        switch ( tag ) {
        case DT_NULL:
        case DT_SYMBOLIC:
        case DT_TEXTREL:
        case DT_BIND_NOW:
            value = 0;
        case DT_NEEDED:
        case DT_PLTRELSZ:
        case DT_RELASZ:
        case DT_RELAENT:
        case DT_STRSZ:
        case DT_SYMENT:
        case DT_SONAME:
        case DT_RPATH:
        case DT_RELSZ:
        case DT_RELENT:
        case DT_PLTREL:
        case DT_INIT_ARRAYSZ:
        case DT_FINI_ARRAYSZ:
        case DT_RUNPATH:
        case DT_FLAGS:
        case DT_PREINIT_ARRAYSZ:
            entry.d_un.d_val = convertor( value );
            break;
        case DT_PLTGOT:
        case DT_HASH:
        case DT_STRTAB:
        case DT_SYMTAB:
        case DT_RELA:
        case DT_INIT:
        case DT_FINI:
        case DT_REL:
        case DT_DEBUG:
        case DT_JMPREL:
        case DT_INIT_ARRAY:
        case DT_FINI_ARRAY:
        case DT_PREINIT_ARRAY:
        default:
            entry.d_un.d_ptr = convertor( value );
            break;
        }

        entry.d_tag = convertor( tag );

        dynamic_section->append_data( reinterpret_cast<char*>( &entry ), sizeof( entry ) );
    }

//------------------------------------------------------------------------------
  private:
    const elfio& elf_file;
    section*     dynamic_section;
};

} // namespace ELFIO

#endif // ELFIO_DYNAMIC_HPP
