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

#ifndef ELFIO_RELOCATION_HPP
#define ELFIO_RELOCATION_HPP

namespace ELFIO {

template<typename T> struct get_sym_and_type;
template<> struct get_sym_and_type< Elf32_Rel >
{
    static int get_r_sym( Elf_Xword info )
    {
        return ELF32_R_SYM( (Elf_Word)info );
    }
    static int get_r_type( Elf_Xword info )
    {
        return ELF32_R_TYPE( (Elf_Word)info );
    }
};
template<> struct get_sym_and_type< Elf32_Rela >
{
    static int get_r_sym( Elf_Xword info )
    {
        return ELF32_R_SYM( (Elf_Word)info );
    }
    static int get_r_type( Elf_Xword info )
    {
        return ELF32_R_TYPE( (Elf_Word)info );
    }
};
template<> struct get_sym_and_type< Elf64_Rel >
{
    static int get_r_sym( Elf_Xword info )
    {
        return ELF64_R_SYM( info );
    }
    static int get_r_type( Elf_Xword info )
    {
        return ELF64_R_TYPE( info );
    }
};
template<> struct get_sym_and_type< Elf64_Rela >
{
    static int get_r_sym( Elf_Xword info )
    {
        return ELF64_R_SYM( info );
    }
    static int get_r_type( Elf_Xword info )
    {
        return ELF64_R_TYPE( info );
    }
};

//------------------------------------------------------------------------------
class relocation_section_accessor
{
  public:
//------------------------------------------------------------------------------
    relocation_section_accessor( const elfio& elf_file_, section* section_ ) :
                                 elf_file( elf_file_ ),
                                 relocation_section( section_ )
    {
    }

//------------------------------------------------------------------------------
    Elf_Xword
    get_entries_num() const
    {
        Elf_Xword nRet = 0;

        if ( 0 != relocation_section->get_entry_size() ) {
            nRet = relocation_section->get_size() / relocation_section->get_entry_size();
        }

        return nRet;
    }

//------------------------------------------------------------------------------
    Elf_Xword
    get_loaded_entries_num() const
    {
        Elf_Xword nRet = 0;

        if ( 0 != relocation_section->get_entry_size() ) {
            nRet = relocation_section->get_data_size() / relocation_section->get_entry_size();
        }

        return nRet;
    }

//------------------------------------------------------------------------------
    bool
    get_entry( Elf_Xword   index,
               Elf64_Addr& offset,
               Elf_Word&   symbol,
               Elf_Word&   type,
               Elf_Sxword& addend ) const
    {
        if ( index >= get_loaded_entries_num() ) {    // Is index valid
            return false;
        }

        if ( elf_file.get_class() == ELFCLASS32 ) {
            if ( SHT_REL == relocation_section->get_type() ) {
                generic_get_entry_rel< Elf32_Rel >( index, offset, symbol,
                                                    type,  addend );
            }
            else if ( SHT_RELA == relocation_section->get_type() ) {
                generic_get_entry_rela< Elf32_Rela >( index, offset, symbol,
                                                      type,  addend );
            }
        }
        else {
            if ( SHT_REL == relocation_section->get_type() ) {
                generic_get_entry_rel< Elf64_Rel >( index, offset, symbol,
                                                    type,  addend );
            }
            else if ( SHT_RELA == relocation_section->get_type() ) {
                generic_get_entry_rela< Elf64_Rela >( index, offset, symbol,
                                                      type,  addend );
            }
        }

        return true;
    }

//------------------------------------------------------------------------------
    bool
    get_entry( Elf_Xword    index,
               Elf64_Addr&  offset,
               Elf64_Addr&  symbolValue,
               std::string& symbolName,
               Elf_Word&    type,
               Elf_Sxword&  addend,
               Elf_Sxword&  calcValue ) const
    {
        // Do regular job
        Elf_Word symbol = 0;
        bool ret = get_entry( index, offset, symbol, type, addend );

        // Find the symbol
        Elf_Xword     size;
        unsigned char bind;
        unsigned char symbolType;
        Elf_Half      section;
        unsigned char other;

        symbol_section_accessor symbols( elf_file, elf_file.sections[get_symbol_table_index()] );
        ret = ret && symbols.get_symbol( symbol, symbolName, symbolValue,
                                         size, bind, symbolType, section, other );

        if ( ret ) { // Was it successful?
            switch ( type ) {
            case R_386_NONE:        // none
                calcValue = 0;
                break;
            case R_386_32:          // S + A
                calcValue = symbolValue + addend;
                break;
            case R_386_PC32:        // S + A - P
                calcValue = symbolValue + addend - offset;
                break;
            case R_386_GOT32:       // G + A - P
                calcValue = 0;
                break;
            case R_386_PLT32:       // L + A - P
                calcValue = 0;
                break;
            case R_386_COPY:        // none
                calcValue = 0;
                break;
            case R_386_GLOB_DAT:    // S
            case R_386_JMP_SLOT:    // S
                calcValue = symbolValue;
                break;
            case R_386_RELATIVE:    // B + A
                calcValue = addend;
                break;
            case R_386_GOTOFF:      // S + A - GOT
                calcValue = 0;
                break;
            case R_386_GOTPC:       // GOT + A - P
                calcValue = 0;
                break;
            default:                // Not recognized symbol!
                calcValue = 0;
                break;
            }
        }

        return ret;
    }

//--------------DECOMPILER!-----------------------------------------------------
    bool
    mips64_get_entry( Elf_Xword   index,
                      Elf64_Addr& offset,
                      Elf_Word&   symbol,
                      Elf64_Byte& special,
                      Elf64_Byte& type3,
                      Elf64_Byte& type2,
                      Elf64_Byte& type,
                      Elf_Sxword& addend ) const
    {
        if ( index >= get_loaded_entries_num() ) {    // Is index valid
            return false;
        }

        if ( elf_file.get_class() != ELFCLASS64 ||
             elf_file.get_machine() != EM_MIPS) {     // Is 64-bit MIPS
            return false;
        }
        else {
            if ( SHT_REL == relocation_section->get_type() ) {
                mips64_get_entry_rel( index, offset, symbol, special, type3,
                                      type2, type, addend );
            }
            else if ( SHT_RELA == relocation_section->get_type() ) {
                mips64_get_entry_rela( index, offset, symbol, special, type3,
                                       type2, type, addend );
            }
        }

        return true;
    }

//------------------------------------------------------------------------------
    void
    add_entry( Elf64_Addr offset, Elf_Xword info )
    {
        if ( elf_file.get_class() == ELFCLASS32 ) {
            generic_add_entry< Elf32_Rel >( offset, info );
        }
        else {
            generic_add_entry< Elf64_Rel >( offset, info );
        }
    }

//------------------------------------------------------------------------------
    void
    add_entry( Elf64_Addr offset, Elf_Word symbol, unsigned char type )
    {
        Elf_Xword info;
        if ( elf_file.get_class() == ELFCLASS32 ) {
            info = ELF32_R_INFO( (Elf_Xword)symbol, type );
        }
        else {
            info = ELF64_R_INFO((Elf_Xword)symbol, type );
        }

        add_entry( offset, info );
    }

//------------------------------------------------------------------------------
    void
    add_entry( Elf64_Addr offset, Elf_Xword info, Elf_Sxword addend )
    {
        if ( elf_file.get_class() == ELFCLASS32 ) {
            generic_add_entry< Elf32_Rela >( offset, info, addend );
        }
        else {
            generic_add_entry< Elf64_Rela >( offset, info, addend );
        }
    }

//------------------------------------------------------------------------------
    void
    add_entry( Elf64_Addr offset, Elf_Word symbol, unsigned char type,
               Elf_Sxword addend )
    {
        Elf_Xword info;
        if ( elf_file.get_class() == ELFCLASS32 ) {
            info = ELF32_R_INFO( (Elf_Xword)symbol, type );
        }
        else {
            info = ELF64_R_INFO( (Elf_Xword)symbol, type );
        }

        add_entry( offset, info, addend );
    }

//------------------------------------------------------------------------------
    void
    add_entry( string_section_accessor str_writer,
               const char* str,
               symbol_section_accessor sym_writer,
               Elf64_Addr value,
               Elf_Word size,
               unsigned char sym_info,
               unsigned char other,
               Elf_Half shndx,
               Elf64_Addr offset,
               unsigned char type )
    {
        Elf_Word str_index = str_writer.add_string( str );
        Elf_Word sym_index = sym_writer.add_symbol( str_index, value, size,
                                                   sym_info, other, shndx );
        add_entry( offset, sym_index, type );
    }

//------------------------------------------------------------------------------
  private:
//------------------------------------------------------------------------------
    Elf_Half
    get_symbol_table_index() const
    {
        return (Elf_Half)relocation_section->get_link();
    }

//------------------------------------------------------------------------------
    template< class T >
    void
    generic_get_entry_rel( Elf_Xword   index,
                           Elf64_Addr& offset,
                           Elf_Word&   symbol,
                           Elf_Word&   type,
                           Elf_Sxword& addend ) const
    {
        if ( index * relocation_section->get_entry_size() + sizeof(T) >
            relocation_section->get_data_size() ) {
            return;
        }
        const endianess_convertor& convertor = elf_file.get_convertor();

        const T* pEntry = reinterpret_cast<const T*>(
                relocation_section->get_data() +
                index * relocation_section->get_entry_size() );
        if ( pEntry ) {
            offset        = convertor( pEntry->r_offset );
            Elf_Xword tmp = convertor( pEntry->r_info );
            symbol        = get_sym_and_type<T>::get_r_sym( tmp );
            type          = get_sym_and_type<T>::get_r_type( tmp );
        }
        addend = 0;
    }

//------------------------------------------------------------------------------
    template< class T >
    void
    generic_get_entry_rela( Elf_Xword   index,
                            Elf64_Addr& offset,
                            Elf_Word&   symbol,
                            Elf_Word&   type,
                            Elf_Sxword& addend ) const
    {
        if ( index * relocation_section->get_entry_size() + sizeof(T) >
            relocation_section->get_data_size() ) {
            return;
        }
        const endianess_convertor& convertor = elf_file.get_convertor();

        const T* pEntry = reinterpret_cast<const T*>(
                relocation_section->get_data() +
                index * relocation_section->get_entry_size() );
        if ( pEntry ) {
            offset        = convertor( pEntry->r_offset );
            Elf_Xword tmp = convertor( pEntry->r_info );
            symbol        = get_sym_and_type<T>::get_r_sym( tmp );
            type          = get_sym_and_type<T>::get_r_type( tmp );
            addend        = convertor( pEntry->r_addend );
        }
    }

//--------------DECOMPILER!-----------------------------------------------------
    void
    mips64_get_entry_rel( Elf_Xword   index,
                          Elf64_Addr& offset,
                          Elf_Word&   symbol,
                          Elf64_Byte& special,
                          Elf64_Byte& type3,
                          Elf64_Byte& type2,
                          Elf64_Byte& type,
                          Elf_Sxword& addend ) const
    {
        if ( index * relocation_section->get_entry_size() + sizeof(Elf64_Mips_Rel) >
             relocation_section->get_data_size() ) {
            return;
        }
        const endianess_convertor& convertor = elf_file.get_convertor();

        const Elf64_Mips_Rel* pEntry = reinterpret_cast<const Elf64_Mips_Rel*>(
                    relocation_section->get_data() +
                    index * relocation_section->get_entry_size() );
        if ( pEntry ) {
            offset        = convertor( pEntry->r_offset );
            symbol        = convertor( pEntry->r_sym );
            special       = pEntry->r_ssym;
            type3         = pEntry->r_type3;
            type2         = pEntry->r_type2;
            type          = pEntry->r_type;
        }
        addend = 0;
    }

//--------------DECOMPILER!-----------------------------------------------------
    void
    mips64_get_entry_rela( Elf_Xword   index,
                           Elf64_Addr& offset,
                           Elf_Word&   symbol,
                           Elf64_Byte& special,
                           Elf64_Byte& type3,
                           Elf64_Byte& type2,
                           Elf64_Byte& type,
                           Elf_Sxword& addend ) const
    {
        if ( index * relocation_section->get_entry_size() + sizeof(Elf64_Mips_Rela) >
             relocation_section->get_data_size() ) {
            return;
        }
        const endianess_convertor& convertor = elf_file.get_convertor();

        const Elf64_Mips_Rela* pEntry = reinterpret_cast<const Elf64_Mips_Rela*>(
                    relocation_section->get_data() +
                    index * relocation_section->get_entry_size() );
        if ( pEntry ) {
            offset        = convertor( pEntry->r_offset );
            symbol        = convertor( pEntry->r_sym );
            special       = pEntry->r_ssym;
            type3         = pEntry->r_type3;
            type2         = pEntry->r_type2;
            type          = pEntry->r_type;
            addend        = convertor( pEntry->r_addend );
        }
    }

//------------------------------------------------------------------------------
    template< class T >
    void
    generic_add_entry( Elf64_Addr offset, Elf_Xword info )
    {
        const endianess_convertor& convertor = elf_file.get_convertor();

        T entry;
        entry.r_offset = offset;
        entry.r_info   = info;
        entry.r_offset = convertor( entry.r_offset );
        entry.r_info   = convertor( entry.r_info );

        relocation_section->append_data( reinterpret_cast<char*>( &entry ), sizeof( entry ) );
    }

//------------------------------------------------------------------------------
    template< class T >
    void
    generic_add_entry( Elf64_Addr offset, Elf_Xword info, Elf_Sxword addend )
    {
        const endianess_convertor& convertor = elf_file.get_convertor();

        T entry;
        entry.r_offset = offset;
        entry.r_info   = info;
        entry.r_addend = addend;
        entry.r_offset = convertor( entry.r_offset );
        entry.r_info   = convertor( entry.r_info );
        entry.r_addend = convertor( entry.r_addend );

        relocation_section->append_data( reinterpret_cast<char*>( &entry ), sizeof( entry ) );
    }

//------------------------------------------------------------------------------
  private:
    const elfio& elf_file;
    section*     relocation_section;
};

} // namespace ELFIO

#endif // ELFIO_RELOCATION_HPP
