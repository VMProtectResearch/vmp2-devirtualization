#pragma once
#include <Zydis/Zydis.h>
#include <functional>
#include <map>
#include <stdexcept>
#include <vmutils.hpp>

namespace vm::transform
{
    /// <summary>
    /// rotate left template function take from IDA SDK...
    /// </summary>
    /// <typeparam name="T">type of data to rotate left...</typeparam>
    /// <param name="value">value to rotate left</param>
    /// <param name="count">number of bits to rotate left...</param>
    /// <returns>returns the rotated value...</returns>
    template < class T > inline T __ROL__( T value, int count )
    {
        const unsigned int nbits = sizeof( T ) * 8;

        if ( count > 0 )
        {
            count %= nbits;
            T high = value >> ( nbits - count );
            if ( T( -1 ) < 0 ) // signed value
                high &= ~( ( T( -1 ) << count ) );
            value <<= count;
            value |= high;
        }
        else
        {
            count = -count % nbits;
            T low = value << ( nbits - count );
            value >>= count;
            value |= low;
        }
        return value;
    }

    /// <summary>
    /// rotate left a one byte value...
    /// </summary>
    /// <param name="value">byte value</param>
    /// <param name="count">number of bits to rotate</param>
    /// <returns>return rotated value...</returns>
    inline u8 __ROL1__( u8 value, int count )
    {
        return __ROL__( ( u8 )value, count );
    }

    /// <summary>
    /// rotate left a two byte value...
    /// </summary>
    /// <param name="value">two byte value to rotate...</param>
    /// <param name="count">number of bits to rotate...</param>
    /// <returns>return rotated value...</returns>
    inline u16 __ROL2__( u16 value, int count )
    {
        return __ROL__( ( u16 )value, count );
    }

    /// <summary>
    /// rotate left a four byte value...
    /// </summary>
    /// <param name="value">four byte value to rotate...</param>
    /// <param name="count">number of bits to shift...</param>
    /// <returns>return rotated value...</returns>
    inline u32 __ROL4__( u32 value, int count )
    {
        return __ROL__( ( u32 )value, count );
    }

    /// <summary>
    /// rotate left an eight byte value...
    /// </summary>
    /// <param name="value">eight byte value...</param>
    /// <param name="count">number of bits to shift...</param>
    /// <returns>return rotated value...</returns>
    inline u64 __ROL8__( u64 value, int count )
    {
        return __ROL__( ( u64 )value, count );
    }

    /// <summary>
    /// rotate right a one byte value...
    /// </summary>
    /// <param name="value">one byte value...</param>
    /// <param name="count">number of bits to shift...</param>
    /// <returns>return rotated value...</returns>
    inline u8 __ROR1__( u8 value, int count )
    {
        return __ROL__( ( u8 )value, -count );
    }

    /// <summary>
    /// rotate right a two byte value...
    /// </summary>
    /// <param name="value">two byte value to rotate...</param>
    /// <param name="count">number of bits to shift...</param>
    /// <returns></returns>
    inline u16 __ROR2__( u16 value, int count )
    {
        return __ROL__( ( u16 )value, -count );
    }

    /// <summary>
    /// rotate right a four byte value...
    /// </summary>
    /// <param name="value">four byte value to rotate...</param>
    /// <param name="count">number of bits to rotate...</param>
    /// <returns>return rotated value...</returns>
    inline u32 __ROR4__( u32 value, int count )
    {
        return __ROL__( ( u32 )value, -count );
    }

    /// <summary>
    /// rotate right an eight byte value...
    /// </summary>
    /// <param name="value">eight byte value</param>
    /// <param name="count">number of bits to rotate...</param>
    /// <returns>return rotated value...</returns>
    inline u64 __ROR8__( u64 value, int count )
    {
        return __ROL__( ( u64 )value, -count );
    }

    /// <summary>
    /// transform function, such as ADD, SUB, BSWAP... etc...
    /// </summary>
    /// <typeparam name="T">returns the transform result...</typeparam>
    template < typename T > using transform_t = std::function< T( T, T ) >;

    /// <summary>
    /// type of transformation...
    /// </summary>
    enum class type
    {
        generic0,
        rolling_key,
        generic1,
        generic2,
        generic3,
        update_key
    };

    /// <summary>
    /// map of transform type to zydis decoded instruction of the transform...
    /// </summary>
    using map_t = std::map< transform::type, zydis_decoded_instr_t >;

    template < class T >
    inline const auto _bswap = []( T a, T b ) -> T {
        if constexpr ( std::is_same_v< T, std::uint64_t > )
            return bswap_64( a );
        if constexpr ( std::is_same_v< T, std::uint32_t > )
            return bswap_32( a );
        if constexpr ( std::is_same_v< T, std::uint16_t > )
            return bswap_16( a );

        throw std::invalid_argument( "invalid type size..." );
    };

    template < class T > inline const auto _add = []( T a, T b ) -> T { return a + b; };

    template < class T > inline const auto _xor = []( T a, T b ) -> T { return a ^ b; };

    template < class T > inline const auto _sub = []( T a, T b ) -> T { return a - b; };

    template < class T > inline const auto _neg = []( T a, T b ) -> T { return a * -1; };

    template < class T > inline const auto _not = []( T a, T b ) -> T { return ~a; };

    template < class T >
    inline const auto _ror = []( T a, T b ) -> T {
        if constexpr ( std::is_same_v< T, std::uint64_t > )
            return __ROR8__( a, b );
        if constexpr ( std::is_same_v< T, std::uint32_t > )
            return __ROR4__( a, b );
        if constexpr ( std::is_same_v< T, std::uint16_t > )
            return __ROR2__( a, b );
        if constexpr ( std::is_same_v< T, std::uint8_t > )
            return __ROR1__( a, b );

        throw std::invalid_argument( "invalid type size..." );
    };

    template < class T >
    inline const auto _rol = []( T a, T b ) -> T {
        if constexpr ( std::is_same_v< T, std::uint64_t > )
            return __ROL8__( a, b );
        if constexpr ( std::is_same_v< T, std::uint32_t > )
            return __ROL4__( a, b );
        if constexpr ( std::is_same_v< T, std::uint16_t > )
            return __ROL2__( a, b );
        if constexpr ( std::is_same_v< T, std::uint8_t > )
            return __ROL1__( a, b );

        throw std::invalid_argument( "invalid type size..." );
    };

    template < class T > inline const auto _inc = []( T a, T b ) -> T { return a + 1; };

    template < class T > inline const auto _dec = []( T a, T b ) -> T { return a - 1; };

    template < class T >
    inline std::map< zydis_mnemonic_t, transform_t< T > > transforms = {
        { ZYDIS_MNEMONIC_ADD, _add< T > }, { ZYDIS_MNEMONIC_XOR, _xor< T > },   { ZYDIS_MNEMONIC_BSWAP, _bswap< T > },
        { ZYDIS_MNEMONIC_SUB, _sub< T > }, { ZYDIS_MNEMONIC_NEG, _neg< T > },   { ZYDIS_MNEMONIC_NOT, _not< T > },
        { ZYDIS_MNEMONIC_ROR, _ror< T > }, { ZYDIS_MNEMONIC_ROL, _rol< T > },   { ZYDIS_MNEMONIC_INC, _inc< T > },
        { ZYDIS_MNEMONIC_DEC, _dec< T > }, { ZYDIS_MNEMONIC_XCHG, _bswap< T > } };

    inline std::map< zydis_mnemonic_t, zydis_mnemonic_t > inverse = {
        { ZYDIS_MNEMONIC_ADD, ZYDIS_MNEMONIC_SUB },     { ZYDIS_MNEMONIC_XOR, ZYDIS_MNEMONIC_XOR },
        { ZYDIS_MNEMONIC_BSWAP, ZYDIS_MNEMONIC_BSWAP }, { ZYDIS_MNEMONIC_SUB, ZYDIS_MNEMONIC_ADD },
        { ZYDIS_MNEMONIC_NEG, ZYDIS_MNEMONIC_NEG },     { ZYDIS_MNEMONIC_NOT, ZYDIS_MNEMONIC_NOT },
        { ZYDIS_MNEMONIC_ROR, ZYDIS_MNEMONIC_ROL },     { ZYDIS_MNEMONIC_ROL, ZYDIS_MNEMONIC_ROR },
        { ZYDIS_MNEMONIC_INC, ZYDIS_MNEMONIC_DEC },     { ZYDIS_MNEMONIC_DEC, ZYDIS_MNEMONIC_INC },
        { ZYDIS_MNEMONIC_XCHG, ZYDIS_MNEMONIC_XCHG } };

    /// <summary>
    /// determines if the given mnemonic is a valid transformation...
    /// </summary>
    /// <param name="op">mnemonic of the native instruction...</param>
    /// <returns>returns true if the mnemonic is a transformation...</returns>
    inline bool valid( zydis_mnemonic_t op )
    {
        return transforms< std::uint64_t >.find( op ) != transforms< std::uint64_t >.end();
    }

    /// <summary>
    /// inverse operand decryption transformations...
    /// </summary>
    /// <param name="transforms">reference to the transformations to be inversed...</param>
    /// <param name="inverse">reference to the resulting inversed transformations...</param>
    inline void inverse_transforms( transform::map_t &transforms, transform::map_t &inverse )
    {
        inverse[ transform::type::generic0 ] = transforms[ transform::type::generic0 ];
        inverse[ transform::type::generic0 ].mnemonic =
            transform::inverse[ transforms[ transform::type::generic0 ].mnemonic ];

        inverse[ transform::type::rolling_key ] = transforms[ transform::type::rolling_key ];
        inverse[ transform::type::rolling_key ].mnemonic =
            transform::inverse[ transforms[ transform::type::rolling_key ].mnemonic ];

        inverse[ transform::type::generic1 ] = transforms[ transform::type::generic1 ];
        inverse[ transform::type::generic1 ].mnemonic =
            transform::inverse[ transforms[ transform::type::generic1 ].mnemonic ];

        inverse[ transform::type::generic2 ] = transforms[ transform::type::generic2 ];
        inverse[ transform::type::generic2 ].mnemonic =
            transform::inverse[ transforms[ transform::type::generic2 ].mnemonic ];

        inverse[ transform::type::generic3 ] = transforms[ transform::type::generic3 ];
        inverse[ transform::type::generic3 ].mnemonic =
            transform::inverse[ transforms[ transform::type::generic3 ].mnemonic ];

        inverse[ transform::type::update_key ] = transforms[ transform::type::update_key ];
        inverse[ transform::type::update_key ].mnemonic =
            transform::inverse[ transforms[ transform::type::update_key ].mnemonic ];
    }

    /// <summary>
    /// inverse transformations given a vector of them...
    /// </summary>
    /// <param name="instrs">reference to a vector of transformations...</param>
    /// <returns>returns true if all transformations were inversed...</returns>
    inline auto inverse_transforms( std::vector< zydis_decoded_instr_t > &instrs ) -> bool
    {
        for ( auto idx = 0u; idx < instrs.size(); idx++ )
            if ( !( instrs[ idx ].mnemonic = inverse[ instrs[ idx ].mnemonic ] ) )
                return false;

        std::reverse( instrs.begin(), instrs.end() );
        return true;
    }

    // max size of a and b is 64 bits, a and b is then converted to
    // the number of bits in bitsize, the transformation is applied,
    // finally the result is converted back to 64bits... zero extended...
    inline auto apply( std::uint8_t bitsize, ZydisMnemonic op, std::uint64_t a, std::uint64_t b ) -> std::uint64_t
    {
        switch ( bitsize )
        {
        case 8:
            return transforms< std::uint8_t >[ op ]( a, b );
        case 16:
            return transforms< std::uint16_t >[ op ]( a, b );
        case 32:
            return transforms< std::uint32_t >[ op ]( a, b );
        case 64:
            return transforms< std::uint64_t >[ op ]( a, b );
        default:
            throw std::invalid_argument( "invalid bit size..." );
        }
    }

    /// <summary>
    /// determines if a given decoded instruction has a second operand that is an immediate value...
    /// </summary>
    /// <param name="instr">pointer to a decoded instruction...</param>
    /// <returns>returns true if the second operand is of type immediate...</returns>
    inline bool has_imm( const zydis_decoded_instr_t *instr )
    {
        return instr->operand_count > 1 && ( instr->operands[ 1 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE );
    }
} // namespace vm::transform