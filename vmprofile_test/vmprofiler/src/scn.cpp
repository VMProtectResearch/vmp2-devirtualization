#include <scn.hpp>

namespace scn
{
    bool read_only( std::uint64_t module_base, std::uint64_t ptr )
    {
        auto win_image = reinterpret_cast< win::image_t<> * >( module_base );
        auto section_count = win_image->get_file_header()->num_sections;
        auto sections = win_image->get_nt_headers()->get_sections();

        for ( auto idx = 0u; idx < section_count; ++idx )
            if ( ptr >= sections[ idx ].virtual_address + module_base &&
                 ptr < sections[ idx ].virtual_address + sections[ idx ].virtual_size + module_base )
                return !( sections[ idx ].characteristics.mem_discardable ) &&
                       !( sections[ idx ].characteristics.mem_write );

        return false;
    }

    bool executable( std::uint64_t module_base, std::uint64_t ptr )
    {
        auto win_image = reinterpret_cast< win::image_t<> * >( module_base );
        auto section_count = win_image->get_file_header()->num_sections;
        auto sections = win_image->get_nt_headers()->get_sections();

        for ( auto idx = 0u; idx < section_count; ++idx )
            if ( ptr >= sections[ idx ].virtual_address + module_base &&
                 ptr < sections[ idx ].virtual_address + sections[ idx ].virtual_size + module_base )
                return !( sections[ idx ].characteristics.mem_discardable ) &&
                       sections[ idx ].characteristics.mem_execute;

        return false;
    }
} // namespace scn