#include <nt/image.hpp>

/// <summary>
/// small namespace that contains function wrappers to determine the validity of linear virtual addresses...
/// </summary>
namespace scn
{
    /// <summary>
    /// determines if a pointer lands inside of a section that is readonly...
    ///
    /// this also checks to make sure the section is not discardable...
    /// </summary>
    /// <param name="module_base">linear virtual address of the module....</param>
    /// <param name="ptr">linear virtual address</param>
    /// <returns>returns true if ptr lands inside of a readonly section of the module</returns>
    bool read_only( std::uint64_t module_base, std::uint64_t ptr );

    /// <summary>
    /// determines if a pointer lands inside of a section that is executable...
    ///
    /// this also checks to make sure the section is not discardable...
    /// </summary>
    /// <param name="module_base"></param>
    /// <param name="ptr"></param>
    /// <returns></returns>
    bool executable( std::uint64_t module_base, std::uint64_t ptr );
} // namespace scn