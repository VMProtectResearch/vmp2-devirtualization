#pragma once
#include <transform.hpp>
#include <vmp2.hpp>

namespace vm::calc_jmp
{
    /// <summary>
    /// extracts calc_jmp out of vm_entry... you can learn about calc_jmp <a
    /// href="https://back.engineering/17/05/2021/#calc_jmp">here</a>.
    /// </summary>
    /// <param name="vm_entry">pass by reference vm entry...</param>
    /// <param name="calc_jmp">zydis_routine_t filled up with native instructions by this routine...</param>
    /// <returns>returns truee if no errors happen...</returns>
    bool get( zydis_routine_t &vm_entry, zydis_routine_t &calc_jmp );

    /// <summary>
    /// gets the advancement of the virtual instruction pointer... iterates over calc_jmp for LEA, MOV, INC, DEC, SUB,
    /// ADD, ETC instructions and then decides which way VIP advances based upon this information...
    /// </summary>
    /// <param name="calc_jmp"></param>
    /// <returns></returns>
    std::optional< vmp2::exec_type_t > get_advancement( const zydis_routine_t &calc_jmp );
} // namespace vm::calc_jmp