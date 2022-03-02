#pragma once
#include <transform.hpp>
#include <vmhandlers.hpp>
#include <vmp2.hpp>

namespace vm {
/// <summary>
/// vm::ctx_t class is used to auto generate vm_entry, calc_jmp, and other
/// per-vm entry information... creating a vm::ctx_t object can make it easier
/// to pass around information pertaining to a given vm entry...
/// </summary>
class ctx_t {
 public:
  /// <summary>
  /// default constructor for vm::ctx_t... all information for a given vm entry
  /// must be provided...
  /// </summary>
  /// <param name="module_base">the linear virtual address of the module
  /// base...</param> <param name="image_base">image base from optional nt
  /// header... <a
  /// href="https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64">IMAGE_OPTIONAL_HEADER64</a>...</param>
  /// <param name="image_size">image size from optional nt header... <a
  /// href="https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64">IMAGE_OPTIONAL_HEADER64</a>...</param>
  /// <param name="vm_entry_rva">relative virtual address from the module base
  /// address to the first push prior to a vm entry...</param>
  explicit ctx_t(std::uintptr_t module_base, std::uintptr_t image_base,
                 std::uintptr_t image_size, std::uintptr_t vm_entry_rva);

  /// <summary>
  /// init all per-vm entry data such as vm_entry, calc_jmp, and vm handlers...
  /// </summary>
  /// <returns>returns true if no errors...</returns>
  bool init();

  const std::uintptr_t module_base, image_base, vm_entry_rva, image_size;

  /// <summary>
  /// the order in which VIP advances...
  /// </summary>
  vmp2::exec_type_t exec_type;
  zydis_routine_t vm_entry, calc_jmp;

  /// <summary>
  /// all the vm handlers for the given vm entry...
  /// </summary>
  std::vector<vm::handler::handler_t> vm_handlers;
};
}  // namespace vm