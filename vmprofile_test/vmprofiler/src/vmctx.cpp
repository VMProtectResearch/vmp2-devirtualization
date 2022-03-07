#include <vmprofiler.hpp>

namespace vm {
ctx_t::ctx_t(std::uintptr_t module_base, std::uintptr_t image_base,
             std::uintptr_t image_size, std::uintptr_t vm_entry_rva)
    : module_base(module_base),
      image_base(image_base),
      image_size(image_size),
      vm_entry_rva(vm_entry_rva) {}

bool ctx_t::init(bool first) {

  if (first)
    vm::util::init();  
  else {
    //clear old data
    vm_handlers.clear();
    vm_entry.clear();
    calc_jmp.clear();
    update_opcode.clear();
    update_rolling_key.clear();
  }
  
  //
  //解决分支的问题
  //
  if (!vm::util::flatten(vm_entry, vm_entry_rva + module_base)) return false;

  //output flatten vm_entry
  
  //if (!first) {
      //vm::util::print(vm_entry);
  //}

  //
  //解决dead store的问题
  //
  vm::util::deobfuscate(vm_entry);

  //获得取opcode到jmp到handler的分支指令
  if (!vm::calc_jmp::get(vm_entry, calc_jmp)) return false;

    if (!vm::calc_jmp::get_op_decrypt(calc_jmp, update_opcode,update_rolling_key))
    return false;

  if (!vm::virtual_machine_stream::get(vm_entry, opcode_stream,key1,key2,module_base))
    return false;

  //通过特征定位到handler table
  if (vm_handler_table = vm::handler::table::get(vm_entry);
      !vm::handler::get_all(module_base, image_base, vm_entry, vm_handler_table, //从table中提取所有的handler
                            vm_handlers))
    return false;

  //确定opcode前进的方向
  if (auto advancement = vm::calc_jmp::get_advancement(calc_jmp);
      advancement.has_value())
    exec_type = advancement.value();
  else
    return false;

  return true;
}
}  // namespace vm