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
    vm::util::init();   // ��ʼ��zydis
  else {
    //clear old data
    vm_handlers.clear();
    vm_entry.clear();
    calc_jmp.clear();
    update_opcode.clear();
    update_rolling_key.clear();
  }
  
  //
  //�����֧������
  //

  if (!vm::util::flatten(vm_entry, vm_entry_rva + module_base)) return false;

  //output flatten vm_entry
  
  //if (!first) {
      //vm::util::print(vm_entry);
  //}

  //
  //���dead store������
  //
  vm::util::deobfuscate(vm_entry);

  LOG(DEBUG) << "print vm_entry after deobfuscate";
  vm::util::print(vm_entry);
  //���ȡopcode��jmp��handler�ķ�ָ֧��
  if (!vm::calc_jmp::get(vm_entry, calc_jmp)) return false;

    if (!vm::calc_jmp::get_op_decrypt(calc_jmp, update_opcode,update_rolling_key))
    return false;

    LOG(DEBUG) << "update_opcode : ";
    vm::util::print(update_opcode);
    LOG(DEBUG) << "end";

        LOG(DEBUG) << "update_rolling_key : ";
    vm::util::print(update_rolling_key);
    LOG(DEBUG) << "end";

  if (!vm::virtual_machine_stream::get(vm_entry, opcode_stream,key1,key2,module_base))
    return false;

  //ͨ��������λ��handler table
  if (vm_handler_table = vm::handler::table::get(vm_entry);
      !vm::handler::get_all(module_base, image_base, vm_entry, vm_handler_table, //��table����ȡ���е�handler
                            vm_handlers))
    return false;

  //ȷ��opcodeǰ���ķ���
  if (auto advancement = vm::calc_jmp::get_advancement(calc_jmp);
      advancement.has_value())
    exec_type = advancement.value();
  else
    return false;

  return true;
}
}  // namespace vm