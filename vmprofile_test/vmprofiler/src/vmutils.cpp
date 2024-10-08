#include <vmprofiler.hpp>
#include <format>

namespace vm::util {
namespace reg {
zydis_register_t to64(zydis_register_t reg) {
  return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
}

bool compare(zydis_register_t a, zydis_register_t b) {
  return to64(a) == to64(b);
}
}  // namespace reg

bool get_fetch_operand(const zydis_routine_t& routine,
                       zydis_instr_t& fetch_instr) {
  const auto result = std::find_if(
      routine.begin(), routine.end(),
      [](const zydis_instr_t& instr_data) -> bool {
        // mov/movsx/movzx rax/eax/ax/al, [rsi]
        return instr_data.instr.operand_count > 1 &&
               (instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOV ||
                instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOVSX ||
                instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOVZX) &&
               instr_data.instr.operands[0].type ==
                   ZYDIS_OPERAND_TYPE_REGISTER &&
               util::reg::to64(instr_data.instr.operands[0].reg.value) ==
                   ZYDIS_REGISTER_RAX &&
               instr_data.instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
               instr_data.instr.operands[1].mem.base == ZYDIS_REGISTER_RSI;
      });

  if (result == routine.end())
    return false;

  fetch_instr = *result;
  return true;
}

std::optional<zydis_routine_t::iterator> get_fetch_operand(
    zydis_routine_t& routine) {
  auto result = std::find_if(
      routine.begin(), routine.end(),
      [](const zydis_instr_t& instr_data) -> bool {
        // mov/movsx/movzx rax/eax/ax/al, [rsi]
        return instr_data.instr.operand_count > 1 &&
               (instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOV ||
                instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOVSX ||
                instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOVZX) &&
               instr_data.instr.operands[0].type ==
                   ZYDIS_OPERAND_TYPE_REGISTER &&
               util::reg::to64(instr_data.instr.operands[0].reg.value) ==
                   ZYDIS_REGISTER_RAX &&
               instr_data.instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
               instr_data.instr.operands[1].mem.base == ZYDIS_REGISTER_RSI;
      });

  if (result == routine.end())
    return {};

  return result;
}

void print(const zydis_decoded_instr_t& instr) {
  char buffer[256];
  ZydisFormatterFormatInstruction(vm::util::g_formatter.get(), &instr, buffer,
                                  sizeof(buffer), 0u);
  //std::puts(buffer);
  LOG(DEBUG) << buffer;
}

void print(zydis_routine_t& routine) {
  char buffer[256];
  for (auto [instr, raw, addr] : routine) {
    ZydisFormatterFormatInstruction(vm::util::g_formatter.get(), &instr, buffer,
                                    sizeof(buffer), addr);
    //std::printf("> %p %s\n", addr, buffer);
    LOG(DEBUG) << std::format("> {:#x} {} {}", addr, vectorToHexString(raw),
                              buffer);
  }
}

void print(const zydis_decoded_instr_t& instr, char (&buf)[256]) {
  ZydisFormatterFormatInstruction(vm::util::g_formatter.get(), &instr, buf,
                                  256, 0u);
}


bool is_jmp(const zydis_decoded_instr_t& instr) {
  return instr.mnemonic >= ZYDIS_MNEMONIC_JB &&
         instr.mnemonic <= ZYDIS_MNEMONIC_JZ;
}

//
// 跟踪jmp直到遇到jmp reg或call reg,vmentry最后通过jmp reg开始分发,handler的话最终会返回vmentry的中间重新分发的
// 所以通过jmp reg来收集流程一般来说是比较正确的
//
bool flatten(zydis_routine_t& routine,
             std::uintptr_t routine_addr,
             bool keep_jmps,
             std::uint32_t max_instrs,
             std::uintptr_t module_base) {
  zydis_decoded_instr_t instr;
  std::uint32_t instr_cnt = 0u;

  auto RAII = llvm::make_scope_exit([&]() { auto it = routine.begin();
    for (; it != routine.end(); it++) {
      if (it->instr.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_INVALID) {
        it = routine.erase(it);
      }
    }
      
      });

  while ((ZydisDecoderDecodeBuffer(
      vm::util::g_decoder.get(), reinterpret_cast<void*>(routine_addr), 15,
      &instr))) {
    if (++instr_cnt > max_instrs)
      return false;
  
    if (routine_addr == 0x14000811E) {
      assert(0);
    }

    // detect if we have already been at this instruction... if so that means
    // there is a loop and we are going to just return...
    if (std::find_if(routine.begin(), routine.end(),
                     [&](const zydis_instr_t& zydis_instr) -> bool {
                       return zydis_instr.addr == routine_addr;
                     }) != routine.end())
      return true;

    std::vector<u8> raw_instr;
    raw_instr.insert(raw_instr.begin(), (u8*)routine_addr, //存储指令数据

                     (u8*)routine_addr + instr.length);

    if (is_jmp(instr) ||
        instr.mnemonic == ZYDIS_MNEMONIC_CALL &&
            instr.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
      if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) { //jmp REG / call REG   
        routine.push_back({instr, raw_instr, routine_addr});
        return true;
      }

      if (keep_jmps)
        routine.push_back({instr, raw_instr, routine_addr});
      ZydisCalcAbsoluteAddress(&instr, &instr.operands[0], routine_addr,
                               &routine_addr);
    } else if (instr.mnemonic == ZYDIS_MNEMONIC_RET) {
      routine.push_back({instr, raw_instr, routine_addr});
      return true;
    } else {
      routine.push_back({instr, raw_instr, routine_addr});
      routine_addr += instr.length;
    }

    // optional sanity checking...
    if (module_base && !scn::executable(module_base, routine_addr))
      return false;
  }

  LOG(ERROR) << "ZydisDecoderDecodeBuffer Fail at " << std::hex << routine_addr;
  return false;
}

void deobfuscate(zydis_routine_t& routine) {

    //static function  
  static const auto _uses_reg = [](zydis_decoded_operand_t& op,
                                   zydis_register_t reg) -> bool {
    switch (op.type) {
      case ZYDIS_OPERAND_TYPE_MEMORY: {
        return reg::compare(op.mem.base, reg) ||
               reg::compare(op.mem.index, reg);
      }
      case ZYDIS_OPERAND_TYPE_REGISTER: {
        return reg::compare(op.reg.value, reg);
      }
      default:
        break;
    }
    return false;
  };//

  //static function
  static const auto _reads = [](zydis_decoded_instr_t& instr,
                                zydis_register_t reg) -> bool {
    if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
        reg::compare(instr.operands[0].mem.base, reg))
      return true;

    for (auto op_idx = 0u; op_idx < instr.operand_count; ++op_idx)
      if (instr.operands[op_idx].actions & ZYDIS_OPERAND_ACTION_READ &&
          _uses_reg(instr.operands[op_idx], reg))
        return true;
    return false;
  };//

  //static function
  static const auto _writes = [](zydis_decoded_instr_t& instr,
                                 zydis_register_t reg) -> bool {
    for (auto op_idx = 0u; op_idx < instr.operand_count; ++op_idx)
      // if instruction writes to the specific register...
      if (instr.operands[op_idx].type == ZYDIS_OPERAND_TYPE_REGISTER &&
          instr.operands[op_idx].actions & ZYDIS_OPERAND_ACTION_WRITE &&
          !(instr.operands[op_idx].actions & ZYDIS_OPERAND_ACTION_READ) &&
          reg::compare(instr.operands[op_idx].reg.value, reg))
        return true;
    return false;
  };//end

  std::uint32_t last_size = 0u;
  static const std::vector<ZydisMnemonic> blacklist = {
      ZYDIS_MNEMONIC_CLC, ZYDIS_MNEMONIC_BT,  ZYDIS_MNEMONIC_TEST,
      ZYDIS_MNEMONIC_CMP, ZYDIS_MNEMONIC_CMC, ZYDIS_MNEMONIC_STC};

  static const std::vector<ZydisMnemonic> whitelist = {
      ZYDIS_MNEMONIC_PUSH, ZYDIS_MNEMONIC_POP, ZYDIS_MNEMONIC_CALL,
      ZYDIS_MNEMONIC_DIV};

  do {
    last_size = routine.size();
    for (auto itr = routine.begin(); itr != routine.end(); ++itr) {
      if (std::find(whitelist.begin(), whitelist.end(), itr->instr.mnemonic) !=
          whitelist.end()) // erase insn in white list
        continue;

      if (std::find(blacklist.begin(), blacklist.end(), itr->instr.mnemonic) !=
          blacklist.end()) {
        routine.erase(itr); //erase insn in blacklist
        break;
      }

      zydis_register_t reg = ZYDIS_REGISTER_NONE;
      // look for operands with writes to a register...
      for (auto op_idx = 0u; op_idx < itr->instr.operand_count; ++op_idx)
        if (itr->instr.operands[op_idx].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            itr->instr.operands[op_idx].actions & ZYDIS_OPERAND_ACTION_WRITE)
          reg = reg::to64(itr->instr.operands[0].reg.value);

      // if this current instruction writes to a register, look ahead in the
      // instruction stream to see if it gets written too before it gets read...
      if (reg != ZYDIS_REGISTER_NONE) {
        // find the next place that this register is written too...
        auto write_result = std::find_if(itr + 1, routine.end(),
                                         [&](zydis_instr_t& instr) -> bool {
                                           return _writes(instr.instr, reg);
                                         });

        auto read_result = std::find_if(itr + 1, write_result,
                                        [&](zydis_instr_t& instr) -> bool {
                                          return _reads(instr.instr, reg);
                                        });

        // if there is neither a read or a write to this register in the
        // instruction stream then we are going to be safe and leave the
        // instruction in the stream...
        if (read_result == routine.end() && write_result == routine.end())
          continue;

        // if there is no read of the register before the next write... and
        // there is a known next write, then remove the instruction from the
        // stream...
        if (read_result == write_result && write_result != routine.end()) {
          // if the instruction reads and writes the same register than skip...
          if (_reads(read_result->instr, reg) &&
              _writes(read_result->instr, reg))
            continue;

          routine.erase(itr);
          break;
        }
      }
    }
  } while (last_size != routine.size());
}
}  // namespace vm::util