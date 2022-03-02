#pragma once
#include <nt/image.hpp>
#include <vmprofiler.hpp>

#define LEA_R12_SIG "\x4C\x8D\x25\x00\x00\x00\x00"
#define LEA_R12_MASK "xxx????"

#define PUSH_4B_IMM "\x68\x00\x00\x00\x00"
#define PUSH_4B_MASK "x????"

namespace vm::locate {
inline bool find(const zydis_routine_t &rtn,
                 std::function<bool(const zydis_instr_t &)> callback) {
  auto res = std::find_if(rtn.begin(), rtn.end(), callback);
  return res != rtn.end();
}

struct vm_enter_t {
  std::uint32_t rva;
  std::uint32_t encrypted_rva;

  struct {
    std::uint32_t hndlr_tbl_rva;
    zydis_instr_t lea_r12_instr;
  } hndlr_tble;
};

std::uintptr_t sigscan(void *base, std::uint32_t size, const char *pattern,
                       const char *mask);

// this routine will search the entire binary for all vm entries. It will apply
// all known axioms/constants/signatures which are detailed here:
// https://back.engineering/17/05/2021/#vm_entry
std::vector<vm_enter_t> get_vm_entries(std::uintptr_t module_base,
                                       std::uint32_t module_size);
}  // namespace vm::locate