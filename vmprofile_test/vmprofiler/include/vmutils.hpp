#pragma once
#include <Zydis/Utils.h>
#include <Zydis/Zydis.h>
#include <xmmintrin.h>

#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#ifdef _MSC_VER

#include <stdlib.h>
#define bswap_32(x) _byteswap_ulong(x)
#define bswap_64(x) _byteswap_uint64(x)
#define bswap_16(x) _byteswap_ushort(x)

#elif defined(__APPLE__)

// Mac OS X / Darwin features
#include <libkern/OSByteOrder.h>
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)

#elif defined(__sun) || defined(sun)

#include <sys/byteorder.h>
#define bswap_32(x) BSWAP_32(x)
#define bswap_64(x) BSWAP_64(x)

#elif defined(__FreeBSD__)

#include <sys/endian.h>
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)

#elif defined(__OpenBSD__)

#include <sys/types.h>
#define bswap_32(x) swap32(x)
#define bswap_64(x) swap64(x)

#elif defined(__NetBSD__)

#include <machine/bswap.h>
#include <sys/types.h>
#if defined(__BSWAP_RENAME) && !defined(__bswap_32)
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)
#endif

#else

#include <byteswap.h>

#endif

using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long long;
using u128 = __m128;

using zydis_decoded_instr_t = ZydisDecodedInstruction;
using zydis_register_t = ZydisRegister;
using zydis_mnemonic_t = ZydisMnemonic;
using zydis_decoded_operand_t = ZydisDecodedOperand;

struct zydis_instr_t {
  zydis_decoded_instr_t instr;
  std::vector<u8> raw;
  std::uintptr_t addr;
};

using zydis_routine_t = std::vector<zydis_instr_t>;

/// <summary>
/// utils used by the other cpp files... misc things that get used a lot...
/// </summary>
namespace vm::util {

inline thread_local std::shared_ptr<ZydisDecoder> g_decoder = nullptr;
inline thread_local std::shared_ptr<ZydisFormatter> g_formatter = nullptr;

inline void init() {
  if (!vm::util::g_decoder && !vm::util::g_formatter) {
    vm::util::g_decoder = std::make_shared<ZydisDecoder>();
    vm::util::g_formatter = std::make_shared<ZydisFormatter>();

    ZydisDecoderInit(vm::util::g_decoder.get(), ZYDIS_MACHINE_MODE_LONG_64,
                     ZYDIS_ADDRESS_WIDTH_64);

    ZydisFormatterInit(vm::util::g_formatter.get(),
                       ZYDIS_FORMATTER_STYLE_INTEL);
  }
}

inline bool open_binary_file(const std::string &file,
                             std::vector<uint8_t> &data) {
  std::ifstream fstr(file, std::ios::binary);
  if (!fstr.is_open()) return false;

  fstr.unsetf(std::ios::skipws);
  fstr.seekg(0, std::ios::end);

  const auto file_size = fstr.tellg();

  fstr.seekg(NULL, std::ios::beg);
  data.reserve(static_cast<uint32_t>(file_size));
  data.insert(data.begin(), std::istream_iterator<uint8_t>(fstr),
              std::istream_iterator<uint8_t>());
  return true;
}

/// <summary>
/// utils pertaining to native registers...
/// </summary>
namespace reg {
/// <summary>
/// converts say... AL to RAX...
/// </summary>
/// <param name="reg">a zydis decoded register value...</param>
/// <returns>returns the largest width register of the given register... AL
/// gives RAX...</returns>
zydis_register_t to64(zydis_register_t reg);

/// <summary>
/// compares to registers with each other... calls to64 and compares...
/// </summary>
/// <param name="a">register a...</param>
/// <param name="b">register b...</param>
/// <returns>returns true if register to64(a) == to64(b)...</returns>
bool compare(zydis_register_t a, zydis_register_t b);
}  // namespace reg

/// <summary>
/// get the instruction that fetches an operand out of VIP...
/// </summary>
/// <param name="routine">this is a deobfuscated, flattened, view of any set of
/// native instructions that read an operand out of VIP... can be calc_jmp,
/// vm_entry, or vm handlers...</param> <param name="fetch_instr"></param>
/// <returns>returns true of the fetch operand native instruction is
/// found...</returns>
bool get_fetch_operand(const zydis_routine_t &routine,
                       zydis_instr_t &fetch_instr);

/// <summary>
/// gets the instruction that fetches an operand out of VIP and returns an
/// iterator to it...
/// </summary>
/// <param name="routine">this is a deobfuscated, flattened, view of any set of
/// native instructions that read an operand out of VIP... can be calc_jmp,
/// vm_entry, or vm handlers...</param> <returns>returns the iterator of the
/// native instruction, else an empty std::optional...</returns>
std::optional<zydis_routine_t::iterator> get_fetch_operand(
    zydis_routine_t &routine);

/// <summary>
/// prints a disassembly view of a routine...
/// </summary>
/// <param name="routine">reference to a zydis_routine_t to be
/// printed...</param>
void print(zydis_routine_t &routine);

/// <summary>
/// prints a single disassembly view of an instruction...
/// </summary>
/// <param name="instr">instruction to print...</param>
void print(const zydis_decoded_instr_t &instr);

/// <summary>
/// determines if a given decoded native instruction is a JCC...
/// </summary>
/// <param name="instr"></param>
/// <returns></returns>
bool is_jmp(const zydis_decoded_instr_t &instr);

/// <summary>
/// flatten native instruction stream, takes every JCC (follows the branch)...
/// </summary>
/// <param name="routine">filled with decoded instructions...</param>
/// <param name="routine_addr">linear virtual address to start flattening
/// from...</param> <param name="keep_jmps">keep JCC's in the flattened
/// instruction stream...</param> <returns>returns true if flattened was
/// successful...</returns>
bool flatten(zydis_routine_t &routine, std::uintptr_t routine_addr,
             bool keep_jmps = false, std::uint32_t max_instrs = 500,
             std::uintptr_t module_base = 0ull);

/// <summary>
/// deadstore deobfuscation of a flattened routine...
/// </summary>
/// <param name="routine">reference to a flattened instruction vector...</param>
void deobfuscate(zydis_routine_t &routine);
}  // namespace vm::util