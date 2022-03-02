#pragma once
#include <transform.hpp>

/// <summary>
/// contains all information pertaining to vm handler identification...
/// </summary>
namespace vm::handler
{
    /// <summary>
    /// vm handler mnemonic... so you dont need to compare strings!
    /// </summary>
    enum mnemonic_t
    {
        INVALID,
        LFLAGSQ,
        RDTSC,

        MULQ,
        MULDW,
        MULW,
        MULB,

        IMULQ,
        IMULDW,
        IMULW,
        IMULB,

        DIVQ,
        DIVDW,
        DIVW,
        DIVB,

        IDIVQ,
        IDIVDW,
        IDIVW,
        IDIVB,

        CALL,
        JMP,
        VMEXIT,
        POPVSPQ,
        POPVSPDW,
        POPVSPW,
        POPVSPB,

        READCR3,
        WRITECR3,
        READCR8,
        WRITECR8,

        PUSHVSPQ,
        PUSHVSPDW,
        PUSHVSPW,
        PUSHVSPB,

        SREGQ,
        SREGDW,
        SREGW,
        SREGB,

        LREGQ,
        LREGDW,
        LREGW,
        LREGB,

        LCONSTQ,
        LCONSTBZXW,
        LCONSTBSXQ,
        LCONSTBSXDW,
        LCONSTDWSXQ,
        LCONSTWSXQ,
        LCONSTWSXDW,
        LCONSTDW,
        LCONSTW,

        READQ,
        READGSQ,
        READDW,
        READW,
        READB,

        WRITEQ,
        WRITEGSQ,
        WRITEDW,
        WRITEW,
        WRITEB,

        ADDQ,
        ADDDW,
        ADDW,
        ADDB,

        SHLQ,
        SHLDW,
        SHLW,
        SHLB,

        SHLDQ,
        SHLDDW,
        SHLD_W,
        SHLDB,

        SHRQ,
        SHRDW,
        SHRW,
        SHRB,

        SHRDQ,
        SHRDDW,
        SHRD_W,
        SHRDB,

        NANDQ,
        NANDDW,
        NANDW,
        NANDB
    };

    /// <summary>
    /// zydis callback lambda used to pattern match native instructions...
    /// </summary>
    using zydis_callback_t = std::function< bool( const zydis_decoded_instr_t &instr ) >;

    /// <summary>
    /// how sign extention is handled...
    /// </summary>
    enum extention_t
    {
        none,
        sign_extend,
        zero_extend
    };

    /// <summary>
    /// pre defined vm handler profile containing all compiled time known information about a vm handler...
    /// </summary>
    struct profile_t
    {
        /// <summary>
        /// name of the vm handler, such as JMP or LCONST...
        /// </summary>
        const char *name;

        /// <summary>
        /// the mnemonic of the vm handler... so you dont need to compare strings...
        /// </summary>
        mnemonic_t mnemonic;

        /// <summary>
        /// size, in bits, of the operand (imm)... if there is none then this will be zero...
        /// </summary>
        u8 imm_size;

        /// <summary>
        /// a vector of signatures used to compare native instructions against zydis aided signatures...
        /// </summary>
        std::vector< zydis_callback_t > signature;

        /// <summary>
        /// how sign extention of operands are handled...
        /// </summary>
        extention_t extention;
    };

    /// <summary>
    /// contains all profiles defined, as well as a vector of all of the defined profiles...
    /// </summary>
    namespace profile
    {
        extern vm::handler::profile_t sregq;
        extern vm::handler::profile_t sregdw;
        extern vm::handler::profile_t sregw;
        extern vm::handler::profile_t sregb;

        extern vm::handler::profile_t lregq;
        extern vm::handler::profile_t lregdw;

        extern vm::handler::profile_t lconstq;
        extern vm::handler::profile_t lconstdw;
        extern vm::handler::profile_t lconstw;

        extern vm::handler::profile_t lconstbzxw;
        extern vm::handler::profile_t lconstbsxdw;
        extern vm::handler::profile_t lconstbsxq;
        extern vm::handler::profile_t lconstdwsxq;
        extern vm::handler::profile_t lconstwsxq;
        extern vm::handler::profile_t lconstwsxdw;

        extern vm::handler::profile_t addq;
        extern vm::handler::profile_t adddw;
        extern vm::handler::profile_t addw;
        extern vm::handler::profile_t addb;

        extern vm::handler::profile_t shlq;
        extern vm::handler::profile_t shldw;
        extern vm::handler::profile_t shlw;
        extern vm::handler::profile_t shlb;

        extern vm::handler::profile_t shldq;
        extern vm::handler::profile_t shlddw;

        extern vm::handler::profile_t nandq;
        extern vm::handler::profile_t nanddw;
        extern vm::handler::profile_t nandw;
        extern vm::handler::profile_t nandb;

        extern vm::handler::profile_t writeq;
        extern vm::handler::profile_t writedw;
        extern vm::handler::profile_t writew;
        extern vm::handler::profile_t writeb;

        extern vm::handler::profile_t readq;
        extern vm::handler::profile_t readgsq;
        extern vm::handler::profile_t readdw;
        extern vm::handler::profile_t readw;
        extern vm::handler::profile_t readb;

        extern vm::handler::profile_t shrq;
        extern vm::handler::profile_t shrdw;
        extern vm::handler::profile_t shrw;
        extern vm::handler::profile_t shrb;

        extern vm::handler::profile_t shrdq;
        extern vm::handler::profile_t shrddw;

        extern vm::handler::profile_t pushvspq;
        extern vm::handler::profile_t pushvspdw;
        extern vm::handler::profile_t pushvspw;

        extern vm::handler::profile_t lflagsq;
        extern vm::handler::profile_t call;

        extern vm::handler::profile_t mulq;
        extern vm::handler::profile_t muldw;

        extern vm::handler::profile_t imulq;
        extern vm::handler::profile_t imuldw;

        extern vm::handler::profile_t readcr8;
        extern vm::handler::profile_t readcr3;
        extern vm::handler::profile_t writecr3;

        extern vm::handler::profile_t divq;
        extern vm::handler::profile_t divdw;

        extern vm::handler::profile_t popvspq;
        extern vm::handler::profile_t popvspw;

        extern vm::handler::profile_t idivdw;
        extern vm::handler::profile_t jmp;
        extern vm::handler::profile_t rdtsc;
        extern vm::handler::profile_t vmexit;

        /// <summary>
        /// a vector of pointers to all defined vm handler profiles...
        /// </summary>
        inline std::vector< vm::handler::profile_t * > all = {
            &sregq,       &sregdw,     &sregw,       &sregb,      &lregq,       &lregdw,   &lconstq, &lconstbzxw,
            &lconstbsxdw, &lconstbsxq, &lconstdwsxq, &lconstwsxq, &lconstwsxdw, &lconstdw, &lconstw, &addq,
            &adddw,       &addw,       &addb,        &popvspq,    &popvspw,     &shlq,     &shldw,   &shlw,
            &shlb,        &writeq,     &writedw,     &writew,     &writeb,      &nandq,    &nanddw,  &nandw,
            &nandb,       &shlddw,     &shldq,       &shrq,       &shrdw,       &shrw,     &shrb,    &shrdq,
            &shrddw,      &readgsq,    &readq,       &readdw,     &readw,       &readb,    &mulq,    &muldw,
            &imulq,       &imuldw,     &pushvspq,    &pushvspdw,  &pushvspw,    &readcr8,  &readcr3, &writecr3,
            &divq,        &divdw,      &idivdw,      &jmp,        &lflagsq,     &vmexit,   &call,    &rdtsc };
    } // namespace profile
} // namespace vm::handler