// SPDX-License-Identifier: MIT
// PPC64LE instruction emitter for FEX JIT backend.
// Targets POWER8 (POWER ISA v2.07) in little-endian mode.
// All instructions are 4-byte fixed-width; we emit uint32_t words.
#pragma once

#include "Registers.h"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <vector>

namespace PPC64Emitter {

// ---------------------------------------------------------------------------
// Forward labels for branch fixup
// ---------------------------------------------------------------------------
struct Label {
  int64_t offset = -1;  // set when bound; -1 = unbound
  bool bound = false;
};

// ---------------------------------------------------------------------------
// Condition classes (mapped from FEX IR CondClass)
// A condition is encoded as (BO, BI) for a bc instruction.
// BI = CR_field*4 + bit; we always use CR0 (field 0).
// ---------------------------------------------------------------------------
struct Cond {
  uint32_t BO;
  uint32_t BI;  // relative to CR field used (0-3)
};

// BO encodings for bc:
// BO=12, BI=LT : branch if CR.LT set
// BO=4,  BI=LT : branch if CR.LT not set
// BO=12, BI=GT : branch if CR.GT set
// BO=4,  BI=GT : branch if CR.GT not set
// BO=12, BI=EQ : branch if CR.EQ set  (BEQ)
// BO=4,  BI=EQ : branch if CR.EQ not set (BNE)
// BO=20         : branch always

// Condition codes for use with our compare conventions.
// We store the result in CR0 after compare instructions.
static constexpr Cond CC_EQ  = {12, 2};   // beq
static constexpr Cond CC_NE  = { 4, 2};   // bne
static constexpr Cond CC_LT  = {12, 0};   // blt  (signed less than)
static constexpr Cond CC_GE  = { 4, 0};   // bge  (signed >=)
static constexpr Cond CC_GT  = {12, 1};   // bgt  (signed >)
static constexpr Cond CC_LE  = { 4, 1};   // ble  (signed <=)
// Unsigned conditions use the same bits but after unsigned compare (cmpldi)
static constexpr Cond CC_ULT = {12, 0};   // blt after cmpldi
static constexpr Cond CC_UGE = { 4, 0};   // bge after cmpldi
static constexpr Cond CC_UGT = {12, 1};   // bgt after cmpldi
static constexpr Cond CC_ULE = { 4, 1};   // ble after cmpldi

static constexpr Cond InvertCond(Cond c) {
  // Invert bit 3 of BO to flip taken/not-taken
  return Cond{ c.BO ^ 8, c.BI };
}

// ---------------------------------------------------------------------------
// Relocation entry: a position in the code buffer that needs patching
// ---------------------------------------------------------------------------
struct PendingBranch {
  int64_t patch_offset;  // byte offset in code buffer of the instruction
  Label*  target;
};

// ---------------------------------------------------------------------------
// Emitter class
// ---------------------------------------------------------------------------
class Emitter {
public:
  Emitter() = default;
  Emitter(uint8_t* buf, size_t size) : Buffer(buf), BufferSize(size), Offset(0) {}

  void SetBuffer(uint8_t* buf, size_t size) {
    Buffer = buf;
    BufferSize = size;
    Offset = 0;
  }

  uint8_t* GetCursorAddress() const { return Buffer + Offset; }
  uint8_t* GetBufferBase()    const { return Buffer; }
  size_t   GetOffset()        const { return Offset; }

  // Return current cursor as typed pointer
  template<typename T>
  T GetCursorAddress() const { return reinterpret_cast<T>(Buffer + Offset); }

  // Bind a label to the current position
  void Bind(Label* lbl) {
    lbl->offset = static_cast<int64_t>(Offset);
    lbl->bound  = true;
    PatchPending(lbl);
  }

  // Drop any unbound forward-branch fixups. Called between compilations so
  // stale Label* pointers from a finished compile don't survive into the next.
  void ClearPendingBranches() { PendingBranches.clear(); }

  // -------------------------------------------------------------------------
  // Raw word emission
  // -------------------------------------------------------------------------
  void Emit32(uint32_t insn) {
    assert(Offset + 4 <= BufferSize && "Code buffer overflow");
    memcpy(Buffer + Offset, &insn, 4);
    Offset += 4;
  }

  void dc64(uint64_t v) {
    assert(Offset + 8 <= BufferSize && "Code buffer overflow");
    memcpy(Buffer + Offset, &v, 8);
    Offset += 8;
  }

  void nop() { Emit32(0x60000000u); }  // ori r0, r0, 0

  // =========================================================================
  // Integer ALU
  // =========================================================================

  // add RT, RA, RB  (XO-form, opcode 31, XO 266)
  void add(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 266, 0); }
  void add_(GPR rt, GPR ra, GPR rb) { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 266, 1); }  // sets CR0

  // addo  (add with overflow exception recording)
  void addo(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 1, 266, 0); }
  void addo_(GPR rt, GPR ra, GPR rb) { EmitXO(31, rt.idx, ra.idx, rb.idx, 1, 266, 1); }

  // addi RT, RA, SI   (D-form, opcode 14; if RA=0, li RT,SI)
  void addi(GPR rt, GPR ra, int16_t si)  { EmitD(14, rt.idx, ra.idx, static_cast<uint16_t>(si)); }
  void li(GPR rt, int16_t si)             { addi(rt, GPRegs::r0, si); }

  // addis RT, RA, SI  (D-form, opcode 15; lis if RA=0)
  void addis(GPR rt, GPR ra, int16_t si) { EmitD(15, rt.idx, ra.idx, static_cast<uint16_t>(si)); }
  void lis(GPR rt, int16_t si)           { addis(rt, GPRegs::r0, si); }

  // addic RT, RA, SI   (adds and records carry, opcode 12)
  void addic(GPR rt, GPR ra, int16_t si)  { EmitD(12, rt.idx, ra.idx, static_cast<uint16_t>(si)); }
  void addic_(GPR rt, GPR ra, int16_t si) { EmitD(13, rt.idx, ra.idx, static_cast<uint16_t>(si)); }

  // addc RT, RA, RB (add carrying, XO 10) — sets XER.CA
  void addc(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 10, 0); }
  void addc_(GPR rt, GPR ra, GPR rb) { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 10, 1); }   // + CR0
  // addco. — addc with overflow recording: sets CA + SO/OV + CR0
  void addco(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 1, 10, 0); }
  void addco_(GPR rt, GPR ra, GPR rb) { EmitXO(31, rt.idx, ra.idx, rb.idx, 1, 10, 1); }

  // adde RT, RA, RB (add extended = add with carry-in, XO 138)
  void adde(GPR rt, GPR ra, GPR rb) { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 138, 0); }
  void adde_(GPR rt, GPR ra, GPR rb){ EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 138, 1); }
  // addeo. — adde + OV recording: sets CA + SO/OV + CR0
  void addeo_(GPR rt, GPR ra, GPR rb){ EmitXO(31, rt.idx, ra.idx, rb.idx, 1, 138, 1); }

  // addme RT, RA (add to minus one extended, XO 234)
  void addme(GPR rt, GPR ra) { EmitXO(31, rt.idx, ra.idx, 0, 0, 234, 0); }

  // addze RT, RA (add to zero extended, XO 202)
  void addze(GPR rt, GPR ra) { EmitXO(31, rt.idx, ra.idx, 0, 0, 202, 0); }

  // subf RT, RA, RB  (subtract from: RT = RB - RA, XO 40)
  void subf(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 40, 0); }
  void subf_(GPR rt, GPR ra, GPR rb) { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 40, 1); }
  void subfo_(GPR rt, GPR ra, GPR rb){ EmitXO(31, rt.idx, ra.idx, rb.idx, 1, 40, 1); }

  // subfic RT, RA, SI (opcode 8)
  void subfic(GPR rt, GPR ra, int16_t si) { EmitD(8, rt.idx, ra.idx, static_cast<uint16_t>(si)); }

  // subfc RT, RA, RB (subtract from carrying, XO 8) — sets XER.CA
  void subfc(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 8, 0); }
  void subfc_(GPR rt, GPR ra, GPR rb) { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 8, 1); }   // + CR0
  // subfco. — subfc with overflow recording: sets CA + SO/OV + CR0
  void subfco(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 1, 8, 0); }
  void subfco_(GPR rt, GPR ra, GPR rb) { EmitXO(31, rt.idx, ra.idx, rb.idx, 1, 8, 1); }

  // subfe RT, RA, RB (subtract from extended, XO 136)
  void subfe(GPR rt, GPR ra, GPR rb) { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 136, 0); }
  void subfe_(GPR rt, GPR ra, GPR rb){ EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 136, 1); }   // + CR0
  // subfeo. — subfe + OV recording: sets CA + SO/OV + CR0
  void subfeo_(GPR rt, GPR ra, GPR rb){ EmitXO(31, rt.idx, ra.idx, rb.idx, 1, 136, 1); }

  // subfze RT, RA (subtract from zero extended, XO 200)
  void subfze(GPR rt, GPR ra) { EmitXO(31, rt.idx, ra.idx, 0, 0, 200, 0); }

  // neg RT, RA (XO 104)
  void neg(GPR rt, GPR ra)  { EmitXO(31, rt.idx, ra.idx, 0, 0, 104, 0); }
  void neg_(GPR rt, GPR ra) { EmitXO(31, rt.idx, ra.idx, 0, 0, 104, 1); }
  void nego_(GPR rt, GPR ra){ EmitXO(31, rt.idx, ra.idx, 0, 1, 104, 1); }

  // mulli RT, RA, SI (opcode 7)
  void mulli(GPR rt, GPR ra, int16_t si) { EmitD(7, rt.idx, ra.idx, static_cast<uint16_t>(si)); }

  // mullw RT, RA, RB (multiply low word, XO 235)
  void mullw(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 235, 0); }
  void mullw_(GPR rt, GPR ra, GPR rb) { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 235, 1); }

  // mulld RT, RA, RB (multiply low doubleword, XO 233)
  void mulld(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 233, 0); }
  void mulld_(GPR rt, GPR ra, GPR rb) { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 233, 1); }

  // mulhd RT, RA, RB (multiply high doubleword signed, XO 73)
  void mulhd(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 73, 0); }

  // mulhdu RT, RA, RB (multiply high doubleword unsigned, XO 9)
  void mulhdu(GPR rt, GPR ra, GPR rb) { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 9, 0); }

  // mulhw RT, RA, RB (multiply high word signed, XO 75)
  void mulhw(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 75, 0); }

  // mulhwu RT, RA, RB (multiply high word unsigned, XO 11)
  void mulhwu(GPR rt, GPR ra, GPR rb) { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 11, 0); }

  // divd RT, RA, RB (divide doubleword signed, XO 489)
  void divd(GPR rt, GPR ra, GPR rb)   { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 489, 0); }
  void divd_(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 489, 1); }

  // divdu RT, RA, RB (divide doubleword unsigned, XO 457)
  void divdu(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 457, 0); }
  void divdu_(GPR rt, GPR ra, GPR rb) { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 457, 1); }

  // divdeu/divde RT, RA, RB (POWER8+ extended divide, XO 393/425).
  // Computes (RA << 64) / RB and is paired with divdu for 128/64 long-division.
  void divdeu(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 393, 0); }
  void divdeu_(GPR rt, GPR ra, GPR rb) { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 393, 1); }
  void divde(GPR rt, GPR ra, GPR rb)   { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 425, 0); }
  void divde_(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 425, 1); }

  // divw RT, RA, RB (divide word signed, XO 491)
  void divw(GPR rt, GPR ra, GPR rb)   { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 491, 0); }

  // divwu RT, RA, RB (divide word unsigned, XO 459)
  void divwu(GPR rt, GPR ra, GPR rb)  { EmitXO(31, rt.idx, ra.idx, rb.idx, 0, 459, 0); }

  // =========================================================================
  // Logical instructions (X-form: note RA=dest, RS=src1)
  // =========================================================================

  // and RA, RS, RB  (XO 28, dest is RA)
  void and_(GPR ra, GPR rs, GPR rb)  { EmitX(31, rs.idx, ra.idx, rb.idx, 28, 0); }
  void and__(GPR ra, GPR rs, GPR rb) { EmitX(31, rs.idx, ra.idx, rb.idx, 28, 1); }

  // andc RA, RS, RB (RA = RS & ~RB, XO 60)
  void andc(GPR ra, GPR rs, GPR rb)  { EmitX(31, rs.idx, ra.idx, rb.idx, 60, 0); }

  // or RA, RS, RB (XO 444)
  void or_(GPR ra, GPR rs, GPR rb)  { EmitX(31, rs.idx, ra.idx, rb.idx, 444, 0); }
  void or__(GPR ra, GPR rs, GPR rb) { EmitX(31, rs.idx, ra.idx, rb.idx, 444, 1); }

  // orc RA, RS, RB (RA = RS | ~RB, XO 412)
  void orc(GPR ra, GPR rs, GPR rb)  { EmitX(31, rs.idx, ra.idx, rb.idx, 412, 0); }

  // mr RA, RS (move register: or RA, RS, RS)
  void mr(GPR ra, GPR rs) { or_(ra, rs, rs); }

  // xor RA, RS, RB (XO 316)
  void xor_(GPR ra, GPR rs, GPR rb)  { EmitX(31, rs.idx, ra.idx, rb.idx, 316, 0); }
  void xor__(GPR ra, GPR rs, GPR rb) { EmitX(31, rs.idx, ra.idx, rb.idx, 316, 1); }

  // nor RA, RS, RB (XO 124)
  void nor(GPR ra, GPR rs, GPR rb)  { EmitX(31, rs.idx, ra.idx, rb.idx, 124, 0); }

  // nand RA, RS, RB (XO 476)
  void nand_(GPR ra, GPR rs, GPR rb) { EmitX(31, rs.idx, ra.idx, rb.idx, 476, 0); }

  // eqv RA, RS, RB (XO 284)
  void eqv(GPR ra, GPR rs, GPR rb)  { EmitX(31, rs.idx, ra.idx, rb.idx, 284, 0); }

  // not RA, RS (nor RA, RS, RS)
  void not_(GPR ra, GPR rs) { nor(ra, rs, rs); }

  // ori RA, RS, UI  (opcode 24)
  void ori(GPR ra, GPR rs, uint16_t ui) { EmitD(24, rs.idx, ra.idx, ui); }

  // oris RA, RS, UI  (opcode 25)
  void oris(GPR ra, GPR rs, uint16_t ui) { EmitD(25, rs.idx, ra.idx, ui); }

  // xori RA, RS, UI  (opcode 26)
  void xori(GPR ra, GPR rs, uint16_t ui) { EmitD(26, rs.idx, ra.idx, ui); }

  // xoris RA, RS, UI  (opcode 27)
  void xoris(GPR ra, GPR rs, uint16_t ui) { EmitD(27, rs.idx, ra.idx, ui); }

  // andi. RA, RS, UI  (opcode 28, always sets CR0)
  void andi_(GPR ra, GPR rs, uint16_t ui) { EmitD(28, rs.idx, ra.idx, ui); }

  // andis. RA, RS, UI  (opcode 29)
  void andis_(GPR ra, GPR rs, uint16_t ui) { EmitD(29, rs.idx, ra.idx, ui); }

  // =========================================================================
  // Shifts and rotate
  // =========================================================================

  // slw RA, RS, RB  (shift left word, XO 24)
  void slw(GPR ra, GPR rs, GPR rb)  { EmitX(31, rs.idx, ra.idx, rb.idx, 24, 0); }

  // srw RA, RS, RB  (shift right word logical, XO 536)
  void srw(GPR ra, GPR rs, GPR rb)  { EmitX(31, rs.idx, ra.idx, rb.idx, 536, 0); }

  // sraw RA, RS, RB  (shift right word algebraic, XO 792)
  void sraw(GPR ra, GPR rs, GPR rb) { EmitX(31, rs.idx, ra.idx, rb.idx, 792, 0); }

  // sld RA, RS, RB  (shift left doubleword, XO 27)
  void sld(GPR ra, GPR rs, GPR rb)  { EmitX(31, rs.idx, ra.idx, rb.idx, 27, 0); }

  // srd RA, RS, RB  (shift right doubleword logical, XO 539)
  void srd(GPR ra, GPR rs, GPR rb)  { EmitX(31, rs.idx, ra.idx, rb.idx, 539, 0); }

  // srad RA, RS, RB  (shift right doubleword algebraic, XO 794)
  void srad(GPR ra, GPR rs, GPR rb) { EmitX(31, rs.idx, ra.idx, rb.idx, 794, 0); }

  // srawi RA, RS, SH  (shift right word algebraic immediate, XO 824)
  void srawi(GPR ra, GPR rs, uint32_t sh) {
    assert(sh < 32);
    EmitX(31, rs.idx, ra.idx, sh, 824, 0);
  }
  void srawi_(GPR ra, GPR rs, uint32_t sh) {
    assert(sh < 32);
    EmitX(31, rs.idx, ra.idx, sh, 824, 1);
  }

  // sradi RA, RS, SH  (shift right algebraic doubleword immediate, XO 413)
  // Encoding is special: SH field spans 5 bits plus 1 extra bit at bit position 30
  void sradi(GPR ra, GPR rs, uint32_t sh) {
    assert(sh < 64);
    // Format: op=31 | RS | RA | sh(low5) | XO=413 | sh(bit5) | Rc=0
    // XO=413 occupies bits [21:29] but the extra SH bit is at bit 30
    // Standard XO encoding would put XO in bits [22:30], but sradi is different:
    // It's at bits [21:29] = 413 >> 1 and the extra sh bit is at bit 30 (= 413 & 1)
    // Let me look at the exact encoding:
    // sradi: primary opcode 31, bits[21:30]=0b1100111010 = 826, Rc at bit 31
    // Wait, sradi XO is 413 but in the 10-bit XO field it's:
    // XO field bits [21:30]: 413 = 0b110011101 (9 bits) but the top bit is the extra SH bit
    // Actually: bits[21:29] = 413 (for sradi), bits[30] = sh>>5, bit[31]=Rc
    uint32_t sh_low = sh & 0x1F;
    uint32_t sh_high = (sh >> 5) & 1;
    Emit32((31u << 26) | (rs.idx << 21) | (ra.idx << 16) | (sh_low << 11) |
           (413u << 2) | (sh_high << 1) | 0u);
  }
  void sradi_(GPR ra, GPR rs, uint32_t sh) {
    assert(sh < 64);
    uint32_t sh_low = sh & 0x1F;
    uint32_t sh_high = (sh >> 5) & 1;
    Emit32((31u << 26) | (rs.idx << 21) | (ra.idx << 16) | (sh_low << 11) |
           (413u << 2) | (sh_high << 1) | 1u);
  }

  // rlwinm RA, RS, SH, MB, ME  (rotate left word immediate and mask, opcode 21)
  void rlwinm(GPR ra, GPR rs, uint32_t sh, uint32_t mb, uint32_t me) {
    assert(sh < 32 && mb < 32 && me < 32);
    EmitM(21, rs.idx, ra.idx, sh, mb, me, 0);
  }
  void rlwinm_(GPR ra, GPR rs, uint32_t sh, uint32_t mb, uint32_t me) {
    EmitM(21, rs.idx, ra.idx, sh, mb, me, 1);
  }

  // rlwimi RA, RS, SH, MB, ME  (rotate left word immediate then mask insert, opcode 20)
  void rlwimi(GPR ra, GPR rs, uint32_t sh, uint32_t mb, uint32_t me) {
    EmitM(20, rs.idx, ra.idx, sh, mb, me, 0);
  }

  // rlwnm RA, RS, RB, MB, ME  (rotate left word then and mask, opcode 23)
  void rlwnm(GPR ra, GPR rs, GPR rb, uint32_t mb, uint32_t me) {
    assert(mb < 32 && me < 32);
    Emit32((23u << 26) | (rs.idx << 21) | (ra.idx << 16) | (rb.idx << 11) | (mb << 6) | (me << 1) | 0u);
  }

  // rldicl RA, RS, SH, MB  (rotate left doubleword then clear left, opcode 30, XO=0)
  void rldicl(GPR ra, GPR rs, uint32_t sh, uint32_t mb) {
    assert(sh < 64 && mb < 64);
    EmitMD(rs.idx, ra.idx, sh, mb, 0, 0);
  }
  void rldicl_(GPR ra, GPR rs, uint32_t sh, uint32_t mb) {
    assert(sh < 64 && mb < 64);
    EmitMD(rs.idx, ra.idx, sh, mb, 0, 1);
  }

  // rldicr RA, RS, SH, ME  (rotate left doubleword then clear right, opcode 30, XO=1)
  void rldicr(GPR ra, GPR rs, uint32_t sh, uint32_t me) {
    assert(sh < 64 && me < 64);
    EmitMD(rs.idx, ra.idx, sh, me, 1, 0);
  }

  // rldic RA, RS, SH, MB  (opcode 30, XO=2)
  void rldic(GPR ra, GPR rs, uint32_t sh, uint32_t mb) {
    EmitMD(rs.idx, ra.idx, sh, mb, 2, 0);
  }

  // rldimi RA, RS, SH, MB  (opcode 30, XO=3)
  void rldimi(GPR ra, GPR rs, uint32_t sh, uint32_t mb) {
    EmitMD(rs.idx, ra.idx, sh, mb, 3, 0);
  }

  // MDS-form (Power ISA 2.07 §1.6.1.7): op=30 | RS | RA | RB | m[1:5] | m[0] | XO(4) | Rc
  // BE bit positions:    0:5 |  6:10 | 11:15 | 16:20 | 21:25 | 26 | 27:30 | 31
  // LE bit positions:   31:26| 25:21 | 20:16 | 15:11 | 10:6  |  5 |  4:1  |  0
  // rldcl RA, RS, RB, MB (rotate left doubleword then clear left by RB, opcode 30, XO=8)
  void rldcl(GPR ra, GPR rs, GPR rb, uint32_t mb) {
    assert(mb < 64);
    uint32_t mb_high = (mb >> 5) & 1;
    uint32_t mb_low  = mb & 0x1F;
    Emit32((30u << 26) | (rs.idx << 21) | (ra.idx << 16) | (rb.idx << 11) |
           (mb_low << 6) | (mb_high << 5) | (8u << 1) | 0u);
  }

  // rldcr RA, RS, RB, ME (opcode 30, XO=9)
  void rldcr(GPR ra, GPR rs, GPR rb, uint32_t me) {
    assert(me < 64);
    uint32_t me_high = (me >> 5) & 1;
    uint32_t me_low  = me & 0x1F;
    Emit32((30u << 26) | (rs.idx << 21) | (ra.idx << 16) | (rb.idx << 11) |
           (me_low << 6) | (me_high << 5) | (9u << 1) | 0u);
  }

  // Pseudo-instructions for shifts
  // sldi RA, RS, n = rldicr RA, RS, n, 63-n
  void sldi(GPR ra, GPR rs, uint32_t n) { assert(n < 64); rldicr(ra, rs, n, 63 - n); }

  // srdi RA, RS, n = rldicl RA, RS, 64-n, n
  void srdi(GPR ra, GPR rs, uint32_t n) { assert(n > 0 && n < 64); rldicl(ra, rs, 64 - n, n); }

  // clrldi RA, RS, n = rldicl RA, RS, 0, n  (clear high n bits)
  void clrldi(GPR ra, GPR rs, uint32_t n) { assert(n < 64); rldicl(ra, rs, 0, n); }
  // clrrdi RA, RS, n = rldicr RA, RS, 0, 63-n  (clear low n bits)
  void clrrdi(GPR ra, GPR rs, uint32_t n) { assert(n < 64); rldicr(ra, rs, 0, 63 - n); }

  // extsb RA, RS (extend byte sign, XO 954)
  void extsb(GPR ra, GPR rs) { EmitX(31, rs.idx, ra.idx, 0, 954, 0); }

  // extsh RA, RS (extend halfword sign, XO 922)
  void extsh(GPR ra, GPR rs) { EmitX(31, rs.idx, ra.idx, 0, 922, 0); }

  // extsw RA, RS (extend word sign, XO 986)
  void extsw(GPR ra, GPR rs) { EmitX(31, rs.idx, ra.idx, 0, 986, 0); }

  // cntlzw RA, RS (count leading zeros word, XO 26)
  void cntlzw(GPR ra, GPR rs) { EmitX(31, rs.idx, ra.idx, 0, 26, 0); }

  // cntlzd RA, RS (count leading zeros doubleword, XO 58)
  void cntlzd(GPR ra, GPR rs) { EmitX(31, rs.idx, ra.idx, 0, 58, 0); }

  // popcntw RA, RS (population count words, XO 378)
  void popcntw(GPR ra, GPR rs) { EmitX(31, rs.idx, ra.idx, 0, 378, 0); }

  // popcntd RA, RS (population count doubleword, XO 506)
  void popcntd(GPR ra, GPR rs) { EmitX(31, rs.idx, ra.idx, 0, 506, 0); }

  // prtyd RA, RS (parity doubleword, XO 186)
  void prtyd(GPR ra, GPR rs) { EmitX(31, rs.idx, ra.idx, 0, 186, 0); }

  // bpermd RA, RS, RB (bit permute doubleword, XO 252, POWER7+)
  void bpermd(GPR ra, GPR rs, GPR rb) { EmitX(31, rs.idx, ra.idx, rb.idx, 252, 0); }

  // =========================================================================
  // Compare
  // =========================================================================

  // cmpdi BF, RA, SI  (compare doubleword immediate signed, opcode 11, L=1)
  void cmpdi(CRField bf, GPR ra, int16_t si) {
    Emit32((11u << 26) | (bf.idx << 23) | (1u << 21) | (ra.idx << 16) |
           (static_cast<uint16_t>(si)));
  }

  // cmpwi BF, RA, SI  (compare word immediate signed, opcode 11, L=0)
  void cmpwi(CRField bf, GPR ra, int16_t si) {
    Emit32((11u << 26) | (bf.idx << 23) | (0u << 21) | (ra.idx << 16) |
           (static_cast<uint16_t>(si)));
  }

  // cmpldi BF, RA, UI  (compare logical doubleword immediate, opcode 10, L=1)
  void cmpldi(CRField bf, GPR ra, uint16_t ui) {
    Emit32((10u << 26) | (bf.idx << 23) | (1u << 21) | (ra.idx << 16) | ui);
  }

  // cmplwi BF, RA, UI  (compare logical word immediate, opcode 10, L=0)
  void cmplwi(CRField bf, GPR ra, uint16_t ui) {
    Emit32((10u << 26) | (bf.idx << 23) | (0u << 21) | (ra.idx << 16) | ui);
  }

  // cmpd BF, RA, RB  (compare doubleword, opcode 31, XO 0, L=1)
  void cmpd(CRField bf, GPR ra, GPR rb) {
    Emit32((31u << 26) | (bf.idx << 23) | (1u << 21) | (ra.idx << 16) | (rb.idx << 11) | (0u << 1));
  }

  // cmpw BF, RA, RB  (compare word, opcode 31, XO 0, L=0)
  void cmpw(CRField bf, GPR ra, GPR rb) {
    Emit32((31u << 26) | (bf.idx << 23) | (0u << 21) | (ra.idx << 16) | (rb.idx << 11) | (0u << 1));
  }

  // cmpld BF, RA, RB  (compare logical doubleword, opcode 31, XO 32, L=1)
  void cmpld(CRField bf, GPR ra, GPR rb) {
    Emit32((31u << 26) | (bf.idx << 23) | (1u << 21) | (ra.idx << 16) | (rb.idx << 11) | (32u << 1));
  }

  // cmplw BF, RA, RB  (compare logical word, opcode 31, XO 32, L=0)
  void cmplw(CRField bf, GPR ra, GPR rb) {
    Emit32((31u << 26) | (bf.idx << 23) | (0u << 21) | (ra.idx << 16) | (rb.idx << 11) | (32u << 1));
  }

  // Default compare to CR0
  void cmpdi(GPR ra, int16_t si)  { cmpdi(cr(0), ra, si); }
  void cmpwi(GPR ra, int16_t si)  { cmpwi(cr(0), ra, si); }
  void cmpldi(GPR ra, uint16_t ui){ cmpldi(cr(0), ra, ui); }
  void cmpd(GPR ra, GPR rb)       { cmpd(cr(0), ra, rb); }
  void cmpw(GPR ra, GPR rb)       { cmpw(cr(0), ra, rb); }
  void cmpld(GPR ra, GPR rb)      { cmpld(cr(0), ra, rb); }
  void cmplw(GPR ra, GPR rb)      { cmplw(cr(0), ra, rb); }

  // =========================================================================
  // Condition register operations
  // =========================================================================

  // crand BT, BA, BB  (XO 257, opcode 19)
  void crand(uint32_t bt, uint32_t ba, uint32_t bb) {
    Emit32((19u << 26) | (bt << 21) | (ba << 16) | (bb << 11) | (257u << 1));
  }

  // cror BT, BA, BB  (XO 449)
  void cror(uint32_t bt, uint32_t ba, uint32_t bb) {
    Emit32((19u << 26) | (bt << 21) | (ba << 16) | (bb << 11) | (449u << 1));
  }

  // crxor BT, BA, BB  (XO 193)
  void crxor(uint32_t bt, uint32_t ba, uint32_t bb) {
    Emit32((19u << 26) | (bt << 21) | (ba << 16) | (bb << 11) | (193u << 1));
  }

  // crnot BT, BA = crxor BT, BA, BA
  void crnot(uint32_t bt, uint32_t ba) { crxor(bt, ba, ba); }

  // crmove BT, BA = cror BT, BA, BA
  void crmove(uint32_t bt, uint32_t ba) { cror(bt, ba, ba); }

  // crset BT = cror BT, BT, BT (sets bit in CR)
  void crset(uint32_t bt) { cror(bt, bt, bt); }

  // crnand BT, BA, BB  (XO 225)
  void crnand(uint32_t bt, uint32_t ba, uint32_t bb) {
    Emit32((19u << 26) | (bt << 21) | (ba << 16) | (bb << 11) | (225u << 1));
  }

  // crandc BT, BA, BB  (XO 129)
  void crandc(uint32_t bt, uint32_t ba, uint32_t bb) {
    Emit32((19u << 26) | (bt << 21) | (ba << 16) | (bb << 11) | (129u << 1));
  }

  // mfcr RT  (move from condition register, XO 19)
  void mfcr(GPR rt) { Emit32((31u << 26) | (rt.idx << 21) | (19u << 1)); }

  // mfocrf RT, FXM  (move from one condition register field, XO 19 with bit 20 set)
  void mfocrf(GPR rt, uint32_t fxm) {
    Emit32((31u << 26) | (rt.idx << 21) | (1u << 20) | (fxm << 12) | (19u << 1));
  }

  // mtcrf FXM, RS  (move to condition register fields, XO 144)
  void mtcrf(uint32_t fxm, GPR rs) {
    Emit32((31u << 26) | (rs.idx << 21) | (fxm << 12) | (144u << 1));
  }

  // mtcr RS = mtcrf 0xFF, RS
  void mtcr(GPR rs) { mtcrf(0xFF, rs); }

  // =========================================================================
  // Load/Store (D-form and DS-form)
  // =========================================================================

  // lbz RT, D(RA)  (load byte and zero, opcode 34)
  void lbz(GPR rt, int16_t d, GPR ra)  { EmitD(34, rt.idx, ra.idx, static_cast<uint16_t>(d)); }

  // lhz RT, D(RA)  (load halfword and zero, opcode 40)
  void lhz(GPR rt, int16_t d, GPR ra)  { EmitD(40, rt.idx, ra.idx, static_cast<uint16_t>(d)); }

  // lha RT, D(RA)  (load halfword algebraic, opcode 42)
  void lha(GPR rt, int16_t d, GPR ra)  { EmitD(42, rt.idx, ra.idx, static_cast<uint16_t>(d)); }

  // lwz RT, D(RA)  (load word and zero, opcode 32)
  void lwz(GPR rt, int16_t d, GPR ra)  { EmitD(32, rt.idx, ra.idx, static_cast<uint16_t>(d)); }

  // lwa RT, DS(RA)  (load word algebraic, DS-form, opcode 58, XO 2)
  void lwa(GPR rt, int16_t ds, GPR ra) {
    assert((ds & 3) == 0 && "LWA displacement must be 4-byte aligned");
    Emit32((58u << 26) | (rt.idx << 21) | (ra.idx << 16) | (static_cast<uint16_t>(ds) & 0xFFFC) | 2u);
  }

  // ld RT, DS(RA)  (load doubleword, DS-form, opcode 58, XO 0)
  void ld(GPR rt, int16_t ds, GPR ra) {
    assert((ds & 3) == 0 && "LD displacement must be 4-byte aligned");
    Emit32((58u << 26) | (rt.idx << 21) | (ra.idx << 16) | (static_cast<uint16_t>(ds) & 0xFFFC) | 0u);
  }

  // ldu RT, DS(RA)  (load doubleword with update, DS-form, XO 1)
  void ldu(GPR rt, int16_t ds, GPR ra) {
    assert((ds & 3) == 0);
    Emit32((58u << 26) | (rt.idx << 21) | (ra.idx << 16) | (static_cast<uint16_t>(ds) & 0xFFFC) | 1u);
  }

  // stb RS, D(RA)  (store byte, opcode 38)
  void stb(GPR rs, int16_t d, GPR ra)  { EmitD(38, rs.idx, ra.idx, static_cast<uint16_t>(d)); }

  // sth RS, D(RA)  (store halfword, opcode 44)
  void sth(GPR rs, int16_t d, GPR ra)  { EmitD(44, rs.idx, ra.idx, static_cast<uint16_t>(d)); }

  // stw RS, D(RA)  (store word, opcode 36)
  void stw(GPR rs, int16_t d, GPR ra)  { EmitD(36, rs.idx, ra.idx, static_cast<uint16_t>(d)); }

  // std RS, DS(RA)  (store doubleword, DS-form, opcode 62, XO 0)
  void std(GPR rs, int16_t ds, GPR ra) {
    assert((ds & 3) == 0 && "STD displacement must be 4-byte aligned");
    Emit32((62u << 26) | (rs.idx << 21) | (ra.idx << 16) | (static_cast<uint16_t>(ds) & 0xFFFC) | 0u);
  }

  // stdu RS, DS(RA)  (store doubleword with update, XO 1)
  void stdu(GPR rs, int16_t ds, GPR ra) {
    assert((ds & 3) == 0);
    Emit32((62u << 26) | (rs.idx << 21) | (ra.idx << 16) | (static_cast<uint16_t>(ds) & 0xFFFC) | 1u);
  }

  // =========================================================================
  // Indexed Load/Store (X-form)
  // =========================================================================

  void lbzx(GPR rt, GPR ra, GPR rb)  { EmitX(31, rt.idx, ra.idx, rb.idx, 87,  0); }
  void lhzx(GPR rt, GPR ra, GPR rb)  { EmitX(31, rt.idx, ra.idx, rb.idx, 279, 0); }
  void lhax(GPR rt, GPR ra, GPR rb)  { EmitX(31, rt.idx, ra.idx, rb.idx, 343, 0); }
  void lwzx(GPR rt, GPR ra, GPR rb)  { EmitX(31, rt.idx, ra.idx, rb.idx, 23,  0); }
  void lwax(GPR rt, GPR ra, GPR rb)  { EmitX(31, rt.idx, ra.idx, rb.idx, 341, 0); }
  void ldx(GPR rt, GPR ra, GPR rb)   { EmitX(31, rt.idx, ra.idx, rb.idx, 21,  0); }
  void stbx(GPR rs, GPR ra, GPR rb)  { EmitX(31, rs.idx, ra.idx, rb.idx, 215, 0); }
  void sthx(GPR rs, GPR ra, GPR rb)  { EmitX(31, rs.idx, ra.idx, rb.idx, 407, 0); }
  void stwx(GPR rs, GPR ra, GPR rb)  { EmitX(31, rs.idx, ra.idx, rb.idx, 151, 0); }
  void stdx(GPR rs, GPR ra, GPR rb)  { EmitX(31, rs.idx, ra.idx, rb.idx, 149, 0); }

  // Byte-reversed loads (lhbrx, lwbrx, ldbrx) — big-endian in memory
  void lhbrx(GPR rt, GPR ra, GPR rb) { EmitX(31, rt.idx, ra.idx, rb.idx, 790, 0); }
  void lwbrx(GPR rt, GPR ra, GPR rb) { EmitX(31, rt.idx, ra.idx, rb.idx, 534, 0); }
  void ldbrx(GPR rt, GPR ra, GPR rb) { EmitX(31, rt.idx, ra.idx, rb.idx, 532, 0); }
  void sthbrx(GPR rs, GPR ra, GPR rb){ EmitX(31, rs.idx, ra.idx, rb.idx, 918, 0); }
  void stwbrx(GPR rs, GPR ra, GPR rb){ EmitX(31, rs.idx, ra.idx, rb.idx, 662, 0); }
  void stdbrx(GPR rs, GPR ra, GPR rb){ EmitX(31, rs.idx, ra.idx, rb.idx, 660, 0); }

  // =========================================================================
  // Floating-point load/store (D-form and X-form)
  // =========================================================================
  void lfs(FPR frt, int16_t d, GPR ra) { EmitD(48, frt.idx, ra.idx, static_cast<uint16_t>(d)); }
  void lfd(FPR frt, int16_t d, GPR ra) { EmitD(50, frt.idx, ra.idx, static_cast<uint16_t>(d)); }
  void stfs(FPR frs, int16_t d, GPR ra){ EmitD(52, frs.idx, ra.idx, static_cast<uint16_t>(d)); }
  void stfd(FPR frs, int16_t d, GPR ra){ EmitD(54, frs.idx, ra.idx, static_cast<uint16_t>(d)); }
  void lfsx(FPR frt, GPR ra, GPR rb)   { EmitX(31, frt.idx, ra.idx, rb.idx, 535, 0); }
  void lfdx(FPR frt, GPR ra, GPR rb)   { EmitX(31, frt.idx, ra.idx, rb.idx, 599, 0); }
  void stfsx(FPR frs, GPR ra, GPR rb)  { EmitX(31, frs.idx, ra.idx, rb.idx, 663, 0); }
  void stfdx(FPR frs, GPR ra, GPR rb)  { EmitX(31, frs.idx, ra.idx, rb.idx, 727, 0); }

  // mffprd RT, FRS (move from FP register doubleword = mfvsrd)
  void mffprd(GPR rt, FPR frs) {
    // MFVSRD: op=31, XO=51, VRS=frs, RA=rt, RB=0
    Emit32((31u << 26) | (frs.idx << 21) | (rt.idx << 16) | (51u << 1));
  }

  // mtfprd FRT, RS (move to FP register doubleword = mtvsrd)
  void mtfprd(FPR frt, GPR rs) {
    // MTVSRD: op=31, XO=179
    Emit32((31u << 26) | (frt.idx << 21) | (rs.idx << 16) | (179u << 1));
  }

  // mtvsrd VRT, RS — MTVSRD with TX=1: targets AltiVec register (VR), not FPR
  // Encoding: op=31, VRT[4:0] in bits[25:21], RS in bits[20:16], XO=179, TX=1
  void mtvsrd(VR vrt, GPR rs) {
    Emit32((31u << 26) | (vrt.idx << 21) | (rs.idx << 16) | (179u << 1) | 1u);
  }

  // mfvsrd RT, VRS — MFVSRD with TX=1: sources AltiVec register (VR)
  void mfvsrd(GPR rt, VR vrs) {
    Emit32((31u << 26) | (vrs.idx << 21) | (rt.idx << 16) | (51u << 1) | 1u);
  }

  // ===== VSX XX3-form (Power ISA 2.07 §1.6.10) =====
  // Layout (LE word bits): bits 0:31
  //   bit 0     = TX
  //   bit 1     = BX
  //   bit 2     = AX
  //   bits 10:3 = XO (8 bits; some ops use a sub-field for DM/SHB/RM)
  //   bits 15:11= VRB low 5 bits
  //   bits 20:16= VRA low 5 bits
  //   bits 25:21= VRT low 5 bits
  //   bits 31:26= primary opcode = 60
  // VR registers map to VSX 32..63, so AX/BX/TX are always 1 when targeting VRs.
  void EmitXX3(uint32_t vrt, uint32_t vra, uint32_t vrb, uint32_t xo) {
    Emit32((60u << 26) | (vrt << 21) | (vra << 16) | (vrb << 11) |
           ((xo & 0xFFu) << 3) | 0x7u /* AX|BX|TX = all 1 for VR targets */);
  }

  // xxpermdi VRT, VRA, VRB, DM (POWER7+).  XO=10; DM goes in the XO field's bits 5:6.
  void xxpermdi(VR vrt, VR vra, VR vrb, uint32_t dm) {
    assert(dm < 4);
    EmitXX3(vrt.idx, vra.idx, vrb.idx, 10u | ((dm & 3u) << 5));
  }
  // xxsldwi VRT, VRA, VRB, SHW (POWER7+).  XO=2; SHW (shift in words) at XO bits 5:6.
  void xxsldwi(VR vrt, VR vra, VR vrb, uint32_t shw) {
    assert(shw < 4);
    EmitXX3(vrt.idx, vra.idx, vrb.idx, 2u | ((shw & 3u) << 5));
  }
  // xxsel VRT, VRA, VRB, VRC — bitwise vec_sel, POWER7+ VSX (XX4-form).
  // Layout adds VRC at bits 10:6 (overlapping with XO field), with CX bit at bit 3.
  void xxsel(VR vrt, VR vra, VR vrb, VR vrc) {
    Emit32((60u << 26) | (vrt.idx << 21) | (vra.idx << 16) | (vrb.idx << 11) |
           (vrc.idx << 6) | (3u << 4) /*XO=3 in XX4-form*/ |
           (1u << 3) /*CX*/ | 0x7u /*AX|BX|TX*/);
  }

  // ===== VSX scalar & vector FP arithmetic (XX3-form, primary 60) =====
  // Scalar single-precision (POWER8+)
  void xsaddsp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,   0); }
  void xssubsp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,   8); }
  void xsmulsp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  16); }
  void xsdivsp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  24); }
  // Scalar double-precision
  void xsadddp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  32); }
  void xssubdp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  40); }
  void xsmuldp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  48); }
  void xsdivdp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  56); }
  void xsmaxdp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 160); }
  void xsmindp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 168); }
  // Vector single-precision (XO = scalar+64)
  void xvaddsp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  64); }
  void xvsubsp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  72); }
  void xvmulsp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  80); }
  void xvdivsp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  88); }
  // Vector double-precision (XO = scalar+96)
  void xvadddp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  96); }
  void xvsubdp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 104); }
  void xvmuldp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 112); }
  void xvdivdp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 120); }
  // FMA family — XO is the base op's XO + 1.  T = T*A + B (a-form) or T*B + A (m-form, +2).
  // a-form: T = ±(T*A) ± B (T is multiplicand and accumulator)
  void xvmaddasp (VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  65); }
  void xvmsubasp (VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  81); }
  void xvnmaddasp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 193); }
  void xvnmsubasp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 209); }
  void xvmaddadp (VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  97); }
  void xvmsubadp (VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 113); }
  void xvnmaddadp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 225); }
  void xvnmsubadp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 241); }
  // m-form: T = ±(T*B) ± A (T is multiplicand, A is addend)
  void xvmaddmsp (VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  73); }
  void xvmsubmsp (VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  89); }
  void xvnmaddmsp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 201); }
  void xvnmsubmsp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 217); }
  void xvmaddmdp (VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 105); }
  void xvmsubmdp (VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 121); }
  void xvnmaddmdp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 233); }
  void xvnmsubmdp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 249); }
  // Bitwise VSX (XO = 144..168).  These overlap with vand/vxor but operate on 128-bit
  // VSX values directly without going through AltiVec.
  void xxlor  (VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 146); }
  void xxlxor (VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 154); }
  void xxland (VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 130); }
  void xxlandc(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 138); }
  void xxlnor (VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 162); }
  // Convert (XX2-form, single operand).  TX bit at LE bit 0; AX bit unused; BX at bit 1.
  void EmitXX2(uint32_t vrt, uint32_t vrb, uint32_t xo) {
    Emit32((60u << 26) | (vrt << 21) | (vrb << 11) | ((xo & 0x1FFu) << 2) |
           (1u << 1) /*BX*/ | 1u /*TX*/);
  }
  // XO field values for XX2 are taken straight from gas-emitted bytes (the
  // ISA-listed numbers in some books include extra bits and don't match the
  // 9-bit XO field at BE 21..29 directly).
  // f32→int truncate / int→f32 (vector single)
  void xvcvspsxws(VR t, VR b) { EmitXX2(t.idx, b.idx, 152); }
  void xvcvspuxws(VR t, VR b) { EmitXX2(t.idx, b.idx, 136); }
  void xvcvsxwsp (VR t, VR b) { EmitXX2(t.idx, b.idx, 184); }
  void xvcvuxwsp (VR t, VR b) { EmitXX2(t.idx, b.idx, 168); }
  // Scalar conversions
  void xscvdpsxws(VR t, VR b) { EmitXX2(t.idx, b.idx,  88); } // f64→i32 trunc signed
  void xscvdpsxds(VR t, VR b) { EmitXX2(t.idx, b.idx, 344); } // f64→i64 trunc signed
  void xscvsxdsp (VR t, VR b) { EmitXX2(t.idx, b.idx, 312); } // i64→f32
  void xscvuxdsp (VR t, VR b) { EmitXX2(t.idx, b.idx, 296); } // u64→f32
  void xscvsxddp (VR t, VR b) { EmitXX2(t.idx, b.idx, 376); } // i64→f64
  void xscvuxddp (VR t, VR b) { EmitXX2(t.idx, b.idx, 360); } // u64→f64
  void xscvspdp  (VR t, VR b) { EmitXX2(t.idx, b.idx, 329); } // f32→f64 scalar
  void xscvdpsp  (VR t, VR b) { EmitXX2(t.idx, b.idx, 265); } // f64→f32 scalar
  // Scalar / vector unary FP (sqrt / abs / neg)
  void xssqrtsp(VR t, VR b)  { EmitXX2(t.idx, b.idx,  11); }
  void xssqrtdp(VR t, VR b)  { EmitXX2(t.idx, b.idx,  75); }
  void xsabsdp (VR t, VR b)  { EmitXX2(t.idx, b.idx, 345); }
  void xsnegdp (VR t, VR b)  { EmitXX2(t.idx, b.idx, 377); }
  void xvabssp (VR t, VR b)  { EmitXX2(t.idx, b.idx, 409); }
  void xvabsdp (VR t, VR b)  { EmitXX2(t.idx, b.idx, 473); }
  void xvnegsp (VR t, VR b)  { EmitXX2(t.idx, b.idx, 441); }
  void xvnegdp (VR t, VR b)  { EmitXX2(t.idx, b.idx, 505); }
  void xvsqrtsp(VR t, VR b)  { EmitXX2(t.idx, b.idx, 139); }
  void xvsqrtdp(VR t, VR b)  { EmitXX2(t.idx, b.idx, 203); }
  // Vector FP round-to-integer (still floating-point output)
  void xvrspi (VR t, VR b)   { EmitXX2(t.idx, b.idx, 137); }  // round to nearest
  void xvrspip(VR t, VR b)   { EmitXX2(t.idx, b.idx, 169); }  // round toward +inf
  void xvrspim(VR t, VR b)   { EmitXX2(t.idx, b.idx, 185); }  // round toward -inf
  void xvrspiz(VR t, VR b)   { EmitXX2(t.idx, b.idx, 153); }  // round toward 0
  void xvrspic(VR t, VR b)   { EmitXX2(t.idx, b.idx, 171); }  // round using FPSCR.RN
  // Scalar DP round-to-integer using current FPSCR.RN rounding mode (banker's by default).
  void xsrdpic(VR t, VR b)   { EmitXX2(t.idx, b.idx, 107); }
  void xvrdpi (VR t, VR b)   { EmitXX2(t.idx, b.idx, 201); }
  void xvrdpip(VR t, VR b)   { EmitXX2(t.idx, b.idx, 233); }
  void xvrdpim(VR t, VR b)   { EmitXX2(t.idx, b.idx, 249); }
  void xvrdpiz(VR t, VR b)   { EmitXX2(t.idx, b.idx, 217); }
  void xvrdpic(VR t, VR b)   { EmitXX2(t.idx, b.idx, 235); }  // round using FPSCR.RN
  // Additional vector convert ops
  void xvcvdpsxws(VR t, VR b) { EmitXX2(t.idx, b.idx, 216); }
  void xvcvdpuxws(VR t, VR b) { EmitXX2(t.idx, b.idx, 200); }
  void xvcvdpsxds(VR t, VR b) { EmitXX2(t.idx, b.idx, 472); }
  void xvcvspdp  (VR t, VR b) { EmitXX2(t.idx, b.idx, 457); }
  void xvcvdpsp  (VR t, VR b) { EmitXX2(t.idx, b.idx, 393); }
  // Copy-sign (per element)
  void xvcpsgnsp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 208); }
  void xvcpsgndp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 240); }
  // Vector FP min/max
  void xvmaxsp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 192); }
  void xvminsp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 200); }
  void xvmaxdp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 224); }
  void xvmindp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 232); }
  // Vector FP compare (Rc=0; results are all-ones for true lanes, all-zeros for false)
  void xvcmpeqsp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  67); }
  void xvcmpeqdp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  99); }
  void xvcmpgtsp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  75); }
  void xvcmpgtdp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 107); }
  void xvcmpgesp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx,  83); }
  void xvcmpgedp(VR t, VR a, VR b) { EmitXX3(t.idx, a.idx, b.idx, 115); }

  // =========================================================================
  // Floating-point arithmetic (opcode 63 = double; opcode 59 = single)
  // =========================================================================

  void fadd(FPR frt, FPR fra, FPR frb)  { EmitA63(frt.idx, fra.idx, frb.idx, 0, 21, 0); }
  void fadds(FPR frt, FPR fra, FPR frb) { EmitA59(frt.idx, fra.idx, frb.idx, 0, 21, 0); }
  void fsub(FPR frt, FPR fra, FPR frb)  { EmitA63(frt.idx, fra.idx, frb.idx, 0, 20, 0); }
  void fsubs(FPR frt, FPR fra, FPR frb) { EmitA59(frt.idx, fra.idx, frb.idx, 0, 20, 0); }
  void fmul(FPR frt, FPR fra, FPR frc)  { EmitA63(frt.idx, fra.idx, 0, frc.idx, 25, 0); }
  void fmuls(FPR frt, FPR fra, FPR frc) { EmitA59(frt.idx, fra.idx, 0, frc.idx, 25, 0); }
  void fdiv(FPR frt, FPR fra, FPR frb)  { EmitA63(frt.idx, fra.idx, frb.idx, 0, 18, 0); }
  void fdivs(FPR frt, FPR fra, FPR frb) { EmitA59(frt.idx, fra.idx, frb.idx, 0, 18, 0); }
  void fsqrt(FPR frt, FPR frb)          { EmitA63(frt.idx, 0, frb.idx, 0, 22, 0); }
  void fsqrts(FPR frt, FPR frb)         { EmitA59(frt.idx, 0, frb.idx, 0, 22, 0); }

  // fabs/fneg/fnabs/fmr (opcode 63, X-form)
  void fabs(FPR frt, FPR frb)   { EmitFX63(frt.idx, 0, frb.idx, 264, 0); }
  void fnabs(FPR frt, FPR frb)  { EmitFX63(frt.idx, 0, frb.idx, 136, 0); }
  void fneg(FPR frt, FPR frb)   { EmitFX63(frt.idx, 0, frb.idx, 40,  0); }
  void fmr(FPR frt, FPR frb)    { EmitFX63(frt.idx, 0, frb.idx, 72,  0); }
  void frsp(FPR frt, FPR frb)   { EmitFX63(frt.idx, 0, frb.idx, 12,  0); }
  // Scalar round-to-integer (preserves f64) — used to pre-round before fctid{w}z
  void frin (FPR frt, FPR frb)  { EmitFX63(frt.idx, 0, frb.idx, 392, 0); }
  void friz (FPR frt, FPR frb)  { EmitFX63(frt.idx, 0, frb.idx, 424, 0); }
  void frip (FPR frt, FPR frb)  { EmitFX63(frt.idx, 0, frb.idx, 456, 0); }
  void frim (FPR frt, FPR frb)  { EmitFX63(frt.idx, 0, frb.idx, 488, 0); }

  // fcmpu BF, FRA, FRB  (compare unordered)
  void fcmpu(CRField bf, FPR fra, FPR frb) {
    Emit32((63u << 26) | (bf.idx << 23) | (fra.idx << 16) | (frb.idx << 11) | (0u << 1));
  }
  void fcmpu(FPR fra, FPR frb) { fcmpu(cr(0), fra, frb); }

  // fcmpo BF, FRA, FRB  (compare ordered)
  void fcmpo(CRField bf, FPR fra, FPR frb) {
    Emit32((63u << 26) | (bf.idx << 23) | (fra.idx << 16) | (frb.idx << 11) | (32u << 1));
  }

  // Fused multiply-add (A-form)
  void fmadd(FPR frt, FPR fra, FPR frc, FPR frb)  { EmitA63(frt.idx, fra.idx, frb.idx, frc.idx, 29, 0); }
  void fmadds(FPR frt, FPR fra, FPR frc, FPR frb) { EmitA59(frt.idx, fra.idx, frb.idx, frc.idx, 29, 0); }
  void fmsub(FPR frt, FPR fra, FPR frc, FPR frb)  { EmitA63(frt.idx, fra.idx, frb.idx, frc.idx, 28, 0); }
  void fmsubs(FPR frt, FPR fra, FPR frc, FPR frb) { EmitA59(frt.idx, fra.idx, frb.idx, frc.idx, 28, 0); }
  void fnmadd(FPR frt, FPR fra, FPR frc, FPR frb) { EmitA63(frt.idx, fra.idx, frb.idx, frc.idx, 31, 0); }
  void fnmsub(FPR frt, FPR fra, FPR frc, FPR frb) { EmitA63(frt.idx, fra.idx, frb.idx, frc.idx, 30, 0); }
  void fnmadds(FPR frt, FPR fra, FPR frc, FPR frb){ EmitA59(frt.idx, fra.idx, frb.idx, frc.idx, 31, 0); }
  void fnmsubs(FPR frt, FPR fra, FPR frc, FPR frb){ EmitA59(frt.idx, fra.idx, frb.idx, frc.idx, 30, 0); }
  // fsel FRT, FRA, FRC, FRB:  FRT = (FRA >= 0) ? FRC : FRB.  Used for branchless
  // conditional-select on FP comparisons (NaN treated as < 0).
  void fsel  (FPR frt, FPR fra, FPR frc, FPR frb) { EmitA63(frt.idx, fra.idx, frb.idx, frc.idx, 23, 0); }
  // Reciprocal estimates — A-form unary (FRA=FRC=0)
  void fres    (FPR frt, FPR frb) { EmitA59(frt.idx, 0, frb.idx, 0, 24, 0); }  // 1/x estimate (single)
  void frsqrte (FPR frt, FPR frb) { EmitA63(frt.idx, 0, frb.idx, 0, 26, 0); }  // 1/sqrt(x) est (double)
  void frsqrtes(FPR frt, FPR frb) { EmitA59(frt.idx, 0, frb.idx, 0, 26, 0); }  // 1/sqrt(x) est (single)
  // Unsigned variants of fctid (existing emitter has fctiw/fctiwz/fctid/fctidz/fcfid/fcfidu/fctiwu/fctiwuz/fcfids/fcfidus)
  void fctidu  (FPR frt, FPR frb) { EmitFX63(frt.idx, 0, frb.idx, 942, 0); }
  void fctiduz (FPR frt, FPR frb) { EmitFX63(frt.idx, 0, frb.idx, 943, 0); }
  // CR-bit NOR — combine "OR result with 0" → invert
  void crnor   (uint32_t bt, uint32_t ba, uint32_t bb) {
    Emit32((19u << 26) | (bt << 21) | (ba << 16) | (bb << 11) | (33u << 1));
  }

  // Conversion instructions (opcode 63)
  void fctiw(FPR frt, FPR frb)   { EmitFX63(frt.idx, 0, frb.idx, 14,  0); }
  void fctiwz(FPR frt, FPR frb)  { EmitFX63(frt.idx, 0, frb.idx, 15,  0); }
  void fctid(FPR frt, FPR frb)   { EmitFX63(frt.idx, 0, frb.idx, 814, 0); }
  void fctidz(FPR frt, FPR frb)  { EmitFX63(frt.idx, 0, frb.idx, 815, 0); }
  void fcfid(FPR frt, FPR frb)   { EmitFX63(frt.idx, 0, frb.idx, 846, 0); }
  void fcfidu(FPR frt, FPR frb)  { EmitFX63(frt.idx, 0, frb.idx, 974, 0); }
  void fctiwu(FPR frt, FPR frb)  { EmitFX63(frt.idx, 0, frb.idx, 142, 0); }
  void fctiwuz(FPR frt, FPR frb) { EmitFX63(frt.idx, 0, frb.idx, 143, 0); }

  // fcfids: convert from int doubleword to single (opcode 59)
  void fcfids(FPR frt, FPR frb)  { EmitFX59(frt.idx, 0, frb.idx, 846, 0); }
  void fcfidus(FPR frt, FPR frb) { EmitFX59(frt.idx, 0, frb.idx, 974, 0); }

  // =========================================================================
  // AltiVec/VMX (opcode 4)
  // =========================================================================

  // Vector loads/stores (opcode 31)
  void lvx(VR vrt, GPR ra, GPR rb)    { EmitX(31, vrt.idx, ra.idx, rb.idx, 103,  0); }
  void lvxl(VR vrt, GPR ra, GPR rb)   { EmitX(31, vrt.idx, ra.idx, rb.idx, 359,  0); }
  void stvx(VR vrs, GPR ra, GPR rb)   { EmitX(31, vrs.idx, ra.idx, rb.idx, 231,  0); }
  void stvxl(VR vrs, GPR ra, GPR rb)  { EmitX(31, vrs.idx, ra.idx, rb.idx, 487,  0); }
  void lvewx(VR vrt, GPR ra, GPR rb)  { EmitX(31, vrt.idx, ra.idx, rb.idx,  71,  0); }
  void lvehx(VR vrt, GPR ra, GPR rb)  { EmitX(31, vrt.idx, ra.idx, rb.idx,  39,  0); }
  void lvebx(VR vrt, GPR ra, GPR rb)  { EmitX(31, vrt.idx, ra.idx, rb.idx,   7,  0); }
  void stvewx(VR vrs, GPR ra, GPR rb) { EmitX(31, vrs.idx, ra.idx, rb.idx, 199,  0); }
  void stvehx(VR vrs, GPR ra, GPR rb) { EmitX(31, vrs.idx, ra.idx, rb.idx, 167,  0); }
  void stvebx(VR vrs, GPR ra, GPR rb) { EmitX(31, vrs.idx, ra.idx, rb.idx, 135,  0); }

  // =========================================================================
  // VSX vector/scalar loads and stores (X-form, primary opcode 31).
  //
  // These take VR operands, and VRs map to VSR32-63 — so the TX/SX bit (BE
  // bit 31, the slot EmitX calls `rc`) is ALWAYS 1 here.  10-bit XO values
  // verified against Power ISA 3.0C Book I App. F opcode tables and the
  // instruction descriptions on the cited pages.
  //
  // NOTE on RA=0: for every one of these, RA=0 in the ENCODING means literal
  // zero, not GPR[r0].  Callers follow the backend convention of passing the
  // EA in `ra` and the invariant-zero r0 in `rb` (EA = GPR[ra] + GPR[rb]);
  // never pass an EA that lives in r0 as `ra`.
  // =========================================================================

  // lxvx XT,RA,RB — **ISA 3.0 (POWER9)** — p.496, XO=268. 16-byte load, any
  // alignment (no lvx-style EA masking). LE: mem[EA+i] → BE byte elem 15-i.
  void lxvx(VR vrt, GPR ra, GPR rb)    { EmitX(31, vrt.idx, ra.idx, rb.idx, 268, 1); }
  // stxvx XS,RA,RB — **ISA 3.0 (POWER9)** — p.514, XO=396. Store form.
  void stxvx(VR vrs, GPR ra, GPR rb)   { EmitX(31, vrs.idx, ra.idx, rb.idx, 396, 1); }

  // lxvd2x XT,RA,RB — ISA 2.06 (POWER7+) — p.492, XO=844. Two doubleword
  // elements, any alignment. LE: dword[0] = the 8-byte LE integer at EA,
  // dword[1] = the 8-byte LE integer at EA+8 — i.e. the DOUBLEWORD-SWAPPED
  // image of what lxvx produces; follow with xxpermdi(v,v,v,2) to fix up.
  void lxvd2x(VR vrt, GPR ra, GPR rb)  { EmitX(31, vrt.idx, ra.idx, rb.idx, 844, 1); }
  // stxvd2x XS,RA,RB — ISA 2.06 (POWER7+) — p.508, XO=972. Store form: writes
  // dword[0] as an 8-byte LE integer at EA and dword[1] at EA+8 (so the value
  // must be doubleword-swapped BEFORE the store to match stxvx/stvx layout).
  void stxvd2x(VR vrs, GPR ra, GPR rb) { EmitX(31, vrs.idx, ra.idx, rb.idx, 972, 1); }

  // Scalar loads into dword[0].  CAUTION: ISA 3.0 defines dword[1] ← 0 for
  // all four, but on ISA 2.06/2.07 hardware (POWER7/POWER8) lxsdx/lxsiwzx
  // leave dword[1] UNDEFINED — never rely on the zeroing in an ungated path.
  // lxsdx XT,RA,RB — ISA 2.06 — p.484, XO=588. dword[0] = 8-byte LE int at EA.
  void lxsdx(VR vrt, GPR ra, GPR rb)   { EmitX(31, vrt.idx, ra.idx, rb.idx, 588, 1); }
  // lxsiwzx XT,RA,RB — ISA 2.07 (POWER8+) — p.488, XO=12. dword[0] =
  // zero-extended 4-byte LE int at EA.
  void lxsiwzx(VR vrt, GPR ra, GPR rb) { EmitX(31, vrt.idx, ra.idx, rb.idx,  12, 1); }
  // lxsibzx XT,RA,RB — **ISA 3.0 (POWER9)** — p.486, XO=781. dword[0] =
  // zero-extended byte at EA; dword[1] = 0 (architectural, v3.0 instruction).
  void lxsibzx(VR vrt, GPR ra, GPR rb) { EmitX(31, vrt.idx, ra.idx, rb.idx, 781, 1); }
  // lxsihzx XT,RA,RB — **ISA 3.0 (POWER9)** — p.486, XO=813. dword[0] =
  // zero-extended 2-byte LE int at EA; dword[1] = 0.
  void lxsihzx(VR vrt, GPR ra, GPR rb) { EmitX(31, vrt.idx, ra.idx, rb.idx, 813, 1); }

  // Vector arithmetic (VX-form: op=4, VRT, VRA, VRB, XO)
  void vaddubm(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 0);   }
  void vadduhm(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 64);  }
  void vadduwm(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 128); }
  void vaddudm(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 192); } // POWER8+
  void vsububm(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 1024);}
  void vsubuhm(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 1088);}
  void vsubuwm(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 1152);}
  void vsubudm(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 1216);} // POWER8+

  void vmuloub(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 8);   }
  void vmulouh(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 72);  }
  void vmulouw(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 136); } // POWER8+
  void vmuluwm(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 137); } // POWER8+
  void vmulesb(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 776); }
  void vmulesh(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 840); }
  void vmulesw(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 904); } // POWER8+
  void vmulosb(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 264); }
  void vmulosh(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 328); }
  void vmulosw(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 392); } // POWER8+
  void vmuleub(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 520); }
  void vmuleuh(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 584); }
  void vmuleuw(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 648); } // POWER8+

  void vand(VR vrt, VR vra, VR vrb)    { EmitVX(vrt.idx, vra.idx, vrb.idx, 1028);}
  void vandc(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 1092);}
  void vor(VR vrt, VR vra, VR vrb)     { EmitVX(vrt.idx, vra.idx, vrb.idx, 1156);}
  void vnor(VR vrt, VR vra, VR vrb)    { EmitVX(vrt.idx, vra.idx, vrb.idx, 1284);}
  void vxor(VR vrt, VR vra, VR vrb)    { EmitVX(vrt.idx, vra.idx, vrb.idx, 1220);}
  void vorc(VR vrt, VR vra, VR vrb)    { EmitVX(vrt.idx, vra.idx, vrb.idx, 1348);} // POWER8+
  void vnand(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 1412);} // POWER8+
  void veqv(VR vrt, VR vra, VR vrb)    { EmitVX(vrt.idx, vra.idx, vrb.idx, 1668);} // POWER8+

  void vmr(VR vrt, VR vra)   { vor(vrt, vra, vra); }
  void vnot(VR vrt, VR vra)  { vnor(vrt, vra, vra); }

  // Shifts (VX-form)
  void vslb(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 260); }
  void vslh(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 324); }
  void vslw(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 388); }
  // POWER8 (ISA 2.07) introduced vsld/vsrd at non-progressive XO. The +64
  // slots (452 and 708) are taken by `vsl`/`vsr` (whole-128-bit shifts), so
  // the doubleword variants encode at 1476/1732. Verified via GAS on POWER8.
  void vsld(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 1476); }
  void vsrb(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 516); }
  void vsrh(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 580); }
  void vsrw(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 644); }
  void vsrd(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 1732); }
  void vsrab(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 772); }
  void vsrah(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 836); }
  void vsraw(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 900); }
  void vsrad(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 964); }

  // Shift immediate (VX-form with UIMM in VRA field)
  void vsldoi(VR vrt, VR vra, VR vrb, uint32_t shb) { // VA-form
    assert(shb < 16);
    EmitVA(vrt.idx, vra.idx, vrb.idx, shb, 44);
  }

  // Saturating ops
  void vaddubs(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 512);  }
  void vadduhs(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 576);  }
  void vadduws(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 640);  }
  void vaddsbs(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 768);  }
  void vaddshs(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 832);  }
  void vaddsws(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 896);  }
  void vsububs(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 1536); }  // check XO
  void vsubsbs(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 1792); }
  void vsubshs(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 1856); }
  void vsubsws(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 1920); }
  void vsubuhs(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 1600); }  // check XO
  void vsubuws(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 1664); }  // check XO

  // Average (unsigned): vavgub XO=1026, vavguh XO=1090, vavguw XO=1154
  void vavgub(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 1026); }
  void vavguh(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 1090); }
  void vavguw(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 1154); }

  // Sum across — fold halfwords/bytes/words into 32-bit accumulator(s) of VRT
  void vsumsws (VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 1928); }
  void vsum2sws(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 1672); }
  void vsum4sbs(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 1800); }
  void vsum4shs(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 1608); }
  void vsum4ubs(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 1544); }

  // Merge high/low
  void vmrghb(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 12);   }
  void vmrghh(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 76);   }
  void vmrghw(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 140);  }
  void vmrglb(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 268);  }
  void vmrglh(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 332);  }
  void vmrglw(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 396);  }
  // POWER8: merge even / odd words (selects words [0,2] or [1,3] from each src)
  void vmrgew(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 1932); }
  void vmrgow(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 1676); }

  // Splat — VX-form with the immediate (UIM/SIM) placed in the VRA slot
  void vspltb(VR vrt, VR vrb, uint32_t uimm)  { EmitVX(vrt.idx, uimm & 0xF, vrb.idx, 524); }
  void vsplth(VR vrt, VR vrb, uint32_t uimm)  { EmitVX(vrt.idx, uimm & 0x7, vrb.idx, 588); }
  void vspltw(VR vrt, VR vrb, uint32_t uimm)  { EmitVX(vrt.idx, uimm & 0x3, vrb.idx, 652); }
  void vspltisb(VR vrt, int32_t simm)         { EmitVX(vrt.idx, simm & 0x1F, 0, 780); }
  void vspltish(VR vrt, int32_t simm)         { EmitVX(vrt.idx, simm & 0x1F, 0, 844); }
  void vspltisw(VR vrt, int32_t simm)         { EmitVX(vrt.idx, simm & 0x1F, 0, 908); }

  // Permute (VA-form: XO=43)
  void vperm(VR vrt, VR vra, VR vrb, VR vrc) { EmitVA(vrt.idx, vra.idx, vrb.idx, vrc.idx, 43); }

  // Select (VA-form: XO=42)
  void vsel(VR vrt, VR vra, VR vrb, VR vrc)  { EmitVA(vrt.idx, vra.idx, vrb.idx, vrc.idx, 42); }

  // Compare (VX-form)
  void vcmpequb(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 6);    }
  void vcmpequh(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 70);   }
  void vcmpequw(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 134);  }
  void vcmpequd(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 199);  } // POWER8+
  void vcmpgtsb(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 774);  }
  void vcmpgtsh(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 838);  }
  void vcmpgtsw(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 902);  }
  void vcmpgtsd(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 967);  } // POWER8+
  void vcmpgtub(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 518);  }
  void vcmpgtuh(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 582);  }
  void vcmpgtuw(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 646);  }
  void vcmpgtud(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 711);  } // POWER8+

  // FP vector compare
  void vcmpeqfp(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 198);  }
  void vcmpgefp(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 454);  }
  void vcmpgtfp(VR vrt, VR vra, VR vrb)  { EmitVX(vrt.idx, vra.idx, vrb.idx, 710);  }
  void vcmpbfp(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 966);  }

  // Vector FP arithmetic
  void vaddfp(VR vrt, VR vra, VR vrb)    { EmitVX(vrt.idx, vra.idx, vrb.idx, 10);   }
  void vsubfp(VR vrt, VR vra, VR vrb)    { EmitVX(vrt.idx, vra.idx, vrb.idx, 74);   }
  void vmaddfp(VR vrt, VR vra, VR vrb, VR vrc) { EmitVA(vrt.idx, vra.idx, vrb.idx, vrc.idx, 46); }
  void vnmsubfp(VR vrt, VR vra, VR vrb, VR vrc){ EmitVA(vrt.idx, vra.idx, vrb.idx, vrc.idx, 47); }
  void vmaxfp(VR vrt, VR vra, VR vrb)    { EmitVX(vrt.idx, vra.idx, vrb.idx, 1034); }
  void vminfp(VR vrt, VR vra, VR vrb)    { EmitVX(vrt.idx, vra.idx, vrb.idx, 1098); }
  void vrfin(VR vrt, VR vrb)     { EmitVX(vrt.idx, 0, vrb.idx, 522); }
  void vrfip(VR vrt, VR vrb)     { EmitVX(vrt.idx, 0, vrb.idx, 650); }
  void vrfim(VR vrt, VR vrb)     { EmitVX(vrt.idx, 0, vrb.idx, 714); }
  void vrfiz(VR vrt, VR vrb)     { EmitVX(vrt.idx, 0, vrb.idx, 586); }
  void vrefp(VR vrt, VR vrb)     { EmitVX(vrt.idx, 0, vrb.idx, 266); }
  void vrsqrtefp(VR vrt, VR vrb) { EmitVX(vrt.idx, 0, vrb.idx, 330); }
  void vlogefp(VR vrt, VR vrb)   { EmitVX(vrt.idx, 0, vrb.idx, 458); }
  void vexptefp(VR vrt, VR vrb)  { EmitVX(vrt.idx, 0, vrb.idx, 394); }

  // Convert float/int — VX-form, UIM in VRA slot
  void vctsxs(VR vrt, VR vrb, uint32_t uimm) { EmitVX(vrt.idx, uimm & 0x1F, vrb.idx, 970); }
  void vctuxs(VR vrt, VR vrb, uint32_t uimm) { EmitVX(vrt.idx, uimm & 0x1F, vrb.idx, 906); }
  void vcfsx (VR vrt, VR vrb, uint32_t uimm) { EmitVX(vrt.idx, uimm & 0x1F, vrb.idx, 842); }
  void vcfux (VR vrt, VR vrb, uint32_t uimm) { EmitVX(vrt.idx, uimm & 0x1F, vrb.idx, 778); }

  // vmin/vmax
  void vmaxub(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx,  2);   }
  void vmaxuh(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 66);   }
  void vmaxuw(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 130);  }
  void vmaxud(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 194);  } // POWER8+
  void vmaxsb(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 258);  }
  void vmaxsh(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 322);  }
  void vmaxsw(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 386);  }
  void vmaxsd(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 450);  } // POWER8+
  void vminub(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 514);  }
  void vminuh(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 578);  }
  void vminuw(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 642);  }
  void vminud(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 706);  } // POWER8+
  void vminsb(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 770);  }
  void vminsh(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 834);  }
  void vminsw(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 898);  }
  void vminsd(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 962);  } // POWER8+

  // Abs (POWER8+)
  void vabsdub(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 19);  }
  void vabsduh(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 83);  }
  void vabsduw(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 147); }

  // Pack/unpack
  void vpkuhum(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 14);  }
  void vpkuwum(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 78);  }
  void vpkudum(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 1102); } // POWER8+
  void vpkuhus(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 142);  }
  void vpkuwus(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 206);  }
  void vpkudus(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 1230); } // POWER8+
  void vpkshus(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 270);  }
  void vpkswus(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 334);  }
  void vpksdus(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 1358); } // POWER8+
  void vpkshss(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 398);  }
  void vpkswss(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 462);  }
  void vpksdss(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 1486); } // POWER8+
  void vpkpx(VR vrt, VR vra, VR vrb)   { EmitVX(vrt.idx, vra.idx, vrb.idx, 782);  }

  void vupkhsb(VR vrt, VR vrb) { EmitVX(vrt.idx, 0, vrb.idx, 526);  }
  void vupkhsh(VR vrt, VR vrb) { EmitVX(vrt.idx, 0, vrb.idx, 590);  }
  void vupkhsw(VR vrt, VR vrb) { EmitVX(vrt.idx, 0, vrb.idx, 1614); } // POWER8+
  void vupklsb(VR vrt, VR vrb) { EmitVX(vrt.idx, 0, vrb.idx, 654);  }
  void vupklsh(VR vrt, VR vrb) { EmitVX(vrt.idx, 0, vrb.idx, 718);  }
  void vupklsw(VR vrt, VR vrb) { EmitVX(vrt.idx, 0, vrb.idx, 1742); } // POWER8+

  // vpopcnt (POWER8+) — VX-form, XO at bits 21..31 (no Rc), so the XO value
  // is OR'd directly without a left-shift. The earlier `<<1` was wrong and
  // produced an unrelated opcode (verified via GAS: vpopcntb=0x10000703 →
  // XO=1795 directly, not 1795<<1).
  void vpopcntb(VR vrt, VR vrb) { Emit32((4u<<26)|(vrt.idx<<21)|(0<<16)|(vrb.idx<<11)|1795u); }
  void vpopcnth(VR vrt, VR vrb) { Emit32((4u<<26)|(vrt.idx<<21)|(0<<16)|(vrb.idx<<11)|1859u); }
  void vpopcntw(VR vrt, VR vrb) { Emit32((4u<<26)|(vrt.idx<<21)|(0<<16)|(vrb.idx<<11)|1923u); }
  void vpopcntd(VR vrt, VR vrb) { Emit32((4u<<26)|(vrt.idx<<21)|(0<<16)|(vrb.idx<<11)|1987u); }

  // vbpermq (POWER8+): bit permute quadword
  void vbpermq(VR vrt, VR vra, VR vrb) { EmitVX(vrt.idx, vra.idx, vrb.idx, 1356); }

  // POWER8 ISA 2.07 crypto (AES + carry-less polynomial multiply + perm-xor).
  // VX-form except vpermxor which is VA-form. vsbox takes only VRA (VRB=0).
  // x86 mappings: vcipher = AESENC round, vcipherlast = AESENCLAST,
  // vncipher = AESDEC, vncipherlast = AESDECLAST, vsbox = AES InvSubBytes.
  void vcipher    (VR vrt, VR vra, VR vrb)            { EmitVX(vrt.idx, vra.idx, vrb.idx, 1288); }
  void vcipherlast(VR vrt, VR vra, VR vrb)            { EmitVX(vrt.idx, vra.idx, vrb.idx, 1289); }
  void vncipher   (VR vrt, VR vra, VR vrb)            { EmitVX(vrt.idx, vra.idx, vrb.idx, 1352); }
  void vncipherlast(VR vrt, VR vra, VR vrb)           { EmitVX(vrt.idx, vra.idx, vrb.idx, 1353); }
  void vsbox      (VR vrt, VR vra)                    { EmitVX(vrt.idx, vra.idx, 0,        1480); }
  void vpmsumb    (VR vrt, VR vra, VR vrb)            { EmitVX(vrt.idx, vra.idx, vrb.idx, 1032); }
  void vpmsumh    (VR vrt, VR vra, VR vrb)            { EmitVX(vrt.idx, vra.idx, vrb.idx, 1096); }
  void vpmsumw    (VR vrt, VR vra, VR vrb)            { EmitVX(vrt.idx, vra.idx, vrb.idx, 1160); }
  void vpmsumd    (VR vrt, VR vra, VR vrb)            { EmitVX(vrt.idx, vra.idx, vrb.idx, 1224); }
  void vpermxor   (VR vrt, VR vra, VR vrb, VR vrc)    { EmitVA(vrt.idx, vra.idx, vrb.idx, vrc.idx, 45); }

  // mfvscr / mtvscr
  void mfvscr(VR vrt) { Emit32((4u<<26)|(vrt.idx<<21)|(0<<16)|(0<<11)|(1540u<<1)); }
  void mtvscr(VR vrb) { Emit32((4u<<26)|(0<<21)|(0<<16)|(vrb.idx<<11)|(1604u<<1)); }

  // Vector VMSUMUBM etc (VA-form)
  void vmsumubm(VR vrt, VR vra, VR vrb, VR vrc) { EmitVA(vrt.idx, vra.idx, vrb.idx, vrc.idx, 36); }
  void vmsummbm(VR vrt, VR vra, VR vrb, VR vrc) { EmitVA(vrt.idx, vra.idx, vrb.idx, vrc.idx, 37); }
  void vmsumuhm(VR vrt, VR vra, VR vrb, VR vrc) { EmitVA(vrt.idx, vra.idx, vrb.idx, vrc.idx, 38); }
  void vmsumuhs(VR vrt, VR vra, VR vrb, VR vrc) { EmitVA(vrt.idx, vra.idx, vrb.idx, vrc.idx, 39); }
  void vmsumshm(VR vrt, VR vra, VR vrb, VR vrc) { EmitVA(vrt.idx, vra.idx, vrb.idx, vrc.idx, 40); }
  void vmsumshs(VR vrt, VR vra, VR vrb, VR vrc) { EmitVA(vrt.idx, vra.idx, vrb.idx, vrc.idx, 41); }

  // =========================================================================
  // Branches (B-form and I-form and XL-form)
  // =========================================================================

  // Unconditional branch (I-form): b target, relative offset
  void b(int32_t offset) {
    assert((offset & 3) == 0 && "Branch target must be 4-byte aligned");
    assert(offset >= -(1<<25) && offset < (1<<25) && "Branch offset too large");
    uint32_t li = (static_cast<uint32_t>(offset >> 2)) & 0x00FFFFFFu;
    Emit32((18u << 26) | (li << 2) | 0u);  // AA=0, LK=0
  }

  // Branch with link (bl)
  void bl(int32_t offset) {
    assert((offset & 3) == 0);
    uint32_t li = (static_cast<uint32_t>(offset >> 2)) & 0x00FFFFFFu;
    Emit32((18u << 26) | (li << 2) | 1u);  // AA=0, LK=1
  }

  // Branch to address (absolute)
  void ba(uint64_t target) {
    int64_t offset = static_cast<int64_t>(target) - static_cast<int64_t>(reinterpret_cast<uintptr_t>(Buffer + Offset));
    b(static_cast<int32_t>(offset));
  }

  // Branch relative using label
  void b(Label* lbl) {
    if (lbl->bound) {
      int32_t offset = static_cast<int32_t>(lbl->offset) - static_cast<int32_t>(Offset);
      b(offset);
    } else {
      PendingBranches.push_back({static_cast<int64_t>(Offset), lbl});
      Emit32((18u << 26) | 0u);  // placeholder
    }
  }

  void bl(Label* lbl) {
    if (lbl->bound) {
      int32_t offset = static_cast<int32_t>(lbl->offset) - static_cast<int32_t>(Offset);
      bl(offset);
    } else {
      PendingBranches.push_back({static_cast<int64_t>(Offset), lbl});
      Emit32((18u << 26) | 1u);  // placeholder with LK=1
    }
  }

  // Conditional branch: bc BO, BI, offset
  // BD field is 14 bits signed, i.e. byte offset must fit in [-32768, +32764].
  // Silent masking here means out-of-range forward branches land in random
  // nearby blocks; assert so we catch JIT block growths past the limit.
  void bc(uint32_t bo, uint32_t bi, int32_t offset) {
    assert((offset & 3) == 0);
    assert(offset >= -32768 && offset <= 32764 && "bc offset out of 14-bit signed range");
    uint32_t bd = (static_cast<uint32_t>(offset >> 2)) & 0x3FFFu;
    Emit32((16u << 26) | (bo << 21) | (bi << 16) | (bd << 2) | 0u);
  }

  // Conditional branch with label
  void bc(Cond cond, Label* lbl) {
    if (lbl->bound) {
      int32_t offset = static_cast<int32_t>(lbl->offset) - static_cast<int32_t>(Offset);
      bc(cond.BO, cond.BI, offset);
    } else {
      PendingBranches.push_back({static_cast<int64_t>(Offset), lbl});
      Emit32((16u << 26) | (cond.BO << 21) | (cond.BI << 16) | 0u);  // placeholder
    }
  }

  // blr: branch to link register (return)
  void blr() { Emit32((19u << 26) | (20u << 21) | (0u << 16) | (16u << 1) | 0u); }

  // bctrl: branch and link to count register (indirect call)
  void bctrl() { Emit32((19u << 26) | (20u << 21) | (0u << 16) | (528u << 1) | 1u); }

  // bctr: branch to count register (indirect jump)
  void bctr() { Emit32((19u << 26) | (20u << 21) | (0u << 16) | (528u << 1) | 0u); }

  // blrl: branch to link register and link
  void blrl() { Emit32((19u << 26) | (20u << 21) | (0u << 16) | (16u << 1) | 1u); }

  // bcl (conditional branch and link to count/cond register)
  void bclr(uint32_t bo, uint32_t bi) {
    Emit32((19u << 26) | (bo << 21) | (bi << 16) | (16u << 1) | 0u);
  }

  // mtctr RS (move to count register; uses SPR 9)
  void mtctr(GPR rs) { EmitSPR(rs.idx, 9, 467); }  // mtspr 9, rs

  // mfctr RT
  void mfctr(GPR rt) { EmitSPR(rt.idx, 9, 339); }  // mfspr 9, rt

  // mtlr RS (move to link register; uses SPR 8)
  void mtlr(GPR rs) { EmitSPR(rs.idx, 8, 467); }

  // mflr RT
  void mflr(GPR rt) { EmitSPR(rt.idx, 8, 339); }

  // =========================================================================
  // Special purpose registers
  // =========================================================================

  // mfspr RT, SPR  (XO 339, note: SPR field is split 5+5 with lower 5 first)
  void mfspr(GPR rt, uint32_t spr) {
    uint32_t spr_lo = spr & 0x1F;
    uint32_t spr_hi = (spr >> 5) & 0x1F;
    Emit32((31u << 26) | (rt.idx << 21) | (spr_lo << 16) | (spr_hi << 11) | (339u << 1));
  }

  // mtspr SPR, RS  (XO 467)
  void mtspr(uint32_t spr, GPR rs) {
    uint32_t spr_lo = spr & 0x1F;
    uint32_t spr_hi = (spr >> 5) & 0x1F;
    Emit32((31u << 26) | (rs.idx << 21) | (spr_lo << 16) | (spr_hi << 11) | (467u << 1));
  }

  // mftb RT (move from time base lower: SPR 268)
  void mftb(GPR rt) { mfspr(rt, 268); }

  // =========================================================================
  // Memory barriers
  // =========================================================================

  // sync L (opcode 31, XO 598)
  void sync(uint32_t l = 0) {
    Emit32((31u << 26) | (l << 21) | (598u << 1));
  }
  void hwsync()  { sync(0); }
  void lwsync()  { sync(1); }

  // isync (opcode 19, XO 150)
  void isync() { Emit32((19u << 26) | (150u << 1)); }

  // eieio (opcode 31, XO 854)
  void eieio() { Emit32((31u << 26) | (854u << 1)); }

  // dcbst (data cache block store, opcode 31, XO 54)
  void dcbst(GPR ra, GPR rb) { EmitX(31, 0, ra.idx, rb.idx, 54, 0); }

  // dcbt (data cache block touch, opcode 31, XO 278)
  void dcbt(GPR ra, GPR rb, uint32_t th = 0) {
    Emit32((31u << 26) | (th << 21) | (ra.idx << 16) | (rb.idx << 11) | (278u << 1));
  }

  // dcbz (data cache block zero, opcode 31, XO 1014)
  void dcbz(GPR ra, GPR rb) { EmitX(31, 0, ra.idx, rb.idx, 1014, 0); }

  // icbi (instruction cache block invalidate, opcode 31, XO 982)
  void icbi(GPR ra, GPR rb) { EmitX(31, 0, ra.idx, rb.idx, 982, 0); }

  // =========================================================================
  // Atomic (reservation) load/store
  // =========================================================================

  void lbarx(GPR rt, GPR ra, GPR rb, uint32_t eh = 0)  { EmitAtom(rt.idx, ra.idx, rb.idx, 52,  eh); }
  void lharx(GPR rt, GPR ra, GPR rb, uint32_t eh = 0)  { EmitAtom(rt.idx, ra.idx, rb.idx, 116, eh); }
  void lwarx(GPR rt, GPR ra, GPR rb, uint32_t eh = 0)  { EmitAtom(rt.idx, ra.idx, rb.idx, 20,  eh); }
  void ldarx(GPR rt, GPR ra, GPR rb, uint32_t eh = 0)  { EmitAtom(rt.idx, ra.idx, rb.idx, 84,  eh); }

  // stbcx. / sthcx. / stwcx. / stdcx.  (always Rc=1)
  void stbcx_(GPR rs, GPR ra, GPR rb) { EmitX(31, rs.idx, ra.idx, rb.idx, 694, 1); }
  void sthcx_(GPR rs, GPR ra, GPR rb) { EmitX(31, rs.idx, ra.idx, rb.idx, 726, 1); }
  void stwcx_(GPR rs, GPR ra, GPR rb) { EmitX(31, rs.idx, ra.idx, rb.idx, 150, 1); }
  void stdcx_(GPR rs, GPR ra, GPR rb) { EmitX(31, rs.idx, ra.idx, rb.idx, 214, 1); }

  // Quadword LL/SC (POWER8, ISA 2.07). RTp/RSp must be an even register; the
  // pair is RTp:RTp+1. In little-endian mode the high-addressed doubleword
  // (EA+8) goes to RTp and the low-addressed doubleword (EA+0) goes to RTp+1.
  void lqarx(GPR rtp, GPR ra, GPR rb, uint32_t eh = 0) { EmitAtom(rtp.idx, ra.idx, rb.idx, 276, eh); }
  void stqcx_(GPR rsp, GPR ra, GPR rb) { EmitX(31, rsp.idx, ra.idx, rb.idx, 182, 1); }

  // =========================================================================
  // Trap / interrupt
  // =========================================================================

  // tw TO, RA, RB (trap word, opcode 31, XO 4)
  void tw(uint32_t to, GPR ra, GPR rb) {
    Emit32((31u << 26) | (to << 21) | (ra.idx << 16) | (rb.idx << 11) | (4u << 1));
  }

  // twi TO, RA, SI (trap word immediate, opcode 3)
  void twi(uint32_t to, GPR ra, int16_t si) {
    Emit32((3u << 26) | (to << 21) | (ra.idx << 16) | static_cast<uint16_t>(si));
  }

  // td TO, RA, RB (trap doubleword, opcode 31, XO 68)
  void td(uint32_t to, GPR ra, GPR rb) {
    Emit32((31u << 26) | (to << 21) | (ra.idx << 16) | (rb.idx << 11) | (68u << 1));
  }

  // tdi TO, RA, SI (trap doubleword immediate, opcode 2)
  void tdi(uint32_t to, GPR ra, int16_t si) {
    Emit32((2u << 26) | (to << 21) | (ra.idx << 16) | static_cast<uint16_t>(si));
  }

  // =========================================================================
  // System call
  // =========================================================================

  void sc(uint32_t lev = 0) {
    Emit32((17u << 26) | (lev << 5) | 2u);
  }

  // =========================================================================
  // Round/float convert
  // =========================================================================

  void mffs(FPR frt) { EmitFX63(frt.idx, 0, 0, 583, 0); }
  void mtfsf(uint32_t fm, FPR frb) {
    Emit32((63u << 26) | (0u << 25) | (fm << 17) | (0u << 16) | (frb.idx << 11) | (711u << 1));
  }
  void mtfsfi(uint32_t bf, uint32_t u) {
    Emit32((63u << 26) | (bf << 23) | (0u << 22) | (u << 12) | (134u << 1));
  }

  // =========================================================================
  // Load immediate large (pseudo-instructions using multiple instructions)
  // =========================================================================

  // Load a 32-bit immediate into a register
  void LoadImm32(GPR rt, uint32_t imm) {
    int32_t simm = static_cast<int32_t>(imm);
    if (simm >= -32768 && simm < 32768) {
      li(rt, static_cast<int16_t>(simm));
    } else {
      lis(rt, static_cast<int16_t>(imm >> 16));
      if (imm & 0xFFFF) {
        ori(rt, rt, static_cast<uint16_t>(imm & 0xFFFF));
      }
    }
  }

  // Load a 64-bit immediate into a register (up to 5 instructions)
  void LoadImm64(GPR rt, uint64_t imm) {
    if (imm == 0) {
      li(rt, 0);
      return;
    }
    // Check if it fits in a 32-bit signed value
    if (imm <= 0x7FFFFFFFull || imm >= 0xFFFFFFFF80000000ull) {
      LoadImm32(rt, static_cast<uint32_t>(static_cast<int32_t>(imm)));
      return;
    }
    // Zero-extended 32-bit value (0x80000000..0xFFFFFFFF). LoadImm32 sign-extends
    // via lis, so the upper 32 bits would become 0xFFFFFFFF; clear them with clrldi.
    if (imm <= 0xFFFFFFFFull) {
      LoadImm32(rt, static_cast<uint32_t>(imm));
      clrldi(rt, rt, 32);
      return;
    }
    // Full 64-bit load: lis + ori + sldi 32 + oris + ori
    uint32_t hi = static_cast<uint32_t>(imm >> 32);
    uint32_t lo = static_cast<uint32_t>(imm);
    if (hi) {
      lis(rt, static_cast<int16_t>(hi >> 16));
      if (hi & 0xFFFF) ori(rt, rt, static_cast<uint16_t>(hi & 0xFFFF));
    } else {
      li(rt, 0);
    }
    sldi(rt, rt, 32);
    if (lo >> 16) oris(rt, rt, static_cast<uint16_t>(lo >> 16));
    if (lo & 0xFFFF) ori(rt, rt, static_cast<uint16_t>(lo & 0xFFFF));
  }

  // =========================================================================
  // Miscellaneous
  // =========================================================================

  // mfmsr RT (move from machine state register)
  void mfmsr(GPR rt) { Emit32((31u << 26) | (rt.idx << 21) | (83u << 1)); }

  // rfid (return from interrupt doubleword; supervisor only, just for completeness)
  void rfid() { Emit32((19u << 26) | (18u << 1)); }

  // Patch a previously emitted branch at byte offset to jump to current position.
  // Range checks: opcode 18 (b) has 24-bit signed LI (byte offset ±32 MiB);
  // opcode 16 (bc) has 14-bit signed BD (byte offset ±32 KiB).  Silent
  // truncation in either field mis-patches the branch to a wrong target.
  void PatchBranchAt(size_t patch_offset, size_t target_offset) {
    uint32_t insn;
    memcpy(&insn, Buffer + patch_offset, 4);
    uint32_t opcode = insn >> 26;
    int32_t offset = static_cast<int32_t>(target_offset) - static_cast<int32_t>(patch_offset);
    assert((offset & 3) == 0);

    if (opcode == 18) {  // unconditional branch
      assert(offset >= -(1 << 25) && offset < (1 << 25) && "b: LI offset out of 24-bit signed range");
      uint32_t li = (static_cast<uint32_t>(offset >> 2)) & 0x00FFFFFFu;
      insn = (insn & 0xFC000003u) | (li << 2);
    } else if (opcode == 16) {  // conditional branch
      assert(offset >= -32768 && offset <= 32764 && "bc: BD offset out of 14-bit signed range");
      uint32_t bd = (static_cast<uint32_t>(offset >> 2)) & 0x3FFFu;
      insn = (insn & 0xFFFF0003u) | (bd << 2);
    }
    memcpy(Buffer + patch_offset, &insn, 4);
  }

private:
  uint8_t* Buffer     = nullptr;
  size_t   BufferSize = 0;
  size_t   Offset     = 0;

  // Pending branch list for forward-label fixup
  struct PendingBranchEntry {
    int64_t patch_offset;
    Label*  target;
  };
  std::vector<PendingBranchEntry> PendingBranches;

  void PatchPending(Label* lbl) {
    for (auto it = PendingBranches.begin(); it != PendingBranches.end(); ) {
      if (it->target == lbl) {
        PatchBranchAt(static_cast<size_t>(it->patch_offset),
                      static_cast<size_t>(lbl->offset));
        it = PendingBranches.erase(it);
      } else {
        ++it;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Instruction encoding helpers
  // -------------------------------------------------------------------------

  // XO-form: op(6) | RT(5) | RA(5) | RB(5) | OE(1) | XO(9) | Rc(1)
  void EmitXO(uint32_t op, uint32_t rt, uint32_t ra, uint32_t rb, uint32_t oe, uint32_t xo, uint32_t rc) {
    Emit32((op << 26) | (rt << 21) | (ra << 16) | (rb << 11) | (oe << 10) | (xo << 1) | rc);
  }

  // X-form: op(6) | RS/RT(5) | RA(5) | RB/SH(5) | XO(10) | Rc(1)
  void EmitX(uint32_t op, uint32_t rs, uint32_t ra, uint32_t rb, uint32_t xo, uint32_t rc) {
    Emit32((op << 26) | (rs << 21) | (ra << 16) | (rb << 11) | (xo << 1) | rc);
  }

  // D-form: op(6) | RT/RS(5) | RA(5) | D/SI/UI(16)
  void EmitD(uint32_t op, uint32_t rt, uint32_t ra, uint16_t d) {
    Emit32((op << 26) | (rt << 21) | (ra << 16) | d);
  }

  // M-form: op(6) | RS(5) | RA(5) | SH(5) | MB(5) | ME(5) | Rc(1)
  void EmitM(uint32_t op, uint32_t rs, uint32_t ra, uint32_t sh, uint32_t mb, uint32_t me, uint32_t rc) {
    Emit32((op << 26) | (rs << 21) | (ra << 16) | (sh << 11) | (mb << 6) | (me << 1) | rc);
  }

  // MD-form (Power ISA 2.07 §1.6.1.6): op=30 | RS(5) | RA(5) | sh[1:5] | m[1:5] | m[0] | XO(3) | sh[0] | Rc
  // BE bit positions:    0:5 |  6:10 | 11:15 | 16:20 | 21:25 | 26 | 27:29 | 30 | 31
  // LE bit positions:   31:26| 25:21 | 20:16 | 15:11 | 10:6  |  5 |  4:2  |  1 |  0
  // Where m is MB (rldicl/rldic/rldimi) or ME (rldicr).  The 6-bit m field is split with
  // the high bit (m[0]) at BE-bit 26 and the low 5 bits (m[1:5]) at BE-bits 21:25.
  // Likewise the 6-bit sh has its high bit at BE-bit 30 and low 5 bits at BE-bits 16:20.
  void EmitMD(uint32_t rs, uint32_t ra, uint32_t sh, uint32_t mb_or_me, uint32_t xo, uint32_t rc) {
    uint32_t sh_low  = sh & 0x1F;
    uint32_t sh_high = (sh >> 5) & 1;
    uint32_t mb_low  = mb_or_me & 0x1F;
    uint32_t mb_high = (mb_or_me >> 5) & 1;
    Emit32((30u << 26) | (rs << 21) | (ra << 16) | (sh_low << 11) |
           (mb_low << 6) | (mb_high << 5) | (xo << 2) | (sh_high << 1) | rc);
  }

  // A-form (float): op(6) | FRT(5) | FRA(5) | FRB(5) | FRC(5) | XO(5) | Rc(1)
  void EmitA63(uint32_t frt, uint32_t fra, uint32_t frb, uint32_t frc, uint32_t xo, uint32_t rc) {
    Emit32((63u << 26) | (frt << 21) | (fra << 16) | (frb << 11) | (frc << 6) | (xo << 1) | rc);
  }
  void EmitA59(uint32_t frt, uint32_t fra, uint32_t frb, uint32_t frc, uint32_t xo, uint32_t rc) {
    Emit32((59u << 26) | (frt << 21) | (fra << 16) | (frb << 11) | (frc << 6) | (xo << 1) | rc);
  }

  // FX-form (float X): op(6) | FRT(5) | FRA(5) | FRB(5) | XO(10) | Rc(1)
  void EmitFX63(uint32_t frt, uint32_t fra, uint32_t frb, uint32_t xo, uint32_t rc) {
    Emit32((63u << 26) | (frt << 21) | (fra << 16) | (frb << 11) | (xo << 1) | rc);
  }
  void EmitFX59(uint32_t frt, uint32_t fra, uint32_t frb, uint32_t xo, uint32_t rc) {
    Emit32((59u << 26) | (frt << 21) | (fra << 16) | (frb << 11) | (xo << 1) | rc);
  }

  // VX-form (AltiVec, Power ISA 2.07 §6.6.1): op=4 | VRT | VRA | VRB | XO(11)
  // BE bits:  0:5 | 6:10 | 11:15 | 16:20 | 21:31    (no Rc; XO occupies all 11 low bits)
  // LE bits: 31:26| 25:21| 20:16 | 15:11 | 10:0
  void EmitVX(uint32_t vrt, uint32_t vra, uint32_t vrb, uint32_t xo) {
    Emit32((4u << 26) | (vrt << 21) | (vra << 16) | (vrb << 11) | xo);
  }

  // VA-form (Power ISA 2.07 §6.6.2): op=4 | VRT | VRA | VRB | VRC | XO(6)
  // BE bits:  0:5 | 6:10 | 11:15 | 16:20 | 21:25 | 26:31
  // LE bits: 31:26| 25:21| 20:16 | 15:11 | 10:6  |  5:0
  void EmitVA(uint32_t vrt, uint32_t vra, uint32_t vrb, uint32_t vrc, uint32_t xo) {
    Emit32((4u << 26) | (vrt << 21) | (vra << 16) | (vrb << 11) | (vrc << 6) | xo);
  }

  // Atomic (reservation) load: X-form with EH bit
  void EmitAtom(uint32_t rt, uint32_t ra, uint32_t rb, uint32_t xo, uint32_t eh) {
    Emit32((31u << 26) | (rt << 21) | (ra << 16) | (rb << 11) | (xo << 1) | eh);
  }

  // SPR move helpers (SPR field is split 5+5 with lower bits first)
  void EmitSPR(uint32_t rs_rt, uint32_t spr, uint32_t xo) {
    uint32_t spr_lo = spr & 0x1F;
    uint32_t spr_hi = (spr >> 5) & 0x1F;
    Emit32((31u << 26) | (rs_rt << 21) | (spr_lo << 16) | (spr_hi << 11) | (xo << 1));
  }
};

} // namespace PPC64Emitter
