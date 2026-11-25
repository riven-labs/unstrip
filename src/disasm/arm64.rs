//! AArch64 decoding, as far as the literal scanner needs it. Every
//! instruction is four bytes; this names the few forms that build an
//! address, a constant, a register copy or a store, and for the rest says
//! which general-purpose registers they may write.

/// Register 31 is the stack pointer as a load/store base and in `ADD`/`SUB`
/// (immediate), and the zero register elsewhere.
pub(crate) const SP: u8 = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// `ADRP` or `ADR`: an address, or the 4 KiB page of one.
    Addr {
        dst: u8,
        target: u64,
    },
    /// `ADD Xd, Xn, #imm`, which completes an `ADRP` page into an address.
    AddImm {
        dst: u8,
        src: u8,
        imm: u64,
    },
    /// A constant written to the full register: `MOVZ`, `MOVN`, `ORR` of a
    /// bitmask immediate with the zero register, `MOV Xd, XZR`.
    MovImm {
        dst: u8,
        value: u64,
    },
    /// `MOVK`: 16 bits of `imm` inserted at `shift` into the register.
    MovK {
        dst: u8,
        shift: u32,
        imm: u64,
        wide: bool,
    },
    /// `MOV Xd, Xm`.
    MovReg {
        dst: u8,
        src: u8,
    },
    /// `STR Xt` or `STUR Xt` at `base + offset`, `width` bytes. `src` 31
    /// is the zero register.
    Store {
        base: u8,
        offset: i64,
        src: u8,
        width: u8,
        /// The base register is updated (pre- or post-index).
        writeback: bool,
    },
    /// `STP Xt, Xt2, [base, #offset]`.
    StorePair {
        base: u8,
        offset: i64,
        first: u8,
        second: u8,
        writeback: bool,
    },
    /// `LDR Xt, [base, #offset]` with an unsigned offset.
    Load {
        dst: u8,
        base: u8,
        offset: i64,
    },
    Call {
        target: Option<u64>,
    },
    Jump {
        target: Option<u64>,
        conditional: bool,
    },
    Ret,
    Other {
        /// Registers the instruction may write, one bit each.
        writes: u32,
        /// A load or store this decoder does not name: memory at this base
        /// register may change.
        mem_base: Option<u8>,
    },
}

/// Decodes the instruction word `insn` at `pc`.
pub(crate) fn decode(insn: u32, pc: u64) -> Kind {
    let rd = (insn & 31) as u8;
    let rn = ((insn >> 5) & 31) as u8;

    // PC-relative addressing.
    if insn & 0x1f00_0000 == 0x1000_0000 {
        let immlo = ((insn >> 29) & 3) as i64;
        let immhi = ((insn >> 5) & 0x7ffff) as i64;
        let imm = sign_extend((immhi << 2) | immlo, 21);
        let target = if insn & 0x8000_0000 != 0 {
            (pc & !0xfff).wrapping_add((imm << 12) as u64)
        } else {
            pc.wrapping_add(imm as u64)
        };
        return Kind::Addr { dst: rd, target };
    }
    // ADD (immediate), 64-bit, flags untouched.
    if insn & 0xff80_0000 == 0x9100_0000 {
        let shift = if insn & (1 << 22) != 0 { 12 } else { 0 };
        let imm = (((insn >> 10) & 0xfff) as u64) << shift;
        return Kind::AddImm {
            dst: rd,
            src: rn,
            imm,
        };
    }
    // Move wide: MOVN, MOVZ, MOVK.
    if insn & 0x1f80_0000 == 0x1280_0000 {
        let wide = insn & 0x8000_0000 != 0;
        let opc = (insn >> 29) & 3;
        let shift = ((insn >> 21) & 3) * 16;
        let imm = ((insn >> 5) & 0xffff) as u64;
        if !wide && shift >= 32 {
            return other_writes(rd);
        }
        let mask = if wide { u64::MAX } else { 0xffff_ffff };
        return match opc {
            0 => Kind::MovImm {
                dst: rd,
                value: !(imm << shift) & mask,
            },
            2 => Kind::MovImm {
                dst: rd,
                value: imm << shift,
            },
            3 => Kind::MovK {
                dst: rd,
                shift,
                imm,
                wide,
            },
            _ => other_writes(rd),
        };
    }
    // ORR (immediate) with the zero register: MOV of a bitmask immediate.
    if insn & 0x7f80_0000 == 0x3200_0000 && rn == 31 {
        let wide = insn & 0x8000_0000 != 0;
        let n = (insn >> 22) & 1;
        if !wide && n == 1 {
            return other_writes(rd);
        }
        let immr = (insn >> 16) & 0x3f;
        let imms = (insn >> 10) & 0x3f;
        return match decode_bit_mask(n, imms, immr, if wide { 64 } else { 32 }) {
            // Register 31 is SP here, which the scanner does not track.
            Some(value) if rd != SP => Kind::MovImm { dst: rd, value },
            _ => other_writes(rd),
        };
    }
    // ORR (shifted register) with the zero register and no shift: MOV.
    if insn & 0xffe0_ffe0 == 0xaa00_03e0 {
        let rm = ((insn >> 16) & 31) as u8;
        return if rm == 31 {
            Kind::MovImm { dst: rd, value: 0 }
        } else {
            Kind::MovReg { dst: rd, src: rm }
        };
    }
    // Branches.
    if insn & 0x7c00_0000 == 0x1400_0000 {
        let target = pc.wrapping_add((sign_extend((insn & 0x03ff_ffff) as i64, 26) << 2) as u64);
        return if insn & 0x8000_0000 != 0 {
            Kind::Call {
                target: Some(target),
            }
        } else {
            Kind::Jump {
                target: Some(target),
                conditional: false,
            }
        };
    }
    if insn & 0xff00_0010 == 0x5400_0000 || insn & 0x7e00_0000 == 0x3400_0000 {
        let imm19 = ((insn >> 5) & 0x7ffff) as i64;
        let target = pc.wrapping_add((sign_extend(imm19, 19) << 2) as u64);
        return Kind::Jump {
            target: Some(target),
            conditional: true,
        };
    }
    if insn & 0x7e00_0000 == 0x3600_0000 {
        let imm14 = ((insn >> 5) & 0x3fff) as i64;
        let target = pc.wrapping_add((sign_extend(imm14, 14) << 2) as u64);
        return Kind::Jump {
            target: Some(target),
            conditional: true,
        };
    }
    match insn & 0xffff_fc1f {
        0xd61f_0000 => {
            return Kind::Jump {
                target: None,
                conditional: false,
            }
        }
        0xd63f_0000 => return Kind::Call { target: None },
        0xd65f_0000 => return Kind::Ret,
        _ => (),
    }
    // Exception generation (BRK, HLT, SVC...): a BRK ends the code path; a
    // supervisor call may change anything.
    if insn & 0xff00_0000 == 0xd400_0000 {
        return if insn & 0x00e0_0000 == 0x0020_0000 {
            Kind::Ret
        } else {
            Kind::Other {
                writes: u32::MAX,
                mem_base: None,
            }
        };
    }

    // Loads and stores.
    if insn & 0x0a00_0000 == 0x0800_0000 {
        let rt2 = ((insn >> 10) & 31) as u8;
        // STR (immediate), 64-bit: unsigned offset, pre- and post-index.
        if insn & 0xffc0_0000 == 0xf900_0000 {
            return Kind::Store {
                base: rn,
                offset: (((insn >> 10) & 0xfff) as i64) * 8,
                src: rd,
                width: 8,
                writeback: false,
            };
        }
        if insn & 0xffe0_0000 == 0xf800_0000 {
            let imm9 = sign_extend(((insn >> 12) & 0x1ff) as i64, 9);
            return match (insn >> 10) & 3 {
                // STUR.
                0 => Kind::Store {
                    base: rn,
                    offset: imm9,
                    src: rd,
                    width: 8,
                    writeback: false,
                },
                // Post-index stores at the old base, pre-index at the new.
                1 => Kind::Store {
                    base: rn,
                    offset: 0,
                    src: rd,
                    width: 8,
                    writeback: true,
                },
                3 => Kind::Store {
                    base: rn,
                    offset: imm9,
                    src: rd,
                    width: 8,
                    writeback: true,
                },
                _ => Kind::Other {
                    writes: 0,
                    mem_base: Some(rn),
                },
            };
        }
        // STP, 64-bit: post-index, signed offset, pre-index.
        if insn & 0xfe40_0000 == 0xa800_0000 && (insn >> 23) & 3 != 0 {
            let imm7 = sign_extend(((insn >> 15) & 0x7f) as i64, 7) * 8;
            let mode = (insn >> 23) & 3;
            return Kind::StorePair {
                base: rn,
                offset: if mode == 1 { 0 } else { imm7 },
                first: rd,
                second: rt2,
                writeback: mode != 2,
            };
        }
        // LDR (immediate), 64-bit, unsigned offset.
        if insn & 0xffc0_0000 == 0xf940_0000 {
            return Kind::Load {
                dst: rd,
                base: rn,
                offset: (((insn >> 10) & 0xfff) as i64) * 8,
            };
        }
        // Anything else in the class writes its destination register (a
        // load, or an exclusive store's status), the second one of a pair,
        // its base on write-back, and memory off its base when it stores.
        let reg = |r: u8| if r == SP { 0 } else { 1u32 << r };
        let (writes, store) = match (insn >> 27) & 7 {
            // Load/store pair: L is bit 22, write-back is modes 1 and 3.
            0b101 => {
                let writeback = matches!((insn >> 23) & 3, 1 | 3);
                let base = if writeback { 1u32 << rn } else { 0 };
                (reg(rd) | reg(rt2) | base, insn & (1 << 22) == 0)
            }
            // Load/store register: unsigned offset (bit 24), register offset
            // and atomics (bit 21), or a 9-bit offset with write-back in
            // modes 1 and 3. Stores have opc (bits 23:22) zero.
            0b111 => {
                let writeback =
                    insn & (1 << 24) == 0 && insn & (1 << 21) == 0 && (insn >> 10) & 1 == 1;
                let base = if writeback { 1u32 << rn } else { 0 };
                let atomic =
                    insn & (1 << 24) == 0 && insn & (1 << 21) != 0 && (insn >> 10) & 3 == 0;
                (reg(rd) | base, (insn >> 22) & 3 == 0 || atomic)
            }
            // Load register (literal).
            0b011 => (reg(rd), false),
            // Exclusives and the SIMD structure loads and stores: anything.
            _ => {
                let rs = ((insn >> 16) & 31) as u8;
                (reg(rd) | reg(rt2) | reg(rs) | (1u32 << rn), true)
            }
        };
        return Kind::Other {
            writes,
            mem_base: store.then_some(rn),
        };
    }
    // ADD/SUB (immediate) and logical (immediate) without flags write SP
    // when Rd is 31; every other data-processing form writes XZR there.
    let writes_sp = insn & 0x3f00_0000 == 0x1100_0000
        || (insn & 0x1f80_0000 == 0x1200_0000 && (insn >> 29) & 3 != 3)
        || insn & 0x3fe0_0000 == 0x0b20_0000;
    if rd == SP && writes_sp {
        return Kind::Other {
            writes: 1u32 << SP,
            mem_base: None,
        };
    }
    // Data processing writes Rd, and SIMD and floating point only vector
    // registers or Rd; either way Rd is the only general register at risk.
    // System instructions (MRS) write Rt in the same bits.
    other_writes(rd)
}

/// An instruction that writes `rd`, which is the zero register when 31.
fn other_writes(rd: u8) -> Kind {
    let writes = if rd == SP { 0 } else { 1u32 << rd };
    Kind::Other {
        writes,
        mem_base: None,
    }
}

fn sign_extend(v: i64, bits: u32) -> i64 {
    let shift = 64 - bits;
    (v << shift) >> shift
}

/// The value of a logical immediate (`DecodeBitMasks` in the Arm ARM).
fn decode_bit_mask(n: u32, imms: u32, immr: u32, reg_size: u32) -> Option<u64> {
    let combined = (n << 6) | (!imms & 0x3f);
    if combined == 0 {
        return None;
    }
    let len = 31 - combined.leading_zeros();
    let size = 1u32 << len;
    let levels = size - 1;
    let s = imms & levels;
    let r = immr & levels;
    if s == levels {
        return None;
    }
    let ones = s + 1;
    let welem: u64 = if ones == 64 {
        u64::MAX
    } else {
        (1u64 << ones) - 1
    };
    let elem = if size == 64 {
        welem.rotate_right(r)
    } else {
        let mask = (1u64 << size) - 1;
        ((welem >> r) | (welem << (size - r))) & mask
    };
    let mut value = 0u64;
    let mut at = 0;
    while at < reg_size {
        value |= elem << at;
        at += size;
    }
    if reg_size == 32 {
        value &= 0xffff_ffff;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adrp_add_and_constants_decode() {
        // ADRP 196608(PC), R1 at 0xaa420; ADD $2330, R1, R1.
        assert_eq!(
            decode(0x9000_0181, 0xaa420),
            Kind::Addr {
                dst: 1,
                target: 0xaa000 + 196608
            }
        );
        assert_eq!(
            decode(0x9124_6821, 0),
            Kind::AddImm {
                dst: 1,
                src: 1,
                imm: 2330
            }
        );
        // ORR $28, ZR, R1 and ORR $1, ZR, R6.
        assert_eq!(decode(0xb27e_0be1, 0), Kind::MovImm { dst: 1, value: 28 });
        assert_eq!(decode(0xb240_03e6, 0), Kind::MovImm { dst: 6, value: 1 });
        // MOVD $443, R2 (MOVZ); MOVD ZR, R0.
        assert_eq!(decode(0xd280_3762, 0), Kind::MovImm { dst: 2, value: 443 });
        assert_eq!(decode(0xaa1f_03e0, 0), Kind::MovImm { dst: 0, value: 0 });
    }

    #[test]
    fn stores_name_base_offset_and_sources() {
        // STP (R1, R2), 8(R0).
        assert_eq!(
            decode(0xa900_8801, 0),
            Kind::StorePair {
                base: 0,
                offset: 8,
                first: 1,
                second: 2,
                writeback: false
            }
        );
        // MOVD R1, (R0); MOVD R1, 96(RSP).
        assert_eq!(
            decode(0xf900_0001, 0),
            Kind::Store {
                base: 0,
                offset: 0,
                src: 1,
                width: 8,
                writeback: false
            }
        );
        assert_eq!(
            decode(0xf900_33e1, 0),
            Kind::Store {
                base: SP,
                offset: 96,
                src: 1,
                width: 8,
                writeback: false
            }
        );
        // MOVD.W R30, -80(RSP) is a pre-index store that moves SP.
        assert_eq!(
            decode(0xf81b_0ffe, 0),
            Kind::Store {
                base: SP,
                offset: -80,
                src: 30,
                width: 8,
                writeback: true
            }
        );
    }

    #[test]
    fn branches_resolve_targets() {
        // CALL with imm26 = -0x200fe words at 0xaa418.
        assert_eq!(
            decode(0x97fd_ff02, 0xaa418),
            Kind::Call {
                target: Some(0xaa418 - 0x803f8)
            }
        );
        // BLS 68(PC).
        assert_eq!(
            decode(0x5400_0889, 0x1000),
            Kind::Jump {
                target: Some(0x1000 + 68 * 4),
                conditional: true
            }
        );
        assert_eq!(decode(0xd65f_03c0, 0), Kind::Ret);
    }
}
