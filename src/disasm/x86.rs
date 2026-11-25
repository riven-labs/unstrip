//! x86 instruction decoding, as far as the code scanners need it: the length
//! of every instruction, and the operands of the few forms they model. It
//! reads amd64 code with [`decode`] and 386 code with [`decode32`].
//!
//! A scanner walks one function at a time from its entry, so a length the
//! decoder gets wrong costs the rest of that function and nothing else.
//! Anything it does not model is reported as [`Kind::Other`] with the
//! general-purpose registers it may write and whether it may write memory,
//! erring towards "may write". An opcode it cannot size is `None`, and the
//! caller stops.

/// General-purpose register numbers, as ModRM and REX encode them. On 386
/// they name the 32-bit registers (`RAX` is EAX).
pub(crate) const RAX: u8 = 0;
pub(crate) const RCX: u8 = 1;
pub(crate) const RDX: u8 = 2;
pub(crate) const RBX: u8 = 3;
pub(crate) const RSP: u8 = 4;
pub(crate) const RBP: u8 = 5;
pub(crate) const RSI: u8 = 6;
pub(crate) const RDI: u8 = 7;

/// Every general-purpose register.
pub(crate) const ALL_REGS: u16 = 0xffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Insn {
    pub(crate) len: usize,
    pub(crate) kind: Kind,
    /// The address a memory operand names outright, whatever the instruction
    /// does with it: RIP-relative on amd64, a displacement with no base
    /// register on 386. There an index register may still scale into it, and
    /// the address is the start of a table.
    pub(crate) mem_target: Option<u64>,
}

/// The mode the code runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// amd64: REX prefixes, RIP-relative operands.
    Long,
    /// 386: no REX, `INC`/`DEC` at 0x40 to 0x4f, absolute operands, and
    /// addresses that wrap at 4 GiB.
    Bits32,
}

/// A memory operand the scanner can name: a base register (with an index
/// register and its scale, if any) plus a displacement, or an absolute
/// address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mem {
    Base {
        reg: u8,
        index: Option<(u8, u8)>,
        disp: i64,
    },
    Abs(u64),
    /// An address the scanner does not name, such as one pushed to the stack.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Src {
    Reg(u8),
    Imm(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// An address in a register: `LEA r64, [rip+disp32]` on amd64,
    /// `LEA r32, [disp32]` on 386.
    Lea {
        dst: u8,
        target: u64,
    },
    /// A constant written to the full register: `MOV r32, imm32` (which
    /// zero-extends on amd64), `MOV r64, imm64`, `MOV r/m64, imm32`, and the
    /// `XOR r32, r32` zero idiom.
    MovImm {
        dst: u8,
        value: u64,
    },
    /// `MOV r64, r64`, or `MOV r32, r32` on 386. A 32-bit move on amd64
    /// truncates and comes back as `Other`.
    MovReg {
        dst: u8,
        src: u8,
    },
    /// `MOV m, r` or `MOV m, imm32`, `width` bytes.
    Store {
        mem: Mem,
        src: Src,
        width: u8,
    },
    Call {
        target: Option<u64>,
    },
    Jump {
        target: Option<u64>,
        conditional: bool,
    },
    Ret,
    /// `INT3`, `UD2`, `HLT` and the like: no fall-through.
    Stop,
    Other {
        /// Registers the instruction may write, one bit each.
        writes: u16,
        /// Memory the instruction may write.
        mem_write: Option<Mem>,
    },
}

/// Decodes the amd64 instruction at the start of `code`, which sits at `pc`.
pub(crate) fn decode(code: &[u8], pc: u64) -> Option<Insn> {
    decode_in(code, pc, Mode::Long)
}

/// Decodes the 386 instruction at the start of `code`, which sits at `pc`.
pub(crate) fn decode32(code: &[u8], pc: u64) -> Option<Insn> {
    decode_in(code, pc, Mode::Bits32)
}

fn decode_in(code: &[u8], pc: u64, mode: Mode) -> Option<Insn> {
    let bits32 = mode == Mode::Bits32;
    let mut i = 0usize;
    let mut opsize16 = false;
    let mut rep = 0u8;
    // An FS or GS override: on 386 an operand with no base register is then
    // thread-local storage, not an address in the image.
    let mut tls = false;
    loop {
        let b = *code.get(i)?;
        match b {
            0x66 => opsize16 = true,
            0xf2 | 0xf3 => rep = b,
            // 16-bit addressing has a different ModRM layout, and Go never
            // emits it.
            0x67 if bits32 => return None,
            0x64 | 0x65 => tls = true,
            0x67 | 0xf0 | 0x2e | 0x36 | 0x3e | 0x26 => (),
            _ => break,
        }
        i += 1;
        if i > 14 {
            return None;
        }
    }
    let mut rex = 0u8;
    if let Some(&b) = code.get(i) {
        if b & 0xf0 == 0x40 && !bits32 {
            rex = b;
            i += 1;
        }
    }
    let ctx = Ctx {
        pc,
        mode,
        tls: tls && bits32,
    };
    let w = rex & 0x08 != 0;
    let r_ext = (rex & 0x04) << 1;
    let x_ext = (rex & 0x02) << 2;
    let b_ext = (rex & 0x01) << 3;

    let op = *code.get(i)?;
    i += 1;
    // Immediate operand size: 2 with an operand-size prefix and no REX.W,
    // else 4 (a 64-bit operand takes a sign-extended 32-bit immediate).
    let opd = if opsize16 && !w { 2 } else { 4 };

    match op {
        0x0f => {
            let op2 = *code.get(i)?;
            i += 1;
            match op2 {
                0x38 => {
                    let op3 = *code.get(i)?;
                    i += 1;
                    let m = modrm(code, i, ctx, r_ext, x_ext, b_ext)?;
                    let writes = if (0xf0..=0xf7).contains(&op3) {
                        m.gpr_writes()
                    } else {
                        0
                    };
                    let mem_write = (op3 == 0xf1 && rep == 0).then_some(m.mem).flatten();
                    return m.finish(code, 0, other(writes, mem_write));
                }
                0x3a => {
                    let op3 = *code.get(i)?;
                    i += 1;
                    let m = modrm(code, i, ctx, r_ext, x_ext, b_ext)?;
                    let (writes, mem_write) = match op3 {
                        0x14..=0x17 => (m.rm_writes(), m.mem),
                        0x60..=0x63 => (1 << RCX, None),
                        _ => (0, None),
                    };
                    return m.finish(code, 1, other(writes, mem_write));
                }
                _ => return decode_0f(code, i, ctx, op2, rep, opsize16, r_ext, x_ext, b_ext),
            }
        }
        // On 386, C4, C5 and 62 are VEX and EVEX only when the next byte
        // would be a register ModRM; otherwise they are LES, LDS and BOUND.
        0xc4 | 0xc5 | 0x62 if bits32 && *code.get(i)? >> 6 != 3 => {
            let m = modrm(code, i, ctx, 0, 0, 0)?;
            let writes = if op == 0x62 { 0 } else { 1 << m.reg };
            return m.finish(code, 0, other(writes, None));
        }
        0xc4 | 0xc5 => return decode_vex(code, i, ctx, op),
        0x62 => return decode_evex(code, i, ctx),
        _ => (),
    }

    let has_modrm = matches!(op,
        0x00..=0x03 | 0x08..=0x0b | 0x10..=0x13 | 0x18..=0x1b | 0x20..=0x23 | 0x28..=0x2b
        | 0x30..=0x33 | 0x38..=0x3b | 0x63 | 0x69 | 0x6b | 0x80 | 0x81 | 0x83..=0x8f
        | 0xc0 | 0xc1 | 0xc6 | 0xc7 | 0xd0..=0xd3 | 0xd8..=0xdf | 0xf6 | 0xf7 | 0xfe | 0xff)
        || (bits32 && op == 0x82);

    if !has_modrm {
        let next = |n: usize| ctx.wrap(pc.wrapping_add((i + n) as u64));
        let rel8 = |at: usize| -> Option<u64> {
            let d = *code.get(at)? as i8 as i64;
            Some(ctx.wrap(next(1).wrapping_add(d as u64)))
        };
        // MOV between the accumulator and an absolute address (moffs).
        let moffs = |at: usize| read_uint(code, at, 4);
        let mut mem_target = None;
        let (imm, kind) = match op {
            0x04 | 0x0c | 0x14 | 0x1c | 0x24 | 0x2c | 0x34 => (1, other(1 << RAX, None)),
            0x05 | 0x0d | 0x15 | 0x1d | 0x25 | 0x2d | 0x35 => (opd, other(1 << RAX, None)),
            0x3c | 0xa8 => (1, other(0, None)),
            0x3d | 0xa9 => (opd, other(0, None)),
            0x50..=0x57 => (0, other(1 << RSP, Some(Mem::Unknown))),
            0x58..=0x5f => (0, other((1 << RSP) | (1 << ((op & 7) | b_ext)), None)),
            0x68 => (opd, other(1 << RSP, Some(Mem::Unknown))),
            0x6a => (1, other(1 << RSP, Some(Mem::Unknown))),
            0x70..=0x7f => (
                1,
                Kind::Jump {
                    target: rel8(i),
                    conditional: true,
                },
            ),
            0x90 if b_ext == 0 => (0, other(0, None)),
            0x90..=0x97 => (0, other((1 << RAX) | (1 << ((op & 7) | b_ext)), None)),
            0x98 | 0x9e | 0x9f => (0, other(1 << RAX, None)),
            0x99 => (0, other(1 << RDX, None)),
            0x9b | 0xf5 | 0xf8..=0xfd => (0, other(0, None)),
            0x9c => (0, other(1 << RSP, Some(Mem::Unknown))),
            0x9d => (0, other(1 << RSP, None)),
            0xa0..=0xa3 if bits32 => {
                let addr = moffs(i)?;
                let width = if op & 1 == 0 { 1 } else { opd as u8 };
                let mem = if ctx.tls {
                    Mem::Unknown
                } else {
                    mem_target = Some(addr);
                    Mem::Abs(addr)
                };
                let kind = match op {
                    0xa0 | 0xa1 => other(1 << RAX, None),
                    _ => Kind::Store {
                        mem,
                        src: Src::Reg(RAX),
                        width,
                    },
                };
                (4, kind)
            }
            0xa0 | 0xa1 => (8, other(1 << RAX, None)),
            0xa2 | 0xa3 => (8, other(0, Some(Mem::Unknown))),
            0x6c..=0x6f | 0xa4..=0xa7 | 0xaa..=0xaf => (0, other(ALL_REGS, Some(Mem::Unknown))),
            0xb0..=0xb7 => (1, other(1 << ((op & 7) | b_ext), None)),
            0xb8..=0xbf => {
                let dst = (op & 7) | b_ext;
                let n = if w { 8 } else { opd };
                let value = read_uint(code, i, n)?;
                let kind = if n == 2 {
                    other(1 << dst, None)
                } else {
                    Kind::MovImm { dst, value }
                };
                (n, kind)
            }
            0xc2 => (2, Kind::Ret),
            0xc3 => (0, Kind::Ret),
            0xcb | 0xcc | 0xf1 | 0xf4 => (0, Kind::Stop),
            0xca => (2, Kind::Stop),
            0xc8 => (3, other(ALL_REGS, Some(Mem::Unknown))),
            0xc9 => (0, other((1 << RSP) | (1 << RBP), None)),
            0xcd => (1, other(ALL_REGS, Some(Mem::Unknown))),
            0xcf => (0, Kind::Stop),
            0xd7 => (0, other(1 << RAX, None)),
            0xe0..=0xe3 => (
                1,
                Kind::Jump {
                    target: rel8(i),
                    conditional: true,
                },
            ),
            0xe4 | 0xe5 => (1, other(1 << RAX, None)),
            0xe6 | 0xe7 => (1, other(0, None)),
            0xe8 | 0xe9 => {
                let d = read_uint(code, i, 4)? as u32 as i32 as i64;
                let target = Some(ctx.wrap(next(4).wrapping_add(d as u64)));
                let kind = if op == 0xe8 {
                    Kind::Call { target }
                } else {
                    Kind::Jump {
                        target,
                        conditional: false,
                    }
                };
                (4, kind)
            }
            0xeb => (
                1,
                Kind::Jump {
                    target: rel8(i),
                    conditional: false,
                },
            ),
            0xec | 0xed => (0, other(1 << RAX, None)),
            0xee | 0xef => (0, other(0, None)),
            // Opcodes amd64 gave up for REX and other uses.
            0x06 | 0x0e | 0x16 | 0x1e | 0x60 if bits32 => (0, other(1 << RSP, Some(Mem::Unknown))),
            0x07 | 0x17 | 0x1f if bits32 => (0, other(1 << RSP, None)),
            0x61 if bits32 => (0, other(ALL_REGS, None)),
            0x27 | 0x2f | 0x37 | 0x3f | 0xd6 if bits32 => (0, other(1 << RAX, None)),
            0xd4 | 0xd5 if bits32 => (1, other(1 << RAX, None)),
            0x40..=0x4f if bits32 => (0, other(1 << (op & 7), None)),
            0xce if bits32 => (0, other(ALL_REGS, Some(Mem::Unknown))),
            0x9a if bits32 => (opd + 2, Kind::Call { target: None }),
            0xea if bits32 => (
                opd + 2,
                Kind::Jump {
                    target: None,
                    conditional: false,
                },
            ),
            _ => return None,
        };
        let len = i + imm;
        if len > code.len() {
            return None;
        }
        return Some(Insn {
            len,
            kind,
            mem_target,
        });
    }

    let m = modrm(code, i, ctx, r_ext, x_ext, b_ext)?;
    let reg3 = (m.reg & 7) as usize;
    let imm = match op {
        0x69 | 0x81 | 0xc7 => opd,
        0x6b | 0x80 | 0x82 | 0x83 | 0xc0 | 0xc1 | 0xc6 => 1,
        0xf6 if reg3 < 2 => 1,
        0xf7 if reg3 < 2 => opd,
        _ => 0,
    };
    let width = if op & 1 == 0 && matches!(op, 0x88 | 0xc6) {
        1
    } else if w {
        8
    } else {
        opd as u8
    };
    // A register-to-register move the full width of the register.
    let full = w || (bits32 && !opsize16);
    let kind = match op {
        // The target is filled in by `finish`, which knows the length.
        0x8d if m.mem_is_rip && w => Kind::Lea {
            dst: m.reg,
            target: 0,
        },
        0x8d if bits32 && !opsize16 && m.abs_target.is_some() && !m.abs_indexed => Kind::Lea {
            dst: m.reg,
            target: m.abs_target?,
        },
        0x8d => other(1 << m.reg, None),
        0xc7 if reg3 == 0 => {
            let raw = read_uint(code, m.end, opd)?;
            let value = if w {
                raw as u32 as i32 as i64 as u64
            } else {
                raw
            };
            match m.rm_reg {
                Some(dst) if opd == 4 => Kind::MovImm { dst, value },
                Some(dst) => other(1 << dst, None),
                None => Kind::Store {
                    mem: m.mem?,
                    src: Src::Imm(value),
                    width,
                },
            }
        }
        0x89 => match m.rm_reg {
            Some(dst) if full => Kind::MovReg { dst, src: m.reg },
            Some(dst) => other(1 << dst, None),
            None => Kind::Store {
                mem: m.mem?,
                src: Src::Reg(m.reg),
                width,
            },
        },
        0x8b => match m.rm_reg {
            Some(src) if full => Kind::MovReg { dst: m.reg, src },
            _ => other(1 << m.reg, None),
        },
        0x31 | 0x33 | 0x29 | 0x2b if m.rm_reg == Some(m.reg) && !opsize16 => Kind::MovImm {
            dst: m.reg,
            value: 0,
        },
        // CMP and TEST write only the flags.
        0x38..=0x3b | 0x84 | 0x85 => other(0, None),
        0x80..=0x83 if reg3 == 7 => other(0, None),
        // ARPL on 386 writes its r/m operand.
        0x63 if bits32 => other(m.rm_writes(), m.mem),
        0xf6 | 0xf7 if reg3 < 2 => other(0, None),
        0xf6 | 0xf7 if reg3 >= 4 => other((1 << RAX) | (1 << RDX), None),
        // Register-destination forms: the memory operand is only read.
        0x02 | 0x03 | 0x0a | 0x0b | 0x12 | 0x13 | 0x1a | 0x1b | 0x22 | 0x23 | 0x2a | 0x2b
        | 0x32 | 0x33 | 0x63 | 0x69 | 0x6b | 0x8a => other(1 << m.reg, None),
        0x8e => other(0, None),
        0x86 | 0x87 => other(m.gpr_writes(), m.mem),
        0x8f => other(m.rm_writes() | (1 << RSP), m.mem),
        0xdf if m.rm_reg.is_some() => other(1 << RAX, None),
        0xd8..=0xdf => other(0, m.mem),
        0xfe | 0xff => match reg3 {
            0 | 1 => other(m.rm_writes(), m.mem),
            2 | 3 => Kind::Call { target: None },
            4 | 5 => Kind::Jump {
                target: None,
                conditional: false,
            },
            6 => other(1 << RSP, Some(Mem::Unknown)),
            _ => return None,
        },
        // What remains writes its r/m operand: ALU with an r/m destination,
        // shifts, MOV, NOT, NEG.
        _ => other(m.rm_writes(), m.mem),
    };
    m.finish(code, imm, kind)
}

#[allow(clippy::too_many_arguments)]
fn decode_0f(
    code: &[u8],
    i: usize,
    ctx: Ctx,
    op: u8,
    rep: u8,
    opsize16: bool,
    r_ext: u8,
    x_ext: u8,
    b_ext: u8,
) -> Option<Insn> {
    let no_modrm = match op {
        0x05 | 0x07 | 0x34 | 0x35 | 0x37 => Some(other(ALL_REGS, Some(Mem::Unknown))),
        0x0b => Some(Kind::Stop),
        0x06 | 0x08 | 0x09 | 0x0e | 0x30 | 0x77 | 0xa0 | 0xa8 | 0xaa => Some(other(0, None)),
        0x31..=0x33 => Some(other((1 << RAX) | (1 << RDX), None)),
        0xa1 | 0xa9 => Some(other(1 << RSP, None)),
        0xa2 => Some(other(ALL_REGS, None)),
        0xc8..=0xcf => Some(other(1 << ((op & 7) | b_ext), None)),
        0x80..=0x8f => {
            let d = read_uint(code, i, 4)? as u32 as i32 as i64;
            let target = ctx.wrap(ctx.pc.wrapping_add((i + 4) as u64).wrapping_add(d as u64));
            return Some(Insn {
                len: i + 4,
                kind: Kind::Jump {
                    target: Some(target),
                    conditional: true,
                },
                mem_target: None,
            });
        }
        _ => None,
    };
    if let Some(kind) = no_modrm {
        return Some(Insn {
            len: i,
            kind,
            mem_target: None,
        });
    }
    if matches!(op, 0x04 | 0x0a | 0x0c | 0x24..=0x27 | 0x36 | 0x39 | 0x3b..=0x3f) {
        return None;
    }
    let m = modrm(code, i, ctx, r_ext, x_ext, b_ext)?;
    let imm = match op {
        0x0f | 0x70..=0x73 | 0xa4 | 0xac | 0xba | 0xc2 | 0xc4..=0xc6 => 1,
        _ => 0,
    };
    let reg3 = m.reg & 7;
    let (writes, mem_write) = match op {
        0x00 | 0x01 | 0xc7 => (ALL_REGS, m.mem),
        0x02 | 0x03 | 0x2c | 0x2d | 0x50 | 0xaf | 0xb6 | 0xb7 | 0xbe | 0xbf | 0xb8 | 0xbc
        | 0xbd | 0xc5 | 0xd7 => (1 << m.reg, None),
        0x40..=0x4f => (1 << m.reg, None),
        0x7e if rep == 0 => (m.rm_writes(), m.mem),
        0x90..=0x9f => (m.rm_writes(), m.mem),
        0xa3 => (0, None),
        0xab | 0xb3 | 0xbb | 0xa4 | 0xa5 | 0xac | 0xad => (m.rm_writes(), m.mem),
        0xba if reg3 >= 5 => (m.rm_writes(), m.mem),
        0xba => (0, None),
        0xb0 | 0xb1 => (m.rm_writes() | (1 << RAX), m.mem),
        0xc0 | 0xc1 => (m.gpr_writes(), m.mem),
        0xae if m.rm_reg.is_none() => (0, m.mem),
        0x11 | 0x13 | 0x17 | 0x29 | 0x2b | 0x7f | 0xc3 | 0xe7 => (0, m.mem),
        0xd6 if opsize16 => (0, m.mem),
        _ => (0, None),
    };
    m.finish(code, imm, other(writes, mem_write))
}

/// VEX-encoded instructions (AVX, AVX2, BMI). `i` is the offset after the `C4`/`C5`.
fn decode_vex(code: &[u8], mut i: usize, ctx: Ctx, lead: u8) -> Option<Insn> {
    let (map, r_ext, x_ext, b_ext, vvvv, pp) = if lead == 0xc5 {
        let p = *code.get(i)?;
        i += 1;
        (1, ((!p >> 7) & 1) << 3, 0, 0, (!p >> 3) & 0xf, p & 3)
    } else {
        let p1 = *code.get(i)?;
        let p2 = *code.get(i + 1)?;
        i += 2;
        (
            p1 & 0x1f,
            ((!p1 >> 7) & 1) << 3,
            ((!p1 >> 6) & 1) << 3,
            ((!p1 >> 5) & 1) << 3,
            (!p2 >> 3) & 0xf,
            p2 & 3,
        )
    };
    let op = *code.get(i)?;
    i += 1;
    if map == 1 && op == 0x77 {
        return Some(Insn {
            len: i,
            kind: other(0, None),
            mem_target: None,
        });
    }
    if !(1..=3).contains(&map) {
        return None;
    }
    let m = modrm(code, i, ctx, r_ext, x_ext, b_ext)?;
    let imm = vex_imm(map, op);
    let gpr = vex_writes_gpr(map, op, pp);
    let writes = if gpr { m.gpr_writes() | (1 << vvvv) } else { 0 };
    let mem_write = vex_stores(map, op, pp).then_some(m.mem).flatten();
    m.finish(code, imm, other(writes, mem_write))
}

/// EVEX-encoded instructions (AVX-512). `i` is the offset after the `62`.
fn decode_evex(code: &[u8], mut i: usize, ctx: Ctx) -> Option<Insn> {
    let p0 = *code.get(i)?;
    let p1 = *code.get(i + 1)?;
    let _p2 = *code.get(i + 2)?;
    i += 3;
    let map = p0 & 7;
    let r_ext = ((!p0 >> 7) & 1) << 3;
    let x_ext = ((!p0 >> 6) & 1) << 3;
    let b_ext = ((!p0 >> 5) & 1) << 3;
    let vvvv = (!p1 >> 3) & 0xf;
    let pp = p1 & 3;
    let op = *code.get(i)?;
    i += 1;
    if !matches!(map, 1 | 2 | 3 | 5 | 6) {
        return None;
    }
    let m = modrm(code, i, ctx, r_ext, x_ext, b_ext)?;
    let imm = if map <= 3 { vex_imm(map, op) } else { 0 };
    let gpr = map <= 3 && vex_writes_gpr(map, op, pp);
    let writes = if gpr { m.gpr_writes() | (1 << vvvv) } else { 0 };
    // AVX-512 adds down-converting and scatter stores; any of those in maps 2
    // and 3 is treated as a possible store.
    let stores = map <= 3 && (vex_stores(map, op, pp) || map == 2 && pp == 2)
        || map == 2 && (0xa0..=0xa3).contains(&op);
    let mem_write = stores.then_some(m.mem).flatten();
    m.finish(code, imm, other(writes, mem_write))
}

fn vex_imm(map: u8, op: u8) -> usize {
    match map {
        3 => 1,
        1 if matches!(op, 0x70..=0x73 | 0xc2 | 0xc4..=0xc6) => 1,
        _ => 0,
    }
}

/// VEX and EVEX opcodes that can write a general-purpose register.
fn vex_writes_gpr(map: u8, op: u8, pp: u8) -> bool {
    match map {
        1 => {
            matches!(
                op,
                0x2c | 0x2d | 0x50 | 0x7e | 0x90..=0x93 | 0x98 | 0x99 | 0xc5 | 0xd7
            ) && !(op == 0x7e && pp == 2)
        }
        2 => matches!(op, 0xf0..=0xf7),
        3 => matches!(op, 0x14..=0x17 | 0x60..=0x63 | 0xf0),
        _ => false,
    }
}

/// VEX and EVEX opcodes whose memory operand is a destination.
fn vex_stores(map: u8, op: u8, pp: u8) -> bool {
    match map {
        1 => {
            matches!(
                op,
                0x11 | 0x13 | 0x17 | 0x29 | 0x2b | 0x7f | 0xd6 | 0xe7 | 0x91
            ) || (op == 0x7e && pp != 2)
        }
        2 => matches!(op, 0x2e | 0x2f | 0x8e | 0xa0..=0xa3),
        3 => matches!(op, 0x14..=0x17 | 0x19 | 0x1d | 0x39 | 0x3b | 0x7a | 0x7b),
        _ => false,
    }
}

fn other(writes: u16, mem_write: Option<Mem>) -> Kind {
    Kind::Other { writes, mem_write }
}

/// What decoding one instruction needs to know besides its bytes.
#[derive(Clone, Copy)]
struct Ctx {
    pc: u64,
    mode: Mode,
    /// An FS or GS override on 386.
    tls: bool,
}

impl Ctx {
    /// An address as the mode computes it: 386 addresses wrap at 4 GiB.
    fn wrap(self, addr: u64) -> u64 {
        match self.mode {
            Mode::Long => addr,
            Mode::Bits32 => addr & 0xffff_ffff,
        }
    }
}

/// A decoded ModRM byte with its SIB and displacement.
struct ModRm {
    /// Offset after the displacement.
    end: usize,
    reg: u8,
    /// The register operand when `mod == 3`.
    rm_reg: Option<u8>,
    /// The memory operand when `mod != 3`.
    mem: Option<Mem>,
    mem_is_rip: bool,
    rip_disp: i64,
    /// On 386, the address of a memory operand with no base register.
    abs_target: Option<u64>,
    /// An index register scales into `abs_target`.
    abs_indexed: bool,
    pc: u64,
}

impl ModRm {
    fn gpr_writes(&self) -> u16 {
        (1 << self.reg) | self.rm_writes()
    }

    fn rm_writes(&self) -> u16 {
        match self.rm_reg {
            Some(r) => 1 << r,
            None => 0,
        }
    }

    /// The finished instruction: `imm` immediate bytes follow the
    /// displacement. A RIP-relative target is relative to the end of the
    /// whole instruction, immediate included.
    /// None when the instruction runs past the end of `code`.
    fn finish(&self, code: &[u8], imm: usize, kind: Kind) -> Option<Insn> {
        let len = self.end + imm;
        if len > code.len() {
            return None;
        }
        if !self.mem_is_rip {
            return Some(Insn {
                len,
                kind,
                mem_target: self.abs_target,
            });
        }
        let target = self
            .pc
            .wrapping_add(len as u64)
            .wrapping_add(self.rip_disp as u64);
        let kind = match kind {
            Kind::Lea { dst, .. } => Kind::Lea { dst, target },
            Kind::Store { src, width, .. } => Kind::Store {
                mem: Mem::Abs(target),
                src,
                width,
            },
            Kind::Other {
                writes,
                mem_write: Some(_),
            } => Kind::Other {
                writes,
                mem_write: Some(Mem::Abs(target)),
            },
            kind => kind,
        };
        Some(Insn {
            len,
            kind,
            mem_target: Some(target),
        })
    }
}

fn modrm(code: &[u8], i: usize, ctx: Ctx, r_ext: u8, x_ext: u8, b_ext: u8) -> Option<ModRm> {
    let b = *code.get(i)?;
    let md = b >> 6;
    let reg = ((b >> 3) & 7) | r_ext;
    let rm = b & 7;
    let mut end = i + 1;
    let mut res = ModRm {
        end,
        reg,
        rm_reg: None,
        mem: None,
        mem_is_rip: false,
        rip_disp: 0,
        abs_target: None,
        abs_indexed: false,
        pc: ctx.pc,
    };
    if md == 3 {
        res.rm_reg = Some(rm | b_ext);
        return Some(res);
    }
    let mut base = Some(rm | b_ext);
    let mut index = None;
    let mut absolute = false;
    if rm == 4 {
        let sib = *code.get(end)?;
        end += 1;
        let reg = ((sib >> 3) & 7) | x_ext;
        if reg != 4 {
            index = Some((reg, 1u8 << (sib >> 6)));
        }
        if sib & 7 == 5 && md == 0 {
            base = None;
            absolute = true;
        } else {
            base = Some((sib & 7) | b_ext);
        }
    }
    let disp_len = match md {
        0 if rm == 5 || absolute => 4,
        0 => 0,
        1 => 1,
        _ => 4,
    };
    let disp = match disp_len {
        0 => 0,
        1 => *code.get(end)? as i8 as i64,
        _ => read_uint(code, end, 4)? as u32 as i32 as i64,
    };
    end += disp_len;
    res.end = end;
    if ctx.mode == Mode::Bits32 && md == 0 && (rm == 5 || absolute) {
        // A displacement with no base is an absolute address on 386.
        let addr = disp as u64 & 0xffff_ffff;
        res.mem = Some(Mem::Unknown);
        if !ctx.tls {
            res.abs_target = Some(addr);
            res.abs_indexed = index.is_some();
            if index.is_none() {
                res.mem = Some(Mem::Abs(addr));
            }
        }
        return Some(res);
    }
    if md == 0 && rm == 5 {
        res.mem_is_rip = true;
        res.rip_disp = disp;
        res.mem = Some(Mem::Unknown);
        return Some(res);
    }
    res.mem = Some(match (base, index) {
        (Some(reg), index) => Mem::Base { reg, index, disp },
        (None, None) => Mem::Abs(disp as u64),
        (None, Some(_)) => Mem::Unknown,
    });
    Some(res)
}

fn read_uint(code: &[u8], at: usize, n: usize) -> Option<u64> {
    let bytes = code.get(at..at.checked_add(n)?)?;
    let mut v = 0u64;
    for (k, b) in bytes.iter().enumerate() {
        v |= (*b as u64) << (8 * k);
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(bytes: &[u8]) -> Insn {
        decode(bytes, 0x1000).expect("decodes")
    }

    #[test]
    fn lea_rip_resolves_against_the_next_instruction() {
        // LEAQ 0x10(IP), CX
        let insn = one(&[0x48, 0x8d, 0x0d, 0x10, 0x00, 0x00, 0x00]);
        assert_eq!(insn.len, 7);
        assert_eq!(
            insn.kind,
            Kind::Lea {
                dst: RCX,
                target: 0x1017
            }
        );
    }

    #[test]
    fn mov_imm_forms_zero_or_sign_extend() {
        // MOVL $19, CX
        let insn = one(&[0xb9, 0x13, 0, 0, 0]);
        assert_eq!(insn.len, 5);
        assert_eq!(
            insn.kind,
            Kind::MovImm {
                dst: RCX,
                value: 19
            }
        );
        // MOVL $1, R9
        let insn = one(&[0x41, 0xb9, 0x01, 0, 0, 0]);
        assert_eq!(insn.kind, Kind::MovImm { dst: 9, value: 1 });
        // MOVQ $-1, AX
        let insn = one(&[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(insn.len, 7);
        assert_eq!(
            insn.kind,
            Kind::MovImm {
                dst: RAX,
                value: u64::MAX
            }
        );
        // XORL AX, AX
        assert_eq!(one(&[0x31, 0xc0]).kind, Kind::MovImm { dst: RAX, value: 0 });
    }

    #[test]
    fn stores_name_base_and_displacement() {
        // MOVQ $28, 8(AX)
        let insn = one(&[0x48, 0xc7, 0x40, 0x08, 0x1c, 0, 0, 0]);
        assert_eq!(insn.len, 8);
        assert_eq!(
            insn.kind,
            Kind::Store {
                mem: Mem::Base {
                    reg: RAX,
                    index: None,
                    disp: 8
                },
                src: Src::Imm(28),
                width: 8
            }
        );
        // MOVQ CX, (AX)
        let insn = one(&[0x48, 0x89, 0x08]);
        assert_eq!(
            insn.kind,
            Kind::Store {
                mem: Mem::Base {
                    reg: RAX,
                    index: None,
                    disp: 0
                },
                src: Src::Reg(RCX),
                width: 8
            }
        );
        // MOVQ AX, 0x10(SP) goes through a SIB byte.
        let insn = one(&[0x48, 0x89, 0x44, 0x24, 0x10]);
        assert_eq!(insn.len, 5);
        assert_eq!(
            insn.kind,
            Kind::Store {
                mem: Mem::Base {
                    reg: RSP,
                    index: None,
                    disp: 0x10
                },
                src: Src::Reg(RAX),
                width: 8
            }
        );
    }

    #[test]
    fn lengths_of_common_go_instructions() {
        let cases: &[(&[u8], usize)] = &[
            (&[0x49, 0x3b, 0x66, 0x10], 4),                // CMPQ SP, 16(R14)
            (&[0x0f, 0x86, 0x10, 0x01, 0, 0], 6),          // JLS rel32
            (&[0x55], 1),                                  // PUSHQ BP
            (&[0x48, 0x89, 0xe5], 3),                      // MOVQ SP, BP
            (&[0x48, 0x83, 0xec, 0x40], 4),                // SUBQ $64, SP
            (&[0x83, 0x3d, 0, 0, 0, 0, 0], 7),             // CMPL x(SB), $0
            (&[0x44, 0x0f, 0x11, 0x7c, 0x24, 0x08], 6),    // MOVUPS X15, 8(SP)
            (&[0x0f, 0x1f, 0x44, 0x00, 0x00], 5),          // NOPL
            (&[0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0], 9), // NOPW
            (&[0xc5, 0xfe, 0x6f, 0x06], 4),                // VMOVDQU (SI), Y0
            (&[0xc4, 0xe3, 0x7d, 0x39, 0xc1, 0x01], 6),    // VEXTRACTI128
            (&[0x62, 0xf1, 0x7e, 0x48, 0x6f, 0x06], 6),    // VMOVDQU32 (SI), Z0
            (&[0x66, 0x0f, 0x3a, 0x0f, 0xc1, 0x08], 6),    // PALIGNR $8
            (&[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8], 10),   // MOVABSQ
            (&[0xf3, 0x48, 0xab], 3),                      // REP STOSQ
            (&[0x66, 0x81, 0x38, 0x34, 0x12], 5),          // CMPW (AX), $0x1234
            (&[0xf6, 0x40, 0x10, 0x01], 4),                // TESTB $1, 16(AX)
        ];
        for (bytes, len) in cases {
            assert_eq!(one(bytes).len, *len, "length of {bytes:02x?}");
        }
    }

    #[test]
    fn truncated_input_is_refused() {
        assert_eq!(decode(&[0x48, 0x8d, 0x0d, 0x10], 0), None);
        assert_eq!(decode(&[], 0), None);
    }

    fn one32(bytes: &[u8]) -> Insn {
        let insn = decode32(bytes, 0x1000).expect("decodes");
        assert_eq!(insn.len, bytes.len(), "length of {bytes:02x?}");
        insn
    }

    #[test]
    fn decode32_names_absolute_operands() {
        // LEAL main.counterMu(SB), AX
        let insn = one32(&[0x8d, 0x05, 0x78, 0x97, 0x5d, 0x08]);
        assert_eq!(
            insn.kind,
            Kind::Lea {
                dst: RAX,
                target: 0x085d_9778
            }
        );
        assert_eq!(insn.mem_target, Some(0x085d_9778));
        // MOVL AX, main.requests(SB)
        let insn = one32(&[0x89, 0x05, 0x70, 0x97, 0x5d, 0x08]);
        assert_eq!(
            insn.kind,
            Kind::Store {
                mem: Mem::Abs(0x085d_9770),
                src: Src::Reg(RAX),
                width: 4
            }
        );
        // MOVL GS:0, CX reads thread-local storage, not the image.
        assert_eq!(one32(&[0x65, 0x8b, 0x0d, 0, 0, 0, 0]).mem_target, None);
        // MOVL table(SB)(CX*4), AX names the table; LEAL of it is no
        // constant address.
        let table = [0x8b, 0x04, 0x8d, 0x00, 0x10, 0x00, 0x08];
        assert_eq!(one32(&table).mem_target, Some(0x0800_1000));
        let lea = one32(&[0x8d, 0x04, 0x8d, 0x00, 0x10, 0x00, 0x08]);
        assert!(
            matches!(lea.kind, Kind::Other { .. }),
            "an indexed LEA is not an address"
        );
    }

    #[test]
    fn decode32_has_no_rex_and_wraps_at_4_gib() {
        // INCL AX; DECL CX then NOP: 0x40 to 0x4f are instructions here.
        assert_eq!(one32(&[0x40]).kind, other(1 << RAX, None));
        assert_eq!(decode32(&[0x49, 0x90], 0).unwrap().len, 1);
        // MOVL AX, CX copies the whole register.
        assert_eq!(
            one32(&[0x89, 0xc1]).kind,
            Kind::MovReg { dst: RCX, src: RAX }
        );
        // CALL internal/sync.(*Mutex).Lock from a Go 1.26 linux/386 build.
        let insn = decode32(&[0xe8, 0x4c, 0xe7, 0xe6, 0xff], 0x826_916f).unwrap();
        assert_eq!(
            insn.kind,
            Kind::Call {
                target: Some(0x80d_78c0)
            }
        );
        // A backward call near address zero wraps to the top of 4 GiB.
        let insn = decode32(&[0xe8, 0xf0, 0xff, 0xff, 0xff], 0x8).unwrap();
        assert_eq!(
            insn.kind,
            Kind::Call {
                target: Some(0xffff_fffd)
            }
        );
    }

    #[test]
    fn decode32_tells_vex_from_les() {
        // VZEROUPPER: the byte after C5 has its top two bits set.
        assert_eq!(one32(&[0xc5, 0xf8, 0x77]).len, 3);
        // LES AX, (CX): it does not.
        assert_eq!(one32(&[0xc4, 0x01]).kind, other(1 << RAX, None));
    }
}
