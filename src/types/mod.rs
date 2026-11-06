use serde::Serialize;

use crate::error::Error;
use crate::gobin::GoBinary;
use crate::moduledata::{read_name_len, ModuleData};
use crate::Result;

/// A recovered Go type. v1 captures the universally-present header fields
/// (size, kind, hash, name). Kind-specific decoding for slices, pointers,
/// structs, and maps lives in [`KindData`]; we attempt those opportunistically
/// and fall through to `Other` on failure rather than aborting a whole pass.
#[derive(Debug, Clone, Default, Serialize)]
#[non_exhaustive]
pub struct Type {
    pub addr: u64,
    pub name: String,
    pub kind: KindName,
    pub size: u64,
    pub ptr_bytes: u64,
    pub hash: u32,
    pub tflag: u8,
    pub kind_data: KindData,
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq, Hash)]
pub enum KindName {
    #[default]
    Invalid,
    Bool,
    Int,
    Int8,
    Int16,
    Int32,
    Int64,
    Uint,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uintptr,
    Float32,
    Float64,
    Complex64,
    Complex128,
    Array,
    Chan,
    Func,
    Interface,
    Map,
    Pointer,
    Slice,
    String,
    Struct,
    UnsafePointer,
    Unknown(u8),
}

impl KindName {
    pub fn from_byte(b: u8) -> Self {
        // Kind enum values from `internal/abi/type.go`. The high bits are
        // flags (KindDirectIface = 1<<5, KindGCProg = 1<<6); mask them off.
        match b & 0x1f {
            0 => KindName::Invalid,
            1 => KindName::Bool,
            2 => KindName::Int,
            3 => KindName::Int8,
            4 => KindName::Int16,
            5 => KindName::Int32,
            6 => KindName::Int64,
            7 => KindName::Uint,
            8 => KindName::Uint8,
            9 => KindName::Uint16,
            10 => KindName::Uint32,
            11 => KindName::Uint64,
            12 => KindName::Uintptr,
            13 => KindName::Float32,
            14 => KindName::Float64,
            15 => KindName::Complex64,
            16 => KindName::Complex128,
            17 => KindName::Array,
            18 => KindName::Chan,
            19 => KindName::Func,
            20 => KindName::Interface,
            21 => KindName::Map,
            22 => KindName::Pointer,
            23 => KindName::Slice,
            24 => KindName::String,
            25 => KindName::Struct,
            26 => KindName::UnsafePointer,
            other => KindName::Unknown(other),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            KindName::Invalid => "invalid",
            KindName::Bool => "bool",
            KindName::Int => "int",
            KindName::Int8 => "int8",
            KindName::Int16 => "int16",
            KindName::Int32 => "int32",
            KindName::Int64 => "int64",
            KindName::Uint => "uint",
            KindName::Uint8 => "uint8",
            KindName::Uint16 => "uint16",
            KindName::Uint32 => "uint32",
            KindName::Uint64 => "uint64",
            KindName::Uintptr => "uintptr",
            KindName::Float32 => "float32",
            KindName::Float64 => "float64",
            KindName::Complex64 => "complex64",
            KindName::Complex128 => "complex128",
            KindName::Array => "array",
            KindName::Chan => "chan",
            KindName::Func => "func",
            KindName::Interface => "interface",
            KindName::Map => "map",
            KindName::Pointer => "pointer",
            KindName::Slice => "slice",
            KindName::String => "string",
            KindName::Struct => "struct",
            KindName::UnsafePointer => "unsafe.Pointer",
            KindName::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum KindData {
    #[default]
    None,
    Pointer {
        elem: u64,
    },
    Slice {
        elem: u64,
    },
    Array {
        elem: u64,
        len: u64,
    },
    Chan {
        elem: u64,
        dir: u64,
    },
    Map {
        key: u64,
        elem: u64,
        /// Address of the runtime's internal bucket struct holding the
        /// hash/key/value/overflow layout. None when unmapped or truncated.
        #[serde(skip_serializing_if = "Option::is_none")]
        bucket: Option<u64>,
    },
    Struct {
        fields: Vec<StructField>,
    },
    Interface {
        methods: Vec<InterfaceMethod>,
    },
    Func {
        in_count: u16,
        out_count: u16,
        variadic: bool,
        /// Addresses of input parameter type entries. Populated when the
        /// funcType layout decode succeeds; empty otherwise.
        in_types: Vec<u64>,
        /// Addresses of output (return value) type entries.
        out_types: Vec<u64>,
    },
}

#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct InterfaceMethod {
    pub name: String,
    pub typ: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
#[non_exhaustive]
pub struct StructField {
    pub name: String,
    pub typ: u64,
    pub offset: u64,
    pub embedded: bool,
    /// The struct tag (`json:"user" db:"u"`), verbatim, or empty when the field
    /// has none. The tag is stored in the field's name encoding right after the
    /// name and survives obfuscation, so it reconstructs a garbled struct's
    /// schema even when other names are hashed.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tag: String,
}

/// Bytes of the `_type` header at pointer size `ps`: size, ptrdata (uintptrs),
/// hash, tflag, align, fieldAlign, kind, equal, gcdata (pointers), str and
/// ptrToThis (int32 offsets). 48 on 64-bit, 32 on 32-bit.
pub(crate) fn type_header_size(ps: usize) -> usize {
    4 * ps + 16
}

/// A little-endian word of `ps` bytes (4 or 8) at `off`.
fn le_word(buf: &[u8], off: usize, ps: usize) -> u64 {
    if ps == 8 {
        u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
    } else {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as u64
    }
}

/// Recover types using the `Mode::Focused` strategy: typelinks-driven walk
/// plus child reference following. Skips primitive-leaf entries and other
/// catalog-padding the typelinks walk doesn't reach naturally. This is the
/// default and produces the type set most analysts actually look up by name.
pub fn recover_all(bin: &GoBinary, md: &ModuleData) -> Result<Vec<Type>> {
    recover_with_mode(bin, md, Mode::Focused)
}

/// Recover types in the requested mode. `Mode::Full` adds a linear scan of
/// `[md.types, md.etypes)` to surface every type-header-shaped entry the
/// typelinks walk missed, matching GoReSym's catalog breadth for users
/// who want one-for-one parity.
pub fn recover_with_mode(bin: &GoBinary, md: &ModuleData, mode: Mode) -> Result<Vec<Type>> {
    let mut types = recover_focused(bin, md)?;
    if matches!(mode, Mode::Full) {
        let seen: std::collections::HashSet<u64> = types.iter().map(|t| t.addr).collect();
        let extras = linear_scan_types_region(bin, md, &seen);
        types.extend(extras);
    }
    decode_field_offsets(&mut types, offset_embed_era(bin, md));
    Ok(types)
}

/// Whether the binary stores struct field offsets the Go 1.18 way, when its
/// version says: the pclntab magic for Go 1.16-1.17 (old) and 1.20+ (new),
/// the buildinfo version between them (1.18 and 1.19 share a magic). None
/// when neither tells (a wiped buildinfo on a 1.18/1.19 magic).
fn offset_embed_era(bin: &GoBinary, md: &ModuleData) -> Option<bool> {
    let magic = bin
        .read_at_addr(md.pc_header_addr, 4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_le_bytes)?;
    match magic {
        crate::pclntab::MAGIC_1_16 => return Some(true),
        crate::pclntab::MAGIC_1_20 => return Some(false),
        crate::pclntab::MAGIC_1_18 => {}
        _ => return None,
    }
    let v = crate::buildinfo::BuildInfo::parse(bin).ok()?.go_version;
    let minor: u32 = v
        .strip_prefix("go1.")?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    Some(minor <= 18)
}

/// Go 1.18 and older store a struct field's `offsetEmbed` (`offset << 1 |
/// embedded`); Go 1.19 stores the offset and moves the embedded flag into
/// the name (CL 412138). `old` is the encoding the version says; without
/// one, a stored value at or past its struct's size anywhere in the binary
/// means the old encoding (a real offset is always below the size). Under
/// the old encoding every struct's offsets are halved (the low bit is the
/// embedded flag).
fn decode_field_offsets(types: &mut [Type], old: Option<bool>) {
    let old = old.unwrap_or_else(|| {
        types.iter().any(|t| match &t.kind_data {
            KindData::Struct { fields } => {
                fields.iter().any(|f| f.offset > 0 && f.offset >= t.size)
            }
            _ => false,
        })
    });
    if !old {
        return;
    }
    for t in types.iter_mut() {
        if let KindData::Struct { fields } = &mut t.kind_data {
            for f in fields.iter_mut() {
                f.embedded |= f.offset & 1 == 1;
                f.offset >>= 1;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Typelinks + child references. Default. Skips primitive leaves and
    /// other catalog-padding entries.
    Focused,
    /// Focused, then linear-scan the types region for every type-header-shaped
    /// entry we missed. Matches GoReSym's catalog breadth.
    Full,
}

/// Linear scan the types region for any 48-byte chunks that look like
/// `_type` headers we haven't already parsed. Catches primitive leaves
/// (uint8, int32, ...) the typelinks walk doesn't reach.
fn linear_scan_types_region(
    bin: &GoBinary,
    md: &ModuleData,
    already_seen: &std::collections::HashSet<u64>,
) -> Vec<Type> {
    let mut out = Vec::new();
    if md.etypes <= md.types {
        return out;
    }
    let region_size = (md.etypes - md.types) as usize;
    let Some(bytes) = bin.read_at_addr(md.types, region_size) else {
        return out;
    };

    // Walk pointer-aligned offsets and try to parse a type header at each.
    // Real types are aligned at uintptr boundaries; trying every pointer
    // catches them all without false-positive thrashing.
    let ps = bin.pointer_size();
    let hdr = type_header_size(ps);
    let mut offset = 0usize;
    while offset + hdr <= bytes.len() {
        let addr = md.types + offset as u64;
        if already_seen.contains(&addr) {
            offset += ps;
            continue;
        }
        if let Ok(t) = parse_type(bin, md, addr) {
            // Only emit if the header looks plausible: nonzero size, valid
            // kind, non-empty resolvable name. Without these filters we
            // emit hundreds of random false positives per binary.
            if t.size > 0
                && !matches!(t.kind, KindName::Invalid | KindName::Unknown(_))
                && !t.name.is_empty()
                && !t.name.starts_with("type@0x")
            {
                out.push(t);
            }
        }
        offset += ps;
    }
    out
}

/// Walks the typelinks slice to recover every linked-in Go type, then
/// follows each type's child references (pointer.elem, slice.elem, etc.) to
/// pull in the dependent types, typelinks alone misses struct types when
/// the program only ever holds the pointer flavor.
///
/// `typelinks` is a `[]int32` of offsets relative to `moduledata.types`.
/// Each offset points at the start of a `_type` struct. We read the common
/// header, resolve the name, dispatch to a kind-specific decoder, then queue
/// any addresses the decoder produced and parse those too. Deduplicated by
/// address; bounded by the [types, etypes) region.
fn recover_focused(bin: &GoBinary, md: &ModuleData) -> Result<Vec<Type>> {
    let ps = bin.pointer_size();
    if !matches!(ps, 4 | 8) || !bin.little_endian {
        // The kind-specific readers below (struct fields, map buckets, func
        // params) read little-endian words of the binary's pointer size.
        // Function names, moduledata, and itab/interface recovery already
        // handle big-endian; the type graph does not yet, so refuse rather than
        // return field offsets and names read in the wrong byte order.
        let order = if bin.little_endian {
            "little-endian"
        } else {
            "big-endian"
        };
        return Err(Error::TypeRecovery(format!(
            "type-graph recovery needs a little-endian 32- or 64-bit binary (got pointer size {ps}, {order})"
        )));
    }

    // Structural cap on total reachable types: the types region itself is
    // bounded, and each type takes at least one header (48 bytes on 64-bit,
    // 32 on 32-bit),
    // so this is a hard ceiling regardless of what typelinks claims.
    let types_region = md.etypes.saturating_sub(md.types) as usize;
    let max_types = types_region / type_header_size(ps);

    // The linked types: `typelinks`, or from Go 1.27 the descriptors walked
    // in place ([`ModuleData::type_addrs`]).
    let mut queue: Vec<u64> = md.type_addrs(bin)?;
    let mut seen: std::collections::BTreeMap<u64, Type> = std::collections::BTreeMap::new();

    while let Some(addr) = queue.pop() {
        if seen.len() >= max_types {
            // Hit the structural ceiling, every byte of the types region is
            // claimed. Anything left in the queue is either a duplicate or
            // pointing outside the region (and would be rejected below).
            break;
        }
        if seen.contains_key(&addr) {
            continue;
        }
        if addr < md.types || addr >= md.etypes {
            continue;
        }
        let t = match parse_type(bin, md, addr) {
            Ok(t) => t,
            Err(_) => continue,
        };
        for child in child_addrs(&t.kind_data) {
            // Only queue children inside the types region. Cuts attacker
            // ability to make us walk arbitrary memory via crafted pointers.
            // Cap the queue too so a wide fan-out can't blow memory before
            // the seen-set ceiling stops processing.
            if queue.len() >= 4 * max_types {
                break;
            }
            if child >= md.types && child < md.etypes && !seen.contains_key(&child) {
                queue.push(child);
            }
        }
        seen.insert(addr, t);
    }

    Ok(seen.into_values().collect())
}

fn child_addrs(kd: &KindData) -> Vec<u64> {
    match kd {
        KindData::Pointer { elem } | KindData::Slice { elem } => vec![*elem],
        KindData::Array { elem, .. } => vec![*elem],
        KindData::Chan { elem, .. } => vec![*elem],
        KindData::Map { key, elem, bucket } => {
            let mut v = vec![*key, *elem];
            if let Some(b) = bucket {
                v.push(*b);
            }
            v
        }
        KindData::Struct { fields } => fields.iter().map(|f| f.typ).collect(),
        KindData::Interface { methods } => methods.iter().map(|m| m.typ).collect(),
        KindData::Func {
            in_types,
            out_types,
            ..
        } => {
            // Walk callback signature types so struct types reachable only
            // through function fields end up in the recovered graph.
            let mut v = Vec::with_capacity(in_types.len() + out_types.len());
            v.extend_from_slice(in_types);
            v.extend_from_slice(out_types);
            v
        }
        _ => Vec::new(),
    }
}

pub(crate) fn parse_type(bin: &GoBinary, md: &ModuleData, addr: u64) -> Result<Type> {
    let ps = bin.pointer_size();
    let buf = bin
        .read_at_addr(addr, type_header_size(ps))
        .ok_or_else(|| Error::TypeRecovery(format!("type header at 0x{addr:x} unmapped")))?;

    let size = le_word(buf, 0, ps);
    let ptr_bytes = le_word(buf, ps, ps);
    let h = 2 * ps;
    let hash = u32::from_le_bytes(buf[h..h + 4].try_into().unwrap());
    let tflag = buf[h + 4];
    let kind_byte = buf[h + 7];
    let s = 4 * ps + 8;
    let str_off = i32::from_le_bytes(buf[s..s + 4].try_into().unwrap());

    let kind = KindName::from_byte(kind_byte);

    let name_addr = md.types.wrapping_add(str_off as i64 as u64);
    let mut name = read_name(bin, md, name_addr).unwrap_or_else(|_| format!("type@0x{addr:x}"));
    // TFlagExtraStar: the stored name has a leading `*` that Go uses for
    // binary-size sharing between `Foo` and `*Foo`. Strip it here so the
    // type's displayed name matches the source-language name.
    if tflag & TFLAG_EXTRA_STAR != 0 && name.starts_with('*') {
        name.remove(0);
    }

    let kind_data = decode_kind(bin, md, addr, kind, tflag).unwrap_or(KindData::None);

    Ok(Type {
        addr,
        name,
        kind,
        size,
        ptr_bytes,
        hash,
        tflag,
        kind_data,
    })
}

/// Public re-export of name resolution for other modules (itabs, funcsig). The
/// caller passes the moduledata so the right name encoding is used.
pub fn read_name_public(bin: &GoBinary, md: &ModuleData, addr: u64) -> Result<String> {
    read_name(bin, md, addr)
}

/// Reads a Go runtime `Name` structure at `addr`. Format:
///   byte 0: flag byte (bit 0 = exported, bit 1 = has tag, bit 3 = embedded)
///   bytes 1..: varint length of the name
///   next N bytes: the name itself (UTF-8)
fn read_name(bin: &GoBinary, md: &ModuleData, addr: u64) -> Result<String> {
    let header = bin
        .read_at_addr(addr, 1 + 10)
        .ok_or_else(|| Error::TypeRecovery(format!("name header at 0x{addr:x} unmapped")))?;

    let (len, len_bytes) = read_name_len(&header[1..], md.name_enc)
        .ok_or_else(|| Error::TypeRecovery(format!("name length at 0x{addr:x} did not decode")))?;

    if len > 1 << 20 {
        return Err(Error::TypeRecovery(format!(
            "name length {len} unreasonably large"
        )));
    }

    let total = 1 + len_bytes + len as usize;
    let body = bin.read_at_addr(addr, total).ok_or_else(|| {
        Error::TypeRecovery(format!("name body at 0x{addr:x} ({total} bytes) unmapped"))
    })?;

    let start = 1 + len_bytes;
    let s = std::str::from_utf8(&body[start..start + len as usize])
        .map_err(|_| Error::TypeRecovery("name is not valid utf-8".into()))?;
    Ok(s.to_string())
}

/// Kind-specific decoding. Each kind's `_type` is followed by extra fields:
///   Pointer:   elem *Type
///   Slice:     elem *Type
///   Array:     elem *Type, slice *Type, len uintptr
///   Chan:      elem *Type, dir uintptr
///   Map:       key *Type, elem *Type, bucket *Type, hasher fn, keysize, valuesize, ...
///   Struct:    pkgpath Name, fields []structField (slice header), then the field array
///   Interface: pkgpath Name, methods []imethod (slice header), then the method array
///   Func:      inCount uint16, outCount uint16, ...args follow as *Type entries
fn decode_kind(
    bin: &GoBinary,
    md: &ModuleData,
    type_addr: u64,
    kind: KindName,
    tflag: u8,
) -> Result<KindData> {
    let ps = bin.pointer_size() as u64;
    let extra_addr = type_addr + type_header_size(ps as usize) as u64;
    match kind {
        KindName::Pointer => {
            let elem = read_uptr(bin, extra_addr)?;
            Ok(KindData::Pointer { elem })
        }
        KindName::Slice => {
            let elem = read_uptr(bin, extra_addr)?;
            Ok(KindData::Slice { elem })
        }
        KindName::Array => {
            let elem = read_uptr(bin, extra_addr)?;
            let _slice = read_uptr(bin, extra_addr + ps)?;
            let len = read_uptr(bin, extra_addr + 2 * ps)?;
            Ok(KindData::Array { elem, len })
        }
        KindName::Chan => {
            let elem = read_uptr(bin, extra_addr)?;
            let dir = read_uptr(bin, extra_addr + ps)?;
            Ok(KindData::Chan { elem, dir })
        }
        KindName::Map => decode_map(bin, extra_addr),
        KindName::Struct => decode_struct(bin, md, extra_addr),
        KindName::Interface => decode_interface(bin, md, extra_addr),
        KindName::Func => decode_func(bin, extra_addr, tflag),
        _ => Ok(KindData::None),
    }
}

/// FuncType extra layout (Go 1.18+, 64-bit):
///   offset  0  InCount  (u16)
///   offset  2  OutCount (u16, top bit = variadic)
///   offset  8 (4 on 32-bit): if TFlag bit 0 (TFlagUncommon) set, UncommonType (16 bytes)
///   then       [InCount + OutCount] *Type
///
/// The parameter type pointers are the key piece. Without them, struct
/// types reachable only through callback fields (cobra command handlers,
/// grpc interceptors, anything passing functions as values) never make it
/// into the recovered type graph.
pub(crate) const TFLAG_UNCOMMON: u8 = 1;
/// TFlagExtraStar (= 1 << 1): the name string in the names blob has a
/// leading `*` that the runtime adds for binary-size reasons (the string
/// `*Foo` is reused between the `Foo` and `*Foo` types). When this flag is
/// set on a Type, the leading `*` is NOT part of the type's actual name
/// and must be stripped when displaying.
pub(crate) const TFLAG_EXTRA_STAR: u8 = 1 << 1;
const UNCOMMON_TYPE_SIZE: usize = 16;

fn decode_func(bin: &GoBinary, extra_addr: u64, tflag: u8) -> Result<KindData> {
    let buf = bin
        .read_at_addr(extra_addr, 4)
        .ok_or_else(|| Error::TypeRecovery("func extra unmapped".into()))?;
    let in_count = u16::from_le_bytes(buf[0..2].try_into().unwrap());
    let raw_out = u16::from_le_bytes(buf[2..4].try_into().unwrap());
    let variadic = raw_out & (1 << 15) != 0;
    let out_count = raw_out & 0x7fff;

    // Sanity cap before allocating: a real Go function has at most a few
    // dozen params. 1024 is a hard ceiling that prevents an attacker-
    // controlled funcType from triggering a giant read.
    const MAX_PARAMS: u16 = 1024;
    if in_count > MAX_PARAMS || out_count > MAX_PARAMS {
        return Ok(KindData::Func {
            in_count,
            out_count,
            variadic,
            in_types: Vec::new(),
            out_types: Vec::new(),
        });
    }

    let total_params = in_count as usize + out_count as usize;
    if total_params == 0 {
        return Ok(KindData::Func {
            in_count,
            out_count,
            variadic,
            in_types: Vec::new(),
            out_types: Vec::new(),
        });
    }

    // The parameter pointer array starts after the FuncType (which embeds the
    // 48-byte Type header plus 4 bytes of in/out counts, padded to 8-byte
    // alignment = 8 bytes of extension; on 32-bit the 32-byte header needs no
    // padding, so 4), optionally offset by UncommonType
    // (16 bytes) if TFlagUncommon is set. The Go runtime computes this with
    // `unsafe.Sizeof(*t)` which includes the alignment padding; we have to
    // bake the same 8 bytes in by hand here. Getting this wrong by 4 bytes
    // produces in_types/out_types pointers that look "almost right" (the low
    // bytes are sane) but actually contain half of one pointer plus part of
    // the next, which silently corrupts every consumer downstream.
    let ps = bin.pointer_size();
    let params_offset = 4usize.next_multiple_of(ps)
        + if tflag & TFLAG_UNCOMMON != 0 {
            UNCOMMON_TYPE_SIZE
        } else {
            0
        };
    let params_addr = extra_addr + params_offset as u64;
    let params_bytes = bin
        .read_at_addr(params_addr, total_params * ps)
        .ok_or_else(|| Error::TypeRecovery("func params array unmapped".into()))?;

    let mut in_types = Vec::with_capacity(in_count as usize);
    for i in 0..in_count as usize {
        in_types.push(le_word(params_bytes, i * ps, ps));
    }
    let mut out_types = Vec::with_capacity(out_count as usize);
    for i in 0..out_count as usize {
        out_types.push(le_word(params_bytes, (in_count as usize + i) * ps, ps));
    }

    Ok(KindData::Func {
        in_count,
        out_count,
        variadic,
        in_types,
        out_types,
    })
}

/// MapType extra layout (Go 1.18+):
///   offset  0  Key    *Type
///   offset  8  Elem   *Type
///   offset 16  Bucket *Type
///   then       hasher, keysize, valuesize, bucketsize, flags
///
/// Surfacing the bucket type matters because it's a real struct in the
/// types region holding the hash/key/value/overflow layout the runtime
/// uses for map storage.
fn decode_map(bin: &GoBinary, extra_addr: u64) -> Result<KindData> {
    let ps = bin.pointer_size() as u64;
    let key = read_uptr(bin, extra_addr)?;
    let elem = read_uptr(bin, extra_addr + ps)?;
    // The bucket pointer is the third *Type; if reading it fails (truncated
    // or unmapped), fall back to None for bucket without failing the whole
    // decode.
    let bucket = read_uptr(bin, extra_addr + 2 * ps).ok();
    Ok(KindData::Map { key, elem, bucket })
}

/// Struct extra layout (after _type header):
///   pkgPath Name
///   fields  slice header (data, len, cap)
///   then each structField: { name Name, typ *Type, offset uintptr } = 24 bytes on 64-bit
fn decode_struct(bin: &GoBinary, md: &ModuleData, extra_addr: u64) -> Result<KindData> {
    let ps = bin.pointer_size();
    let _pkg_path = read_uptr(bin, extra_addr)?;
    let fields_data = read_uptr(bin, extra_addr + ps as u64)?;
    let fields_len = read_uptr(bin, extra_addr + 2 * ps as u64)?;
    if fields_len > 1024 {
        return Err(Error::TypeRecovery(format!(
            "struct field count {fields_len} unreasonably large"
        )));
    }

    // name, typ, offset: three words.
    let field_size = 3 * ps;
    let total = fields_len as usize * field_size;
    let buf = bin.read_at_addr(fields_data, total).ok_or_else(|| {
        Error::TypeRecovery(format!(
            "struct fields array at 0x{fields_data:x} ({total} bytes) unmapped"
        ))
    })?;

    let mut fields = Vec::with_capacity(fields_len as usize);
    for i in 0..fields_len as usize {
        let off = i * field_size;
        let name_ptr = le_word(buf, off, ps);
        let typ = le_word(buf, off + ps, ps);
        let offset = le_word(buf, off + 2 * ps, ps);

        let (name, embedded, tag) =
            read_name_full(bin, md, name_ptr).unwrap_or((String::new(), false, String::new()));
        fields.push(StructField {
            name,
            typ,
            offset,
            embedded,
            tag,
        });
    }
    let _ = md;
    Ok(KindData::Struct { fields })
}

/// Read a struct field's name encoding: its name, the embedded flag, and the
/// struct tag. The Go `Name` lays the tag out right after the name -- flag byte,
/// varint name length, name bytes, then (when the has-tag flag is set) varint
/// tag length and tag bytes. Reading it recovers a field's `json:"..."` schema,
/// which garble leaves verbatim even when the field name itself is hashed.
fn read_name_full(bin: &GoBinary, md: &ModuleData, addr: u64) -> Result<(String, bool, String)> {
    let header = bin
        .read_at_addr(addr, 1 + 10)
        .ok_or_else(|| Error::TypeRecovery(format!("name header at 0x{addr:x} unmapped")))?;
    let flag_byte = header[0];
    let embedded = flag_byte & (1 << 3) != 0;
    let has_tag = flag_byte & (1 << 1) != 0;

    let (name_len, name_len_bytes) = read_name_len(&header[1..], md.name_enc)
        .ok_or_else(|| Error::TypeRecovery(format!("name length at 0x{addr:x} did not decode")))?;
    if name_len > 1 << 20 {
        return Err(Error::TypeRecovery(format!(
            "name length {name_len} unreasonably large"
        )));
    }
    let name_start = 1 + name_len_bytes;
    let name_end = name_start + name_len as usize;
    let body = bin
        .read_at_addr(addr, name_end)
        .ok_or_else(|| Error::TypeRecovery(format!("name body at 0x{addr:x} unmapped")))?;
    let name = std::str::from_utf8(&body[name_start..name_end])
        .map_err(|_| Error::TypeRecovery("name is not valid utf-8".into()))?
        .to_string();

    let tag = if has_tag {
        read_tag(bin, md, addr + name_end as u64).unwrap_or_default()
    } else {
        String::new()
    };
    Ok((name, embedded, tag))
}

/// Read the tag at `addr`: a length (per the binary's name encoding) followed by
/// that many bytes. The tag follows the name in the field's `Name` encoding. A bad
/// length or non-UTF-8 body yields an empty tag rather than failing the struct.
fn read_tag(bin: &GoBinary, md: &ModuleData, addr: u64) -> Option<String> {
    let hdr = bin.read_at_addr(addr, 10)?;
    let (len, len_bytes) = read_name_len(hdr, md.name_enc)?;
    if len == 0 || len > 1 << 16 {
        return None;
    }
    let bytes = bin.read_at_addr(addr + len_bytes as u64, len as usize)?;
    std::str::from_utf8(bytes).ok().map(str::to_string)
}

/// InterfaceType extra layout (after _type header):
///   pkgPath Name (1 ptr = 8 bytes)
///   methods slice header (data, len, cap = 24 bytes)
/// Then [len]Imethod, each = (NameOff i32, TypeOff i32) = 8 bytes.
fn decode_interface(bin: &GoBinary, md: &ModuleData, extra_addr: u64) -> Result<KindData> {
    let ps = bin.pointer_size() as u64;
    let _pkg_path = read_uptr(bin, extra_addr)?;
    let methods_data = read_uptr(bin, extra_addr + ps)?;
    let methods_len = read_uptr(bin, extra_addr + 2 * ps)?;
    if methods_len > 1024 {
        return Err(Error::TypeRecovery(format!(
            "interface method count {methods_len} unreasonably large"
        )));
    }
    const IMETHOD_SIZE: usize = 8;
    let total = methods_len as usize * IMETHOD_SIZE;
    let buf = bin.read_at_addr(methods_data, total).ok_or_else(|| {
        Error::TypeRecovery(format!(
            "interface methods array at 0x{methods_data:x} ({total} bytes) unmapped"
        ))
    })?;

    let mut methods = Vec::with_capacity(methods_len as usize);
    for i in 0..methods_len as usize {
        let off = i * IMETHOD_SIZE;
        let name_off = i32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let typ_off = i32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap());
        let name_addr = md.types.wrapping_add(name_off as i64 as u64);
        let typ_addr = md.types.wrapping_add(typ_off as i64 as u64);
        let name = read_name(bin, md, name_addr).unwrap_or_else(|_| format!("method{i}"));
        methods.push(InterfaceMethod {
            name,
            typ: typ_addr,
        });
    }
    Ok(KindData::Interface { methods })
}

fn read_uptr(bin: &GoBinary, addr: u64) -> Result<u64> {
    let ps = bin.pointer_size();
    let buf = bin
        .read_at_addr(addr, ps)
        .ok_or_else(|| Error::TypeRecovery(format!("uintptr at 0x{addr:x} unmapped")))?;
    Ok(le_word(buf, 0, ps))
}
