//! Emit RE-tool scripts that surface unstrip's recovered interface
//! dispatch table when the analyst hovers or clicks on a virtual call
//! site.
//!
//! Today only Ghidra is supported. The emitted script:
//!
//! 1. Embeds the full `(interface -> concrete -> [method, fn_ptr])`
//!    mapping recovered by `--itabs`.
//! 2. Registers a Ghidra action ("Unstrip: Resolve dispatch") under
//!    Tools that, when invoked at the cursor, walks the current
//!    instruction for a virtual call shape and prints every
//!    `(interface, concrete impl)` pair that has a method at the same
//!    register-relative offset.
//!
//! Because Ghidra's Python scripting environment is conservative, we
//! ship a simple action-based resolver instead of hooking the listing
//! right-click menu directly. The analyst selects an instruction, runs
//! the action, and sees the candidate set in the console.

use crate::itabs::Itab;

/// Emit the Ghidra Python script for the recovered itab dispatch
/// table. Run inside Ghidra (Script Manager) to register the resolver.
pub fn write_ghidra(itabs: &[Itab]) -> String {
    let mut s = String::with_capacity(itabs.len() * 256);
    s.push_str(GHIDRA_HEADER);

    // Emit the table as a literal Python dict structure. The Ghidra
    // script reads it directly; no external JSON file required.
    s.push_str("ITABS = [\n");
    for it in itabs {
        s.push_str("    {\n");
        s.push_str(&format!(
            "        'interface': {},\n",
            quote_py(&it.interface_name)
        ));
        s.push_str(&format!(
            "        'concrete': {},\n",
            quote_py(&it.concrete_name)
        ));
        s.push_str("        'methods': [\n");
        for (idx, m) in it.methods.iter().enumerate() {
            s.push_str(&format!(
                "            {{'slot': {}, 'name': {}, 'fn': 0x{:x}}},\n",
                idx,
                quote_py(&m.interface_method),
                m.concrete_fn
            ));
        }
        s.push_str("        ],\n");
        s.push_str("    },\n");
    }
    s.push_str("]\n\n");

    s.push_str(GHIDRA_FOOTER);
    s
}

fn quote_py(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

const GHIDRA_HEADER: &str = concat!(
    "# unstrip: interface dispatch resolver for Ghidra (PyGhidra, Python 3).\n",
    "# Place the cursor on an interface method call and run this script. Go\n",
    "# loads the method from the itab into a register and calls through it:\n",
    "#   amd64: MOV RDX, qword ptr [RDX + 0x18] ... CALL RDX\n",
    "#   arm64: ldr x1, [x0, #0x18] ... blr x1\n",
    "# The load offset gives the itab method slot, and the script prints every\n",
    "# recovered (interface, concrete impl) pair with a method in that slot.\n",
    "# @category unstrip\n",
    "# @menupath Tools.Unstrip.Resolve dispatch at cursor\n",
    "# @runtime PyGhidra\n",
    "\n",
    "from ghidra.program.model.lang import Register\n",
    "from ghidra.program.model.scalar import Scalar\n",
    "\n",
);

const GHIDRA_FOOTER: &str = concat!(
    "# itab.fun starts after inter, _type and the 4-byte hash: 24 bytes on\n",
    "# 64-bit in every Go release.\n",
    "FUN_OFFSET = 24\n",
    "PTR_SIZE = 8\n",
    "# How far back from the call to look for the load, within straight-line code.\n",
    "MAX_LOOKBACK = 64\n",
    "\n",
    "def _base_and_offset(objs):\n",
    "    regs = [o for o in objs if isinstance(o, Register)]\n",
    "    scalars = [o for o in objs if isinstance(o, Scalar)]\n",
    "    if len(regs) != 1 or len(scalars) != 1:\n",
    "        return None\n",
    "    return regs[0], int(scalars[0].getValue())\n",
    "\n",
    "def _itab_load_offset(insn):\n",
    "    # The offset of the itab method load that feeds the call at insn.\n",
    "    if insn is None or insn.getMnemonicString().upper() not in ('CALL', 'BLR'):\n",
    "        return None\n",
    "    objs = list(insn.getOpObjects(0))\n",
    "    # CALL qword ptr [reg + off]: the load is the call itself.\n",
    "    direct = _base_and_offset(objs)\n",
    "    if direct is not None:\n",
    "        return direct\n",
    "    if len(objs) != 1 or not isinstance(objs[0], Register):\n",
    "        return None\n",
    "    target = objs[0].getBaseRegister()\n",
    "    prev = insn.getPrevious()\n",
    "    for _ in range(MAX_LOOKBACK):\n",
    "        if prev is None or not prev.getFlowType().isFallthrough():\n",
    "            return None\n",
    "        written = [o for o in prev.getResultObjects() if isinstance(o, Register)]\n",
    "        if any(r.getBaseRegister() == target for r in written):\n",
    "            if prev.getMnemonicString().upper() not in ('MOV', 'LDR'):\n",
    "                return None\n",
    "            return _base_and_offset(list(prev.getOpObjects(1)))\n",
    "        prev = prev.getPrevious()\n",
    "    return None\n",
    "\n",
    "def _slot_for_instruction(insn):\n",
    "    load = _itab_load_offset(insn)\n",
    "    if load is None:\n",
    "        return None\n",
    "    base, off = load\n",
    "    # A load through the stack pointer is a spilled value, not an itab, and\n",
    "    # an offset inside the itab header is a closure call (offset 0) or data.\n",
    "    sp = currentProgram.getCompilerSpec().getStackPointer()\n",
    "    if sp is not None and base.getBaseRegister() == sp.getBaseRegister():\n",
    "        return None\n",
    "    if off < FUN_OFFSET or (off - FUN_OFFSET) % PTR_SIZE != 0:\n",
    "        return None\n",
    "    return (off - FUN_OFFSET) // PTR_SIZE\n",
    "\n",
    "def _resolve():\n",
    "    if currentProgram.getDefaultPointerSize() != PTR_SIZE:\n",
    "        print('unstrip dispatch: only 64-bit programs are supported')\n",
    "        return\n",
    "    addr = currentAddress\n",
    "    if addr is None:\n",
    "        print('unstrip dispatch: no cursor address')\n",
    "        return\n",
    "    listing = currentProgram.getListing()\n",
    "    insn = listing.getInstructionAt(addr)\n",
    "    slot = _slot_for_instruction(insn)\n",
    "    if slot is None:\n",
    "        print('unstrip dispatch: instruction at %s is not a call through an itab method load we recognize' % addr)\n",
    "        return\n",
    "    print('unstrip dispatch: looking for itabs with a method at slot %d (offset 0x%x)' % (slot, FUN_OFFSET + slot * PTR_SIZE))\n",
    "    hits = 0\n",
    "    for it in ITABS:\n",
    "        for m in it['methods']:\n",
    "            if m['slot'] == slot:\n",
    "                print('  %s => %s :: %s -> 0x%x' % (it['interface'], it['concrete'], m['name'], m['fn']))\n",
    "                hits += 1\n",
    "                break\n",
    "    if hits == 0:\n",
    "        print('unstrip dispatch: no itab has a method at slot %d' % slot)\n",
    "    else:\n",
    "        print('unstrip dispatch: %d candidates' % hits)\n",
    "\n",
    "_resolve()\n",
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::itabs::ItabMethod;

    #[test]
    fn script_maps_the_itab_load_offset_to_the_method_slot() {
        let itab = Itab {
            addr: 0x601c00,
            interface_name: "io.Writer".into(),
            concrete_name: "*os.File".into(),
            methods: vec![ItabMethod {
                interface_method: "Write".into(),
                concrete_fn: 0x4b9020,
            }],
            hash: 0,
            incomplete: false,
            stdlib_interface: Some("io.Writer"),
        };
        let script = write_ghidra(&[itab]);
        assert!(
            script.contains("{'slot': 0, 'name': 'Write', 'fn': 0x4b9020}"),
            "the itab's first method is slot 0"
        );
        // MOV RDX, [RDX + 0x18] loads fun[0]: slot = (0x18 - 24) / 8.
        assert!(script.contains("FUN_OFFSET = 24\n"));
        assert!(script.contains("return (off - FUN_OFFSET) // PTR_SIZE\n"));
        assert!(
            !script.contains("long"),
            "PyGhidra runs Python 3, which has no `long`"
        );
        assert!(script.contains("# @runtime PyGhidra\n"));
    }
}
