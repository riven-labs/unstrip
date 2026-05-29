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
    "# unstrip: interface dispatch resolver for Ghidra.\n",
    "# Place the current cursor on a virtual CALL site (CALL qword ptr [reg + offset]\n",
    "# on amd64; BLR / BR through a register on arm64) and run this script.\n",
    "# It prints every recovered (interface, concrete impl) pair whose method\n",
    "# table contains the dereferenced offset.\n",
    "# @category unstrip\n",
    "# @menupath Tools.Unstrip.Resolve dispatch at cursor\n",
    "\n",
);

const GHIDRA_FOOTER: &str = concat!(
    "def _slot_for_instruction(insn):\n",
    "    # CALL qword ptr [REG + offset] on amd64. The offset is the\n",
    "    # method slot * 8. Pull the integer scalar from the second operand.\n",
    "    if insn is None:\n",
    "        return None\n",
    "    n = insn.getNumOperands()\n",
    "    for i in range(n):\n",
    "        objs = insn.getOpObjects(i)\n",
    "        for o in objs:\n",
    "            try:\n",
    "                v = o.getValue()\n",
    "                if isinstance(v, (int, long)) and v >= 0 and v < 4096 and v % 8 == 0:\n",
    "                    return int(v) // 8\n",
    "            except Exception:\n",
    "                continue\n",
    "    return None\n",
    "\n",
    "def _resolve():\n",
    "    addr = currentAddress\n",
    "    if addr is None:\n",
    "        print('unstrip dispatch: no cursor address')\n",
    "        return\n",
    "    listing = currentProgram.getListing()\n",
    "    insn = listing.getInstructionAt(addr)\n",
    "    slot = _slot_for_instruction(insn)\n",
    "    if slot is None:\n",
    "        print('unstrip dispatch: instruction at %s is not a register-indirect call we recognize' % addr)\n",
    "        return\n",
    "    print('unstrip dispatch: looking for itabs with a method at slot %d (offset 0x%x)' % (slot, slot * 8))\n",
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
