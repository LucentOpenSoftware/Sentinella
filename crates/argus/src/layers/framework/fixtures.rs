//! Test-only PE fixture builder, shared by the `pe.rs` parser tests and the
//! per-framework detector tests (NSIS / Inno / WiX detector bodies land in
//! the next wave — build detector tests on this, do not hand-roll bytes).
//!
//! The builder writes a *coherent* minimal PE: section bodies are actually
//! placed at their declared `PointerToRawData` (zero-padding as needed), so
//! declared structure and file bytes agree unless a test deliberately asks
//! for a mismatch (`declared_raw_size` > `body_len`, `truncate_at`, a
//! patched header field via [`patch_u32_le`], ...).
//!
//! Malformed variants are first-class: overrides exist for the section
//! count, the optional-header size, `e_lfanew`, and per-section raw
//! pointers, and [`patch_u32_le`] covers everything else.

/// Section fields as written into the section-table entry.
///
/// `declared_raw_size` goes into the header; `body_len` controls how many
/// bytes are actually appended at the declared raw pointer. `body_len <
/// declared_raw_size` models a section whose declared range runs past EOF.
#[derive(Debug, Clone)]
pub(crate) struct SectionSpec {
    /// Section name (truncated/padded to the 8 header bytes).
    pub name: String,
    /// `VirtualSize`.
    pub virtual_size: u32,
    /// `SizeOfRawData` as declared in the header.
    pub declared_raw_size: u32,
    /// Bytes actually written to the file at the raw pointer.
    pub body_len: usize,
    /// Fill byte for the section body.
    pub fill: u8,
    /// Section characteristics flags (default MEM_READ | MEM_EXECUTE).
    pub characteristics: u32,
    /// `PointerToRawData` override; `None` = auto-layout after the previous
    /// section body.
    pub raw_ptr_override: Option<u32>,
    /// `VirtualAddress` override; `None` = auto (0x1000-aligned sequence).
    pub virtual_address_override: Option<u32>,
}

// Some builder knobs are only exercised by the detector tests that land in
// the next wave; this is the shared fixture API, so they stay.
#[allow(dead_code)]
impl SectionSpec {
    /// A section whose body fully backs its declared raw size.
    pub(crate) fn new(name: impl Into<String>, virtual_size: u32, raw_size: u32) -> Self {
        Self {
            name: name.into(),
            virtual_size,
            declared_raw_size: raw_size,
            body_len: raw_size as usize,
            fill: 0x41,
            characteristics: 0x6000_0020, // CODE | MEM_EXECUTE | MEM_READ
            raw_ptr_override: None,
            virtual_address_override: None,
        }
    }

    /// Write fewer (or zero) body bytes than the declared raw size.
    pub(crate) fn body_len(mut self, n: usize) -> Self {
        self.body_len = n;
        self
    }

    /// Section body fill byte.
    pub(crate) fn fill(mut self, b: u8) -> Self {
        self.fill = b;
        self
    }

    /// Section characteristics flags.
    pub(crate) fn characteristics(mut self, c: u32) -> Self {
        self.characteristics = c;
        self
    }

    /// Declare the raw pointer explicitly (overlapping-section and
    /// header-overlap fixtures). The body is written at this offset.
    pub(crate) fn raw_ptr_override(mut self, ptr: u32) -> Self {
        self.raw_ptr_override = Some(ptr);
        self
    }

    /// Declare the virtual address explicitly.
    pub(crate) fn virtual_address_override(mut self, rva: u32) -> Self {
        self.virtual_address_override = Some(rva);
        self
    }
}

/// Minimal-PE fixture builder. All `self`-consuming chain methods.
///
/// Defaults: `e_lfanew = 0x80`, PE32 (`0x10B`, 224-byte optional header,
/// 16 data directories), machine `0x14C` (i386), entry point RVA `0x1000`,
/// `SizeOfImage` `0x4000`, no resource directory, no sections, no overlay.
pub(crate) struct PeBuilder {
    e_lfanew: u32,
    machine: u16,
    optional_magic: u16,
    entry_point: u32,
    size_of_image: u32,
    resource_dir_rva: u32,
    resource_dir_size: u32,
    section_count_override: Option<u16>,
    size_of_optional_override: Option<u16>,
    sections: Vec<SectionSpec>,
    overlay: Vec<u8>,
    truncate_at: Option<usize>,
}

// Some builder knobs are only exercised by the detector tests that land in
// the next wave; this is the shared fixture API, so they stay.
#[allow(dead_code)]
impl PeBuilder {
    pub(crate) fn new() -> Self {
        Self {
            e_lfanew: 0x80,
            machine: 0x14C,
            optional_magic: 0x10B,
            entry_point: 0x1000,
            size_of_image: 0x4000,
            resource_dir_rva: 0,
            resource_dir_size: 0,
            section_count_override: None,
            size_of_optional_override: None,
            sections: Vec::new(),
            overlay: Vec::new(),
            truncate_at: None,
        }
    }

    pub(crate) fn e_lfanew(mut self, v: u32) -> Self {
        self.e_lfanew = v;
        self
    }

    pub(crate) fn machine(mut self, v: u16) -> Self {
        self.machine = v;
        self
    }

    pub(crate) fn optional_magic(mut self, v: u16) -> Self {
        self.optional_magic = v;
        self
    }

    pub(crate) fn entry_point(mut self, rva: u32) -> Self {
        self.entry_point = rva;
        self
    }

    pub(crate) fn size_of_image(mut self, v: u32) -> Self {
        self.size_of_image = v;
        self
    }

    /// Populate the resource data directory (entry 2) of the optional header.
    pub(crate) fn resource_directory(mut self, rva: u32, size: u32) -> Self {
        self.resource_dir_rva = rva;
        self.resource_dir_size = size;
        self
    }

    /// Declare a section count different from the number of section-table
    /// entries actually written (absurd-count fixtures).
    pub(crate) fn section_count_override(mut self, n: u16) -> Self {
        self.section_count_override = Some(n);
        self
    }

    /// Declare an optional-header size different from the magic's default
    /// (0 = no optional header at all).
    pub(crate) fn size_of_optional_override(mut self, n: u16) -> Self {
        self.size_of_optional_override = Some(n);
        self
    }

    /// Convenience: a fully-backed section with default flags/fill.
    pub(crate) fn section(self, name: &str, virtual_size: u32, raw_size: u32) -> Self {
        self.add_section(SectionSpec::new(name, virtual_size, raw_size))
    }

    pub(crate) fn add_section(mut self, spec: SectionSpec) -> Self {
        self.sections.push(spec);
        self
    }

    /// Bytes appended after the last section body (the overlay).
    pub(crate) fn overlay(mut self, bytes: &[u8]) -> Self {
        self.overlay = bytes.to_vec();
        self
    }

    /// Truncate the final file to `n` bytes (truncation fixtures).
    pub(crate) fn truncate_at(mut self, n: usize) -> Self {
        self.truncate_at = Some(n);
        self
    }

    /// Write the fixture.
    pub(crate) fn build(self) -> Vec<u8> {
        let pe32plus = self.optional_magic == 0x20B;
        let size_of_optional = self.size_of_optional_override.unwrap_or(if pe32plus {
            240
        } else {
            224
        });

        // DOS header + stub: MZ at 0, e_lfanew at 0x3C, zeros up to e_lfanew.
        let e_lfanew = usize::try_from(self.e_lfanew).unwrap_or(0x1000);
        let mut buf = vec![0u8; e_lfanew.max(0x40)];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&self.e_lfanew.to_le_bytes());
        buf.resize(e_lfanew, 0);

        let declared_count = self
            .section_count_override
            .unwrap_or(self.sections.len() as u16);

        // PE signature + COFF header.
        buf.extend_from_slice(b"PE\0\0");
        buf.extend_from_slice(&self.machine.to_le_bytes());
        buf.extend_from_slice(&declared_count.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        buf.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
        buf.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
        buf.extend_from_slice(&size_of_optional.to_le_bytes());
        buf.extend_from_slice(&0x0102u16.to_le_bytes()); // EXECUTABLE | 32BIT

        // Optional header (zeros except the fields the builder models).
        let opt_start = buf.len();
        buf.resize(opt_start + usize::from(size_of_optional), 0);
        let opt_put = |buf: &mut [u8], off: usize, bytes: &[u8]| {
            if off + bytes.len() <= usize::from(size_of_optional) {
                buf[opt_start + off..opt_start + off + bytes.len()].copy_from_slice(bytes);
            }
        };
        opt_put(&mut buf, 0, &self.optional_magic.to_le_bytes());
        opt_put(&mut buf, 16, &self.entry_point.to_le_bytes());
        opt_put(&mut buf, 56, &self.size_of_image.to_le_bytes());
        let (num_rva_off, dirs_off) = if pe32plus { (108, 112) } else { (92, 96) };
        opt_put(&mut buf, num_rva_off, &16u32.to_le_bytes());
        opt_put(&mut buf, dirs_off + 2 * 8, &self.resource_dir_rva.to_le_bytes());
        opt_put(&mut buf, dirs_off + 2 * 8 + 4, &self.resource_dir_size.to_le_bytes());

        // Section table. Auto-layout: raw bodies start right after the table,
        // virtual addresses run 0x1000-aligned from 0x1000.
        let mut raw_cursor = buf.len() + self.sections.len() * 40;
        let mut vaddr_cursor = 0x1000u32;
        let mut raw_ptrs = Vec::with_capacity(self.sections.len());
        for spec in &self.sections {
            let raw_ptr = spec.raw_ptr_override.unwrap_or(raw_cursor as u32);
            raw_ptrs.push(raw_ptr);
            let body_end = raw_ptr as usize + spec.body_len;
            raw_cursor = raw_cursor.max(body_end);

            let vaddr = spec.virtual_address_override.unwrap_or(vaddr_cursor);
            vaddr_cursor = vaddr
                .saturating_add(spec.virtual_size)
                .saturating_add(0xFFF)
                & !0xFFF;

            let mut entry = [0u8; 40];
            let name_bytes = spec.name.as_bytes();
            let n = name_bytes.len().min(8);
            entry[..n].copy_from_slice(&name_bytes[..n]);
            entry[8..12].copy_from_slice(&spec.virtual_size.to_le_bytes());
            entry[12..16].copy_from_slice(&vaddr.to_le_bytes());
            entry[16..20].copy_from_slice(&spec.declared_raw_size.to_le_bytes());
            entry[20..24].copy_from_slice(&raw_ptr.to_le_bytes());
            entry[36..40].copy_from_slice(&spec.characteristics.to_le_bytes());
            buf.extend_from_slice(&entry);
        }

        // Section bodies at their declared raw pointers (zero-pad gaps).
        for (spec, &raw_ptr) in self.sections.iter().zip(&raw_ptrs) {
            let start = raw_ptr as usize;
            let end = start + spec.body_len;
            if buf.len() < end {
                buf.resize(end, 0);
            }
            for b in &mut buf[start..end] {
                *b = spec.fill;
            }
        }

        buf.extend_from_slice(&self.overlay);

        if let Some(n) = self.truncate_at {
            buf.truncate(n);
        }
        buf
    }
}

impl Default for PeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Patch a little-endian u32 in a built fixture — for malformed variants the
/// builder has no dedicated override for (e.g. `e_lfanew` pointing into the
/// overlay).
pub(crate) fn patch_u32_le(buf: &mut [u8], offset: usize, v: u32) {
    buf[offset..offset + 4].copy_from_slice(&v.to_le_bytes());
}
