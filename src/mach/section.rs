use scroll::Pwrite;

use goblin::mach::constants::S_REGULAR;
use goblin::mach::relocation::{RelocationInfo, SIZEOF_RELOCATION_INFO};
use goblin::mach::segment::Section;

pub type SectionIndex = usize;

pub const CODE_SECTION_INDEX: SectionIndex = 0;
pub const DATA_SECTION_INDEX: SectionIndex = 1;
pub const CSTRING_SECTION_INDEX: SectionIndex = 2;

/// Helper to build sections
#[derive(Debug, Clone)]
pub struct SectionBuilder {
    addr: u64,
    align: u64,
    offset: u64,
    size: u64,
    flags: u32,
    sectname: String,
    segname: &'static str,
    relocations: Vec<RelocationInfo>,
}

impl SectionBuilder {
    /// Create a new section builder with `sectname`, `segname` and `size`
    pub fn new(sectname: String, segname: &'static str, size: u64) -> Self {
        SectionBuilder {
            addr: 0,
            align: 4,
            offset: 0,
            flags: S_REGULAR,
            size,
            sectname,
            segname,
            relocations: Vec::new(),
        }
    }
    /// Set the vm address of this section
    pub fn addr(mut self, addr: u64) -> Self {
        self.addr = addr;
        self
    }
    /// Set the file offset of this section
    pub fn offset(mut self, offset: u64) -> Self {
        self.offset = offset;
        self
    }
    /// Set the alignment of this section
    pub fn align(mut self, align: u64) -> Self {
        self.align = align;
        self
    }
    /// Set the flags of this section
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    pub fn add_reloc(&mut self, reloc: RelocationInfo) {
        self.relocations.push(reloc)
    }

    pub fn relocations(&self) -> &[RelocationInfo] {
        &self.relocations
    }

    /// Finalize and create the actual Mach-o section
    pub fn create(&self, section_offset: &mut u64, relocation_offset: &mut u64) -> Section {
        let mut sectname = [0u8; 16];
        sectname.pwrite(&*self.sectname, 0).unwrap();
        let mut segname = [0u8; 16];
        segname.pwrite(self.segname, 0).unwrap();
        let mut section = Section {
            sectname,
            segname,
            addr: self.addr,
            size: self.size,
            offset: self.offset as u32,
            align: self.align as u32,
            // FIXME, client needs to set after all offsets known
            reloff: 0,
            nreloc: 0,
            flags: self.flags,
        };
        section.offset = *section_offset as u32;
        *section_offset += section.size;
        if !self.relocations.is_empty() {
            let nrelocs = self.relocations.len();
            section.nreloc = nrelocs as _;
            section.reloff = *relocation_offset as u32;
            *relocation_offset += nrelocs as u64 * SIZEOF_RELOCATION_INFO as u64;
        }
        section
    }
}
