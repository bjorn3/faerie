use crate::artifact::{Decl, DefinedDecl, ImportKind, Reloc, SectionKind};
use crate::Artifact;

use goblin::mach::relocation::{RelocType, RelocationInfo};

use super::{SegmentBuilder, SymbolIndex, SymbolTable};

/// Mach relocation builder
#[derive(Debug)]
pub(super) struct RelocationBuilder {
    symbol: SymbolIndex,
    relocation_offset: u64,
    absolute: bool,
    size: u8,
    r_type: RelocType,
}

impl RelocationBuilder {
    /// Create a relocation for `symbol`, starting at `relocation_offset`
    pub fn new(symbol: SymbolIndex, relocation_offset: u64, r_type: RelocType) -> Self {
        RelocationBuilder {
            symbol,
            relocation_offset,
            absolute: false,
            size: 0,
            r_type,
        }
    }
    /// This is an absolute relocation
    pub fn absolute(mut self) -> Self {
        self.absolute = true;
        self
    }
    /// The size in bytes of the relocated value (defaults to the address size).
    pub fn size(mut self, size: u8) -> Self {
        self.size = size;
        self
    }
    /// Finalize and create the relocation
    pub fn create(self) -> RelocationInfo {
        // it basically goes sort of backwards than what you'd expect because C bitfields are bonkers
        let r_symbolnum: u32 = self.symbol as u32;
        let r_pcrel: u32 = if self.absolute { 0 } else { 1 } << 24;
        let r_length: u32 = match self.size {
            0 => {
                if self.absolute {
                    3
                } else {
                    2
                }
            }
            4 => 2,
            8 => 3,
            size => panic!("unsupported relocation size {}", size),
        } << 25;
        let r_extern: u32 = 1 << 27;
        let r_type = (self.r_type as u32) << 28;
        // r_symbolnum, 24 bits, r_pcrel 1 bit, r_length 2 bits, r_extern 1 bit, r_type 4 bits
        let r_info = r_symbolnum | r_pcrel | r_length | r_extern | r_type;
        RelocationInfo {
            r_address: self.relocation_offset as i32,
            r_info,
        }
    }
}


// FIXME: this should actually return a runtime error if we encounter a from.decl to.decl pair which we don't explicitly match on
pub(super) fn build_relocations(segment: &mut SegmentBuilder, artifact: &Artifact, symtab: &SymbolTable) {
    use goblin::mach::relocation::{
        R_ABS, X86_64_RELOC_BRANCH, X86_64_RELOC_GOT_LOAD, X86_64_RELOC_SIGNED,
        X86_64_RELOC_UNSIGNED,
    };
    let text_idx = segment.sections.get_full("__text").unwrap().0;
    let data_idx = segment.sections.get_full("__data").unwrap().0;
    debug!("Generating relocations");
    for link in artifact.links() {
        debug!(
            "Import links for: from {} to {} at {:#x} with {:?}",
            link.from.name, link.to.name, link.at, link.reloc
        );
        let (absolute, reloc) = match link.reloc {
            Reloc::Auto => {
                // NB: we currently deduce the meaning of our relocation from from decls -> to decl relocations
                // e.g., global static data references, are constructed from Data -> Data links
                match (link.from.decl, link.to.decl) {
                    (Decl::Defined(DefinedDecl::Section(s)), _)
                        if s.kind() == SectionKind::Debug =>
                    {
                        panic!("must use Reloc::Debug for debug section links")
                    }
                    // only debug sections should link to debug sections
                    (_, Decl::Defined(DefinedDecl::Section(s)))
                        if s.kind() == SectionKind::Debug =>
                    {
                        panic!("invalid DebugSection link")
                    }

                    (Decl::Defined(DefinedDecl::Section(_)), _)
                    | (_, Decl::Defined(DefinedDecl::Section(_))) => {
                        panic!("relocations are not yet supported for custom sections")
                    }
                    // various static function pointers in the .data section
                    (
                        Decl::Defined(DefinedDecl::Data { .. }),
                        Decl::Defined(DefinedDecl::Function { .. }),
                    ) => (true, X86_64_RELOC_UNSIGNED),
                    (
                        Decl::Defined(DefinedDecl::Data { .. }),
                        Decl::Import(ImportKind::Function { .. }),
                    ) => (true, X86_64_RELOC_UNSIGNED),
                    // anything else is just a regular relocation/callq
                    (_, Decl::Defined(DefinedDecl::Function { .. })) => {
                        (false, X86_64_RELOC_BRANCH)
                    }
                    // we are a relocation in the data section to another object
                    // in the data section, e.g., a static reference
                    (
                        Decl::Defined(DefinedDecl::Data { .. }),
                        Decl::Defined(DefinedDecl::Data { .. }),
                    ) => (true, X86_64_RELOC_UNSIGNED),
                    (_, Decl::Defined(DefinedDecl::Data { .. })) => (false, X86_64_RELOC_SIGNED),
                    (_, Decl::Import(ImportKind::Function)) => (false, X86_64_RELOC_BRANCH),
                    (_, Decl::Import(ImportKind::Data)) => (false, X86_64_RELOC_GOT_LOAD),
                }
            }
            Reloc::Raw { reloc, addend } => {
                debug_assert!(reloc <= u8::max_value() as u32);
                assert!(addend == 0);
                match reloc as u8 {
                    R_ABS => (true, R_ABS),
                    reloc => (false, reloc),
                }
            }
            Reloc::Debug { size, .. } => {
                if link.to.decl.is_section() {
                    // TODO: not sure if these are needed for Mach
                } else {
                    match symtab.index(link.to.name) {
                        Some(to_symbol_index) => {
                            let builder = RelocationBuilder::new(to_symbol_index, link.at, X86_64_RELOC_UNSIGNED).absolute().size(size);
                            segment.sections[link.from.name].add_reloc(builder.create());
                        }
                        _ => error!("Import Relocation from {} to {} at {:#x} has a missing symbol. Dumping symtab {:?}", link.from.name, link.to.name, link.at, symtab)
                    }
                }
                continue;
            }
        };
        match (symtab.offset(link.from.name), symtab.index(link.to.name)) {
            (Some(base_offset), Some(to_symbol_index)) => {
                debug!("{} offset: {}", link.to.name, base_offset + link.at);
                let builder = RelocationBuilder::new(to_symbol_index, base_offset + link.at, reloc);
                // NB: we currently associate absolute relocations with data relocations; this may prove
                // too fragile for future additions; needs analysis
                if absolute {
                    segment.sections.get_index_mut(data_idx).unwrap().1.add_reloc(builder.absolute().create());
                } else {
                    segment.sections.get_index_mut(text_idx).unwrap().1.add_reloc(builder.create());
                }
            },
            _ => error!("Import Relocation from {} to {} at {:#x} has a missing symbol. Dumping symtab {:?}", link.from.name, link.to.name, link.at, symtab)
        }
    }
}
