use crate::artifact::{DefinedDecl, Definition, SectionKind};
use crate::{Artifact, Ctx};

use failure::Error;

use indexmap::IndexMap;
use scroll::IOwrite;
use scroll::ctx::SizeWith;

use goblin::mach::constants::{
    S_ATTR_DEBUG, S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS, S_CSTRING_LITERALS,
};
use goblin::mach::header::{Header};
use goblin::mach::segment::{Section, Segment};
use goblin::mach::relocation::RelocationInfo;

use std::convert::TryFrom;
use std::io::{Cursor, Seek, Write};

use super::{
    CODE_SECTION_INDEX, DATA_SECTION_INDEX, CSTRING_SECTION_INDEX,
    SectionBuilder, SectionIndex, SymbolTable, SymbolType,
};

const VM_PROT_READ: u32 = 0x1;
const VM_PROT_WRITE: u32 = 0x2;
const VM_PROT_EXECUTE: u32 = 0x4;

#[derive(Debug)]
/// A Mach-o program segment
pub struct SegmentBuilder {
    /// The sections that belong to this program segment
    pub sections: IndexMap<String, SectionBuilder>,
    /// A stupid offset value I need to refactor out
    pub offset: u64,
    size: u64,
}

impl SegmentBuilder {
    /// The size of this segment's _data_, in bytes
    pub fn size(&self) -> u64 {
        self.size
    }
    /// The size of this segment's _load command_, including its associated sections, in bytes
    pub fn load_command_size(&self, ctx: &Ctx) -> u64 {
        Segment::size_with(&ctx) as u64
            + (self.sections.len() as u64 * Section::size_with(&ctx) as u64)
    }
    fn _section_data_file_offset(&self, ctx: &Ctx) -> u64 {
        // section data
        Header::size_with(&ctx.container) as u64 + self.load_command_size(ctx)
    }
    // FIXME: this is in desperate need of refactoring, obviously
    fn build_section(
        symtab: &mut SymbolTable,
        sectname: &'static str,
        segname: &'static str,
        sections: &mut IndexMap<String, SectionBuilder>,
        offset: &mut u64,
        addr: &mut u64,
        symbol_offset: &mut u64,
        section: SectionIndex,
        definitions: &[Definition],
        alignment_exponent: u64,
        flags: Option<u32>,
    ) {
        let mut local_size = 0;
        let mut segment_relative_offset = 0;
        for def in definitions {
            if let DefinedDecl::Section { .. } = def.decl {
                unreachable!();
            }
            local_size += def.data.len() as u64;
            symtab.insert(
                def.name,
                SymbolType::Defined {
                    section,
                    segment_relative_offset,
                    absolute_offset: *symbol_offset,
                    global: def.decl.is_global(),
                },
            );
            *symbol_offset += def.data.len() as u64;
            segment_relative_offset += def.data.len() as u64;
        }
        let mut section = SectionBuilder::new(sectname.to_string(), segname, local_size)
            .offset(*offset)
            .addr(*addr)
            .align(alignment_exponent);
        if let Some(flags) = flags {
            section = section.flags(flags);
        }
        *offset += local_size;
        *addr += local_size;
        sections.insert(sectname.to_string(), section);
    }
    fn build_custom_section(
        sections: &mut IndexMap<String, SectionBuilder>,
        offset: &mut u64,
        addr: &mut u64,
        def: &Definition,
    ) {
        let s = match def.decl {
            DefinedDecl::Section(s) => s,
            _ => unreachable!("in build_custom_section: def.decl != Section"),
        };

        let segment_name = match s.kind() {
            SectionKind::Data => "__DATA",
            SectionKind::Debug => "__DWARF",
            SectionKind::Text => "__TEXT",
        };

        let sectname = if def.name.starts_with(".debug") {
            format!("__debug{}", &def.name["debug".len()..])
        } else {
            def.name.to_string()
        };

        let mut flags = 0;

        if s.kind() == SectionKind::Debug {
            flags |= S_ATTR_DEBUG;
        }

        let local_size = def.data.len() as u64;
        let section = SectionBuilder::new(sectname, segment_name, local_size)
            .offset(*offset)
            .addr(*addr)
            .align(1)
            .flags(flags);
        *offset += local_size;
        *addr += local_size;
        sections.insert(def.name.to_string(), section);
    }
    /// Create a new program segment from an `artifact`, symbol table, and context
    // FIXME: this is pub(crate) for now because we can't leak pub(crate) Definition
    pub(crate) fn new(
        artifact: &Artifact,
        code: &[Definition],
        data: &[Definition],
        cstrings: &[Definition],
        custom_sections: &[Definition],
        symtab: &mut SymbolTable,
        ctx: &Ctx,
    ) -> Self {
        let mut offset = Header::size_with(&ctx.container) as u64;
        let mut size = 0;
        let mut symbol_offset = 0;
        let mut sections = IndexMap::new();
        Self::build_section(
            symtab,
            "__text",
            "__TEXT",
            &mut sections,
            &mut offset,
            &mut size,
            &mut symbol_offset,
            CODE_SECTION_INDEX,
            &code,
            4,
            Some(S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS),
        );
        Self::build_section(
            symtab,
            "__data",
            "__DATA",
            &mut sections,
            &mut offset,
            &mut size,
            &mut symbol_offset,
            DATA_SECTION_INDEX,
            &data,
            3,
            None,
        );
        Self::build_section(
            symtab,
            "__cstring",
            "__TEXT",
            &mut sections,
            &mut offset,
            &mut size,
            &mut symbol_offset,
            CSTRING_SECTION_INDEX,
            &cstrings,
            0,
            Some(S_CSTRING_LITERALS),
        );
        for def in custom_sections {
            Self::build_custom_section(&mut sections, &mut offset, &mut size, def);
        }
        for (ref import, _) in artifact.imports() {
            symtab.insert(import, SymbolType::Undefined);
        }
        // FIXME re add assert
        //assert_eq!(offset, Header::size_with(&ctx.container) + Self::load_command_size(ctx));
        debug!(
            "Segment Size: {} Symtable LoadCommand Offset: {}",
            size, offset
        );
        SegmentBuilder {
            size,
            sections,
            offset,
        }
    }

    pub fn write_load_commands<T: Write + Seek>(
        &self,
        ctx: Ctx,
        mut file: T,
        first_section_offset: u64,
        relocation_offset_start: u64,
    ) -> Result<SegmentBuildRes, Error> {
        // marshall the sections into something we can actually write
        let mut raw_sections = Cursor::new(Vec::<u8>::new());
        let mut section_offset = first_section_offset;
        let mut relocation_offset = relocation_offset_start;
        let mut relocations = Vec::new();

        for section in self.sections.values() {
            let header = section.create(&mut section_offset, &mut relocation_offset, &mut relocations);
            debug!("Section: {:#?}", header);
            raw_sections.iowrite_with(header, ctx)?;
        }

        let mut segment_load_command = Segment::new(ctx, &*raw_sections.get_ref());
        segment_load_command.nsects = u32::try_from(self.sections.len()).expect("More than u32::max_value() sections");
        segment_load_command.initprot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
        segment_load_command.maxprot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
        segment_load_command.filesize = self.size();
        segment_load_command.vmsize = segment_load_command.filesize;
        segment_load_command.fileoff = first_section_offset;

        debug!("Segment: {:#?}", segment_load_command);

        let segment_load_command_cmdsize = u64::from(segment_load_command.cmdsize);

        file.iowrite_with(segment_load_command, ctx)?;
        file.write_all(&raw_sections.get_ref())?;

        Ok(SegmentBuildRes {
            relocations,
            segment_load_command_cmdsize,
            raw_sections_len: raw_sections.get_ref().len(),
        })
    }
}

pub struct SegmentBuildRes {
    pub relocations: Vec<RelocationInfo>,
    pub segment_load_command_cmdsize: u64,
    pub raw_sections_len: usize,
}
