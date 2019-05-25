//! The Mach 32/64 bit backend for transforming an artifact to a valid, mach-o object file.

use crate::artifact::{DataType, DefinedDecl, Definition};
use crate::target::make_ctx;
use crate::{Artifact, Ctx};

use failure::Error;
use scroll::ctx::SizeWith;
use scroll::IOwrite;
use std::convert::TryFrom;
use std::io::SeekFrom::*;
use std::io::{BufWriter, Cursor, Seek, Write};
use string_interner::DefaultStringInterner;
use target_lexicon::Architecture;

use goblin::mach::cputype;
use goblin::mach::header::{Header, MH_OBJECT, MH_SUBSECTIONS_VIA_SYMBOLS};
use goblin::mach::load_command::SIZEOF_SYMTAB_COMMAND;

mod relocations;
mod section;
mod segment;
mod symbols;

use section::{
    CODE_SECTION_INDEX, DATA_SECTION_INDEX, CSTRING_SECTION_INDEX, SectionBuilder, SectionIndex,
};
use segment::SegmentBuilder;
use symbols::{SymbolTable, SymbolType, SymbolIndex};

struct CpuType(cputype::CpuType);

impl From<Architecture> for CpuType {
    fn from(architecture: Architecture) -> CpuType {
        use goblin::mach::cputype::*;
        use target_lexicon::Architecture::*;
        CpuType(match architecture {
            X86_64 => CPU_TYPE_X86_64,
            I386 | I586 | I686 => CPU_TYPE_X86,
            Aarch64 => CPU_TYPE_ARM64,
            Arm | Armv4t | Armv5te | Armv7 | Armv7s | Thumbv6m | Thumbv7em | Thumbv7m => {
                CPU_TYPE_ARM
            }
            Sparc => CPU_TYPE_SPARC,
            Powerpc => CPU_TYPE_POWERPC,
            Powerpc64 | Powerpc64le => CPU_TYPE_POWERPC64,
            Unknown => 0,
            _ => panic!("requested architecture does not exist in MachO"),
        })
    }
}

type StrtableOffset = u64;

type ArtifactCode<'a> = Vec<Definition<'a>>;
type ArtifactData<'a> = Vec<Definition<'a>>;

type StrTableIndex = usize;
type StrTable = DefaultStringInterner;

/// A Mach-o object file container
#[derive(Debug)]
struct Mach<'a> {
    ctx: Ctx,
    architecture: Architecture,
    symtab: SymbolTable,
    segment: SegmentBuilder,
    code: ArtifactCode<'a>,
    data: ArtifactData<'a>,
    cstrings: Vec<Definition<'a>>,
    sections: Vec<Definition<'a>>,
    _p: ::std::marker::PhantomData<&'a ()>,
}

impl<'a> Mach<'a> {
    pub fn new(artifact: &'a Artifact) -> Self {
        let ctx = make_ctx(&artifact.target);
        // FIXME: I believe we can avoid this partition by refactoring SegmentBuilder::new
        let (mut code, mut data, mut cstrings, mut sections) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for def in artifact.definitions() {
            match def.decl {
                DefinedDecl::Function { .. } => {
                    code.push(def);
                }
                DefinedDecl::Data(d) => {
                    if d.get_datatype() == DataType::String {
                        cstrings.push(def);
                    } else {
                        data.push(def);
                    }
                }
                DefinedDecl::Section(_) => {
                    sections.push(def);
                }
            }
        }

        let mut symtab = SymbolTable::new();
        let mut segment = SegmentBuilder::new(
            &artifact,
            &code,
            &data,
            &cstrings,
            &sections,
            &mut symtab,
            &ctx,
        );
        relocations::build_relocations(&mut segment, &artifact, &symtab);

        Mach {
            ctx,
            architecture: artifact.target.architecture,
            symtab,
            segment,
            _p: ::std::marker::PhantomData::default(),
            code,
            data,
            cstrings,
            sections,
        }
    }
    fn header(&self, sizeofcmds: u64) -> Header {
        let mut header = Header::new(&self.ctx);
        header.filetype = MH_OBJECT;
        // safe to divide up the sections into sub-sections via symbols for dead code stripping
        header.flags = MH_SUBSECTIONS_VIA_SYMBOLS;
        header.cputype = CpuType::from(self.architecture).0;
        header.cpusubtype = 3;
        header.ncmds = 2;
        header.sizeofcmds = sizeofcmds as u32;
        header
    }
    pub fn write<T: Write + Seek>(self, file: T) -> Result<(), Error> {
        let mut file = BufWriter::new(file);

        // sizes
        let segment_load_command_size = self.segment.load_command_size(&self.ctx);
        let sizeof_load_commands = segment_load_command_size + SIZEOF_SYMTAB_COMMAND as u64;

        // offsets
        let symtable_offset = self.segment.offset + sizeof_load_commands;
        let strtable_offset = symtable_offset + self.symtab.sizeof_symtable(self.ctx);
        let relocation_offset_start = strtable_offset + self.symtab.sizeof_strtable();
        let first_section_offset = Header::size_with(&self.ctx) as u64 + sizeof_load_commands;

        {
            // start with setting the headers dependent value
            let header = self.header(sizeof_load_commands);

            //////////////////////////////
            // write header
            //////////////////////////////
            file.iowrite_with(header, self.ctx)?;
            debug!("SEEK: after header: {}", file.seek(Current(0))?);
        }

        debug!("Symtable: {:#?}", self.symtab);
        // marshall the sections into something we can actually write
        let mut raw_sections = Cursor::new(Vec::<u8>::new());
        let mut relocations = Vec::new();
        let mut relocation_offset = relocation_offset_start;
        let mut section_offset = first_section_offset;
        for section in self.segment.sections.values() {
            let header = section.create(&mut section_offset, &mut relocation_offset, &mut relocations);
            debug!("Section: {:#?}", header);
            raw_sections.iowrite_with(header, self.ctx)?;
        }
        let raw_sections = raw_sections.into_inner();
        debug!(
            "Raw sections len: {} - Section start: {} Strtable size: {} - Segment size: {}",
            raw_sections.len(),
            first_section_offset,
            self.symtab.sizeof_strtable(),
            self.segment.size()
        );

        let segment_load_command = self.segment.load_command(self.ctx, &raw_sections, first_section_offset);
        debug!("Segment: {:#?}", segment_load_command);

        debug!("Symtable Offset: {:#?}", symtable_offset);

        assert_eq!(
            symtable_offset,
            self.segment.offset
                + segment_load_command.cmdsize as u64
                + SIZEOF_SYMTAB_COMMAND as u64
        );
        let symtab_load_command = self.symtab.load_command(
            u32::try_from(symtable_offset).unwrap(),
            u32::try_from(strtable_offset).unwrap(),
        );
        debug!("Symtab Load command: {:#?}", symtab_load_command);

        //////////////////////////////
        // write load commands
        //////////////////////////////
        file.iowrite_with(segment_load_command, self.ctx)?;
        file.write_all(&raw_sections)?;
        file.iowrite_with(symtab_load_command, self.ctx.le)?;
        debug!("SEEK: after load commands: {}", file.seek(Current(0))?);

        //////////////////////////////
        // write code
        //////////////////////////////
        for code in self.code {
            file.write_all(code.data)?;
        }
        debug!("SEEK: after code: {}", file.seek(Current(0))?);

        //////////////////////////////
        // write data
        //////////////////////////////
        for data in self.data {
            file.write_all(data.data)?;
        }
        debug!("SEEK: after data: {}", file.seek(Current(0))?);

        //////////////////////////////
        // write cstrings
        //////////////////////////////
        for cstring in self.cstrings {
            file.write_all(cstring.data)?;
        }
        debug!("SEEK: after cstrings: {}", file.seek(Current(0))?);

        //////////////////////////////
        // write custom sections
        //////////////////////////////
        for section in self.sections {
            file.write_all(section.data)?;
        }
        debug!("SEEK: after custom sections: {}", file.seek(Current(0))?);

        symbols::write(&mut file, self.ctx, self.symtab)?;

        //////////////////////////////
        // write relocations
        //////////////////////////////
        debug!("Relocations: {}", relocations.len());
        for reloc in relocations {
            debug!("  {:?}", reloc);
            file.iowrite_with(reloc, self.ctx.le)?;
        }
        debug!("SEEK: after relocations: {}", file.seek(Current(0))?);

        file.iowrite(0u8)?;

        Ok(())
    }
}

pub fn to_bytes(artifact: &Artifact) -> Result<Vec<u8>, Error> {
    let mach = Mach::new(&artifact);
    let mut buffer = Cursor::new(Vec::new());
    mach.write(&mut buffer)?;
    Ok(buffer.into_inner())
}
