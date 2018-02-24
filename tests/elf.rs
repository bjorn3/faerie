extern crate faerie;
extern crate scroll;
extern crate goblin;

use faerie::{Artifact, Decl, Target, Link};
use goblin::elf::*;

#[test]
#[should_panic]
fn file_name_is_same_as_symbol_name_issue_31() {
    const NAME: &str = "a";
    let mut obj = Artifact::new(Target::X86_64, "a".into());
    obj.declare(NAME, Decl::Function { global: true }).expect("can declare");
    obj.define(NAME, vec![1, 2, 3, 4]).expect("can define");
    println!("\n{:#?}", obj);
    let bytes = obj.emit::<faerie::Elf>().expect("can emit elf file");
    let bytes = bytes.as_slice();
    println!("{:?}", bytes);

    let elf = goblin::Object::parse(&bytes).expect("can parse elf file");
    match elf {
        goblin::Object::Elf(elf) => {
            assert_eq!(elf.syms.len(), 3);
            let syms =  elf.syms.iter().collect::<Vec<_>>();
            let sym = syms.iter().find(|sym| {
                sym.st_type() as u32 == section_header::SHN_ABS
            }).expect("There should be a SHN_ABS symbol");
            println!("{:?}", sym);
            assert_eq!(&elf.strtab[sym.st_name], "a");
        },
        _ => {
            println!("Elf file not parsed as elf file");
            assert!(false)
        }
    }
}

#[test]
#[should_panic]
fn link_symbol_pair_panic_issue_30() {
    let mut obj = Artifact::new(Target::X86_64, "t.o".into());

    obj.declare("a", Decl::Function { global: true }).expect("can declare a");
    obj.declare("b", Decl::Function { global: true }).expect("can declare b");

    let code = vec![1, 2, 3, 4];
    obj.define("b", code).expect("can define b");
    obj.link(Link {
        to: "a",
        from: "b",
        at: 0,
    }).expect("can link a to b");

    let _bytes = obj.emit::<faerie::Elf>().expect("Can emit object bytes");
}