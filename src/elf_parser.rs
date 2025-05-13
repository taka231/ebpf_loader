use anyhow::{bail, Context as _, Result};
use std::collections::HashMap;
use std::fs;
use std::mem::size_of;
use std::path::Path;

use crate::{
    common,
    elf::{Elf, Elf64Ehdr, Elf64Shdr},
};

fn read_section_name_table<'a>(
    data: &'a [u8],
    shdrs: &'a [&'a Elf64Shdr],
    shstrndx: usize,
) -> Option<&'a [u8]> {
    let name_section = &shdrs[shstrndx];
    let start = name_section.sh_offset as usize;
    let end = start + name_section.sh_size as usize;
    if end <= data.len() {
        Some(&data[start..end])
    } else {
        None
    }
}

pub fn parse_elf<P: AsRef<Path>>(path: P) -> Result<Elf> {
    let data = fs::read(path).context("Failed to read ELF file")?;

    let ehdr = common::read_struct::<Elf64Ehdr>(&data, 0)
        .context("File too small for ELF header")?
        .clone();

    if &ehdr.e_ident[0..4] != b"\x7fELF" {
        bail!("Not an ELF file");
    }

    let shoff = ehdr.e_shoff as usize;
    let shentsize = ehdr.e_shentsize as usize;
    let shnum = ehdr.e_shnum as usize;

    let mut shdrs = Vec::new();
    for i in 0..shnum {
        let offset = shoff + i * shentsize;
        let sh = common::read_struct::<Elf64Shdr>(&data, offset)
            .context("Failed to read section header")?;
        shdrs.push(sh);
    }

    let name_table = read_section_name_table(&data, &shdrs, ehdr.e_shstrndx as usize)
        .context("Invalid section name table")?;

    let section_map: HashMap<String, Elf64Shdr> = shdrs
        .iter()
        .map(|&sh| {
            let name = common::get_name_from_string_section(name_table, sh.sh_name as usize)?;
            Ok((name.to_string(), sh.clone()))
        })
        .collect::<Result<_>>()?;
    let section_name_table = Some(name_table.to_vec());
    Ok(Elf {
        data,
        ehdr: ehdr.clone(),
        shdrs: section_map,
        section_name_table,
    })
}
