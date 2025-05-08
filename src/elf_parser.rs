use anyhow::{bail, Context as _, Result};
use std::collections::HashMap;
use std::fs;
use std::mem::size_of;
use std::path::Path;

use crate::elf::{Elf, Elf64Ehdr, Elf64Shdr};

pub fn read_struct<T>(data: &[u8], offset: usize) -> Option<&T> {
    if offset + size_of::<T>() > data.len() {
        return None;
    }
    unsafe {
        Some(
            data[offset..offset + size_of::<T>()]
                .as_ptr()
                .cast::<T>()
                .as_ref()
                .unwrap(),
        )
    }
}

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

fn get_section_name(name_table: &[u8], sh_name: u32) -> &str {
    let start = sh_name as usize;
    let end = name_table[start..]
        .iter()
        .position(|&c| c == 0)
        .map(|pos| start + pos)
        .unwrap_or(name_table.len());
    std::str::from_utf8(&name_table[start..end]).unwrap_or("<invalid>")
}

pub fn parse_elf<P: AsRef<Path>>(path: P) -> Result<Elf> {
    let data = fs::read(path).context("Failed to read ELF file")?;

    let ehdr = read_struct::<Elf64Ehdr>(&data, 0)
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
        let sh =
            read_struct::<Elf64Shdr>(&data, offset).context("Failed to read section header")?;
        shdrs.push(sh);
    }

    let name_table = read_section_name_table(&data, &shdrs, ehdr.e_shstrndx as usize)
        .context("Invalid section name table")?;

    let section_map: HashMap<String, Elf64Shdr> = shdrs
        .iter()
        .map(|&sh| {
            let name = get_section_name(name_table, sh.sh_name);
            (name.to_string(), sh.clone())
        })
        .collect();
    let section_name_table = Some(name_table.to_vec());
    Ok(Elf {
        data,
        ehdr: ehdr.clone(),
        shdrs: section_map,
        section_name_table,
    })
}
