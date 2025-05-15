use std::collections::HashMap;

use crate::{common, elf_parser};

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Elf64Ehdr {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Elf64Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

#[derive(Debug, Clone)]
pub struct Elf {
    pub data: Vec<u8>,
    pub ehdr: Elf64Ehdr,
    pub section_name_table: Option<Vec<u8>>,
    pub shdrs: HashMap<String, Elf64Shdr>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub enum BpfRelocationType {
    RBpfNone = 0,
    RBpf64_64 = 1,
    RBpf64Abs64 = 2,
    RBpf64Abs32 = 3,
    RBpf64Nodyld32 = 4,
    RBpf64_32 = 10,
}

#[derive(Debug, Clone)]
pub struct Elf64Rel {
    pub r_offset: u64,
    pub rel_type: BpfRelocationType,
    pub sym_idx: u32,
}

pub fn relocate(data: &mut [u8], rel_section: &[Elf64Rel], rel_map: &HashMap<u32, i64>) {
    for Elf64Rel {
        r_offset,
        rel_type,
        sym_idx,
    } in rel_section
    {
        match rel_type {
            BpfRelocationType::RBpfNone => {}
            BpfRelocationType::RBpf64_64 => {
                if let Some(&addr) = rel_map.get(sym_idx) {
                    let r_offset = *r_offset as usize;
                    let offset = r_offset + 4;
                    // rewrite src to 0x1
                    if r_offset + 1 < data.len() {
                        let value = data[r_offset + 1];
                        let new_value = value | 0x10;
                        data[r_offset + 1] = new_value;
                    }
                    // rewrite imm to map_fd
                    if offset + 4 <= data.len() {
                        let value =
                            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
                        let new_value = value.wrapping_add(addr as u32);
                        data[offset..offset + 4].copy_from_slice(&new_value.to_le_bytes());
                    }
                }
            }
            _ => unimplemented!(),
        }
    }
}

impl Elf {
    pub fn get_section_body(&self, section_name: &str) -> Option<&[u8]> {
        if let Some(shdr) = self.shdrs.get(section_name) {
            let start = shdr.sh_offset as usize;
            let end = start + shdr.sh_size as usize;
            if end <= self.data.len() {
                return Some(&self.data[start..end]);
            }
        }
        None
    }

    pub fn parse_relocation_section(&self, section_name: &str) -> Option<Vec<Elf64Rel>> {
        if let Some(shdr) = self.shdrs.get(section_name) {
            let start = shdr.sh_offset as usize;
            let end = start + shdr.sh_size as usize;
            if end <= self.data.len() {
                let mut relocations = Vec::new();
                for offset in (start..end).step_by(std::mem::size_of::<Elf64Rel>()) {
                    let r_offset = *common::read_struct::<u64>(&self.data, offset)?;
                    let rel_type = common::read_struct::<u32>(&self.data, offset + 8)?;
                    let sym_idx = *common::read_struct::<u32>(&self.data, offset + 12)?;
                    let rel = Elf64Rel {
                        r_offset,
                        rel_type: match rel_type {
                            0 => BpfRelocationType::RBpfNone,
                            1 => BpfRelocationType::RBpf64_64,
                            2 => BpfRelocationType::RBpf64Abs64,
                            3 => BpfRelocationType::RBpf64Abs32,
                            4 => BpfRelocationType::RBpf64Nodyld32,
                            10 => BpfRelocationType::RBpf64_32,
                            _ => continue, // Skip unknown types
                        },
                        sym_idx,
                    };
                    relocations.push(rel);
                }
                return Some(relocations);
            }
        }
        None
    }
}
