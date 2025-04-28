use std::collections::HashMap;

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
    pub shdrs: HashMap<String, Elf64Shdr>,
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
}
