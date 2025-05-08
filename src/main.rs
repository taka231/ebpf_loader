use rust_ebpf_loader::elf;
use rust_ebpf_loader::elf_parser;
use rust_ebpf_loader::syscalls_wrapper;
use rust_ebpf_loader::syscalls_wrapper::BpfMapType;
use rust_ebpf_loader::syscalls_wrapper::BpfMapUpdateFlag;
use rust_ebpf_loader::syscalls_wrapper::BpfProgType;

fn main() -> anyhow::Result<()> {
    let path = "/home/taka2/ebpf/sample_xdp_drop/xdp_map_drop.o";
    let elf = elf_parser::parse_elf(path)?;
    println!("ELF Header: {:#?}", elf.ehdr);
    for (name, shdr) in &elf.shdrs {
        println!("Section Header: {}\n{:#?}", name, shdr);
    }
    let Some(xdp_section) = elf.get_section_body("xdp") else {
        panic!();
    };
    let mut xdp_section = xdp_section.to_vec();
    let xdp_rel_section = elf.parse_relocation_section(".relxdp");
    println!("xdp_rel_section: {:?}", xdp_rel_section);
    let map = unsafe { syscalls_wrapper::bpf_map_create(BpfMapType::Array, 4, 4, 1)? };
    unsafe { syscalls_wrapper::bpf_map_update_elem(map, &0, &0, BpfMapUpdateFlag::Any)? };
    unsafe {
        let mut value = 0;
        syscalls_wrapper::bpf_map_lookup_elem(map, &0, &mut value)?;
        println!("value: {value}");
    }
    elf::relocate(
        &mut xdp_section,
        &xdp_rel_section.unwrap(),
        &vec![(3, map as i64)].into_iter().collect(),
    );
    let mut log_buf = vec![0; 256];
    let prog_fd = unsafe {
        let result =
            syscalls_wrapper::bpf_prog_load(BpfProgType::Xdp, &xdp_section, "GPL", &mut log_buf, 1);
        match result {
            Ok(fd) => fd,
            Err(e) => {
                println!("log_bug:\n{}", String::from_utf8_lossy(&log_buf));
                return Err(e.into());
            }
        }
    };
    println!("fd: {prog_fd}");
    let ret = unsafe { syscalls_wrapper::xdp_attach(1, prog_fd as i32)? };
    std::thread::sleep(std::time::Duration::from_secs(10));
    unsafe { syscalls_wrapper::close(ret)? };
    unsafe { syscalls_wrapper::close(map)? };
    Ok(())
}
