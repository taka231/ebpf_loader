use rust_ebpf_loader::elf_parser;
use rust_ebpf_loader::syscalls_wrapper;
use rust_ebpf_loader::syscalls_wrapper::BpfProgType;

fn main() -> anyhow::Result<()> {
    let path = "/home/taka2/ebpf/sample_xdp_drop/xdp_drop.o"; // eBPF用ELFファイルパスに置き換え
    let elf = elf_parser::parse_elf(path)?;
    println!("ELF Header: {:#?}", elf.ehdr);
    for (name, shdr) in &elf.shdrs {
        println!("Section Header: {}\n{:#?}", name, shdr);
    }
    let Some(xdp_section) = elf.get_section_body("xdp") else {
        panic!();
    };
    let mut log_buf = vec![0; 256];
    let prog_fd = unsafe {
        syscalls_wrapper::bpf_prog_load(BpfProgType::Xdp, xdp_section, "GPL", &mut log_buf, 1)?
    };
    println!("fd: {prog_fd}");
    println!(
        "log_buf: {:?}",
        String::from_utf8_lossy(
            &log_buf
                .into_iter()
                .take_while(|&c| c != 0)
                .collect::<Vec<_>>()
        )
    );
    let socket_fd = unsafe { syscalls_wrapper::open_raw_sock(1)? };
    println!("socket_fd: {socket_fd}");
    let ret = unsafe { syscalls_wrapper::xdp_attach(socket_fd, prog_fd as i32)? };
    // std::thread::sleep(std::time::Duration::from_secs(10));
    // unsafe { syscalls_wrapper::detach(ret)? };
    //
    Ok(())
}
