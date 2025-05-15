use rust_ebpf_loader::btf_parser;
use rust_ebpf_loader::common;
use rust_ebpf_loader::elf;
use rust_ebpf_loader::elf_parser;
use rust_ebpf_loader::syscalls_wrapper;
use rust_ebpf_loader::syscalls_wrapper::BpfMapType;
use rust_ebpf_loader::syscalls_wrapper::BpfMapUpdateFlag;
use rust_ebpf_loader::syscalls_wrapper::BpfProgType;

fn main() -> anyhow::Result<()> {
    let vmlinux_path = "/sys/kernel/btf/vmlinux";
    let vmlinux_bin = std::fs::read(vmlinux_path)?;
    let vmlinux_btf = btf_parser::parse_btf(&vmlinux_bin, 0)?;

    let path = "/home/taka2/ebpf/sample_xdp_drop/xdp_ipv6_drop_co_re.o";
    let elf = elf_parser::parse_elf(path)?;
    let mut xdp_section = elf.get_section_body("xdp").unwrap().to_vec();

    let xdp_btf_section = btf_parser::parse_btf(elf.get_section_body(".BTF").unwrap(), 0)?;
    let xdp_btf_ext_section =
        btf_parser::parse_btf_ext(elf.get_section_body(".BTF.ext").unwrap(), 0)?;

    let map = unsafe { syscalls_wrapper::bpf_map_create(BpfMapType::Array, 4, 4, 1)? };
    unsafe { syscalls_wrapper::bpf_map_update_elem(map, &0, &1, BpfMapUpdateFlag::Any)? };

    // let xdp_rel_section = elf.parse_relocation_section(".relxdp");
    // elf::relocate(
    //     &mut xdp_section,
    //     &xdp_rel_section.unwrap(),
    //     &vec![(3, map as i64)].into_iter().collect(),
    // );

    let mut log_buf = vec![0; 4096];
    let prog_fd = unsafe {
        let result =
            syscalls_wrapper::bpf_prog_load(BpfProgType::Xdp, &xdp_section, "GPL", &mut log_buf, 1);
        match result {
            Ok(fd) => fd,
            Err(e) => {
                println!(
                    "log_bug:\n{}",
                    String::from_utf8_lossy(
                        &log_buf
                            .into_iter()
                            .take_while(|&c| c != 0)
                            .collect::<Vec<_>>()
                    )
                );

                unsafe { syscalls_wrapper::close(map)? };
                return Err(e.into());
            }
        }
    };
    println!(
        "log_bug:\n{}",
        String::from_utf8_lossy(
            &log_buf
                .into_iter()
                .take_while(|&c| c != 0)
                .collect::<Vec<_>>()
        )
    );
    println!("fd: {prog_fd}");
    let ret = unsafe { syscalls_wrapper::xdp_attach(1, prog_fd as i32)? };
    // std::thread::sleep(std::time::Duration::from_secs(10));
    // unsafe { syscalls_wrapper::bpf_map_update_elem(map, &0, &0, BpfMapUpdateFlag::Any)? };
    // println!("update map");
    // std::thread::sleep(std::time::Duration::from_secs(3));
    // unsafe { syscalls_wrapper::bpf_map_update_elem(map, &0, &1, BpfMapUpdateFlag::Any)? };
    // println!("update map");
    // std::thread::sleep(std::time::Duration::from_secs(3));
    unsafe { syscalls_wrapper::close(ret)? };
    unsafe { syscalls_wrapper::close(map)? };
    Ok(())
}
