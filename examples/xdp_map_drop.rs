use anyhow::{Context as _, Result};
use rust_ebpf_loader::{
    elf, elf_parser,
    syscalls_wrapper::{self, BpfMapType, BpfMapUpdateFlag, BpfProgType},
};

fn main() -> Result<()> {
    let path = "./ebpf_bin/xdp_map_drop.o";
    let elf = elf_parser::parse_elf(path)?;
    let mut xdp_section = elf
        .get_section_body("xdp")
        .context("Failed to get xdp section")?
        .to_vec();
    let xdp_rel_section = elf.parse_relocation_section(".relxdp");
    let map = unsafe { syscalls_wrapper::bpf_map_create(BpfMapType::Array, 4, 4, 1)? };
    unsafe { syscalls_wrapper::bpf_map_update_elem(map, &0, &1, BpfMapUpdateFlag::Any)? };
    elf::relocate(
        &mut xdp_section,
        &xdp_rel_section.unwrap(),
        &vec![(3, map as i64)].into_iter().collect(),
    );
    let mut log_buf = vec![0; 4096];
    let prog_fd = unsafe {
        syscalls_wrapper::bpf_prog_load(BpfProgType::Xdp, &xdp_section, "GPL", &mut log_buf, 1)?
    };
    // attach xdp to lo interface
    let ret = unsafe { syscalls_wrapper::xdp_attach(1, prog_fd as i32)? };
    std::thread::sleep(std::time::Duration::from_secs(3));
    unsafe { syscalls_wrapper::bpf_map_update_elem(map, &0, &0, BpfMapUpdateFlag::Any)? };
    println!("map updated");
    std::thread::sleep(std::time::Duration::from_secs(3));
    unsafe { syscalls_wrapper::bpf_map_update_elem(map, &0, &1, BpfMapUpdateFlag::Any)? };
    println!("map updated");
    std::thread::sleep(std::time::Duration::from_secs(3));
    unsafe { syscalls_wrapper::close(ret)? };
    unsafe { syscalls_wrapper::close(map)? };

    Ok(())
}

static PROGRAM: &str = r#"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} drop_flag SEC(".maps");

SEC("xdp")
int xdp_prog_map(struct xdp_md *ctx) {
    __u32 key = 0;
    __u32 *flag = bpf_map_lookup_elem(&drop_flag, &key);

    if (flag && *flag == 1) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"#;
