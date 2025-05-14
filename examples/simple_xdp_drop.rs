use anyhow::{Context as _, Result};
use rust_ebpf_loader::{
    elf_parser,
    syscalls_wrapper::{self, BpfProgType},
};

fn main() -> Result<()> {
    let path = "./ebpf_bin/xdp_drop.o";
    let elf = elf_parser::parse_elf(path)?;
    let xdp_section = elf
        .get_section_body("xdp")
        .context("Failed to get xdp section")?;
    let mut log_buf = vec![0; 4096];
    let prog_fd = unsafe {
        syscalls_wrapper::bpf_prog_load(BpfProgType::Xdp, xdp_section, "GPL", &mut log_buf, 1)?
    };
    // attach xdp to lo interface
    let ret = unsafe { syscalls_wrapper::xdp_attach(1, prog_fd as i32)? };
    std::thread::sleep(std::time::Duration::from_secs(3));
    unsafe { syscalls_wrapper::close(ret)? };

    Ok(())
}

static PROGRAM: &str = r#"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx) {
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
"#;
