#[repr(C)]
#[derive(Clone, Copy)]
struct BpfMapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfMapElemAttr {
    map_fd: u32,
    key: u64,
    value_or_next_key: ValueOrNextKey,
    flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ValueOrNextKey {
    pub value: u64,
    pub next_key: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfMapGetNextKeyAttr {
    map_fd: u32,
    key: u64,
    next_key: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
}

#[repr(C)]
union BpfAttr {
    map_create: BpfMapCreateAttr,
    map_elem: BpfMapElemAttr,
    prog_load: BpfProgLoadAttr,
}

#[derive(Debug, Clone, Copy)]
pub enum BpfProgType {
    Unspec, /* Reserve 0 as invalid
            program type */
    SocketFilter,
    Kprobe,
    SchedCls,
    SchedAct,
    Tracepoint,
    Xdp,
    PerfEvent,
    CgroupSkb,
    CgroupSock,
    LwtIn,
    LwtOut,
    LwtXmit,
    SockOps,
    SkSkb,
    CgroupDevice,
    SkMsg,
    RawTracepoint,
    CgroupSockAddr,
    LwtSeg6local,
    LircMode2,
    SkReuseport,
    FlowDissector,
    /* See /usr/include/linux/bpf.h for the full list. */
}

enum BpfCmd {
    MapCreate,
    MapLookupElem,
    MapUpdateElem,
    MapDeleteElem,
    MapGetNextKey,
    ProgLoad,
}

fn handle_error(ret: i64) -> Result<i64, std::io::Error> {
    if ret == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

unsafe fn bpf(cmd: i32, attr: &BpfAttr, size: usize) -> Result<usize, std::io::Error> {
    let ret = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, size) };
    Ok(handle_error(ret)? as usize)
}

pub unsafe fn bpf_prog_load(
    prog_type: BpfProgType,
    insns: &[u8],
    license: &str,
    log_buf: &mut Vec<u8>,
    log_level: u32,
) -> Result<usize, std::io::Error> {
    let log_size = log_buf.len() as u32;
    let insn_cnt = insns.len() as u32 / std::mem::size_of::<u64>() as u32;
    let attr = BpfAttr {
        prog_load: BpfProgLoadAttr {
            prog_type: prog_type as u32,
            insns: insns.as_ptr() as u64,
            insn_cnt,
            license: license.as_ptr() as u64,
            log_buf: log_buf.as_mut_ptr() as u64,
            log_size,
            log_level,
        },
    };
    unsafe {
        bpf(
            BpfCmd::ProgLoad as i32,
            &attr,
            std::mem::size_of::<BpfProgLoadAttr>(),
        )
    }
}

pub unsafe fn detach(fd: i32) -> Result<i32, std::io::Error> {
    let ret = unsafe { libc::close(fd) };
    Ok(handle_error(ret as i64)? as i32)
}

pub unsafe fn xdp_attach(socket_fd: i32, prog_fd: i32) -> Result<i32, std::io::Error> {
    // let ret = unsafe {
    //     libc::setsockopt(
    //         socket_fd,
    //         libc::SOL_SOCKET,
    //         libc::SO_ATTACH_BPF,
    //         &prog_fd as *const i32 as *const libc::c_void,
    //         std::mem::size_of_val(&prog_fd) as u32,
    //     )
    // };
    // Ok(handle_error(ret as i64)? as i32)
}

pub unsafe fn open_raw_sock(ifindex: i32) -> Result<i32, std::io::Error> {
    let socket_fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if socket_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    if unsafe {
        libc::bind(
            socket_fd,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        ) < 0
    } {
        return Err(std::io::Error::last_os_error());
    }
    Ok(socket_fd)
}

const PERF_EVENT_IOC_SET_BPF: u32 = libc::_IOW::<u32>('$' as u32, 8);

unsafe fn attach(event_fd: i32, prog_fd: i32) -> Result<i32, std::io::Error> {
    let ret = unsafe { libc::ioctl(event_fd, PERF_EVENT_IOC_SET_BPF as u64, prog_fd) };
    Ok(handle_error(ret as i64)? as i32)
}

unsafe fn perf_event_open(attr: &PerfEventAttr) -> Result<i32, std::io::Error> {
    let ret = unsafe { libc::syscall(libc::SYS_perf_event_open, attr, -1, 0, -1, 0) };
    Ok(handle_error(ret)? as i32)
}

impl Default for PerfEventAttr {
    fn default() -> Self {
        PerfEventAttr {
            type_: 0,
            size: std::mem::size_of::<PerfEventAttr>() as u32,
            config: 0,
            sample: SampleUnion { sample_period: 0 },
            sample_type: 0,
            read_format: 0,
            flags: Flags::default(),
            wakeup: WakeupUnion { wakeup_events: 0 },
            bp_type: 0,
            config1: Config1Union { bp_addr: 0 },
            config2: Config2Union { bp_len: 0 },
            branch_sample_type: 0,
            sample_regs_user: 0,
            sample_stack_user: 0,
            clockid: 0,
            sample_regs_intr: 0,
            aux_watermark: 0,
            sample_max_stack: 0,
            __reserved_2: 0,
            aux_sample_size: 0,
            __reserved_3: 0,
            sig_data: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PerfEventAttr {
    pub type_: u32,
    pub size: u32,
    pub config: u64,
    pub sample: SampleUnion,
    pub sample_type: u64,
    pub read_format: u64,
    pub flags: Flags,
    pub wakeup: WakeupUnion,
    pub bp_type: u32,
    pub config1: Config1Union,
    pub config2: Config2Union,
    pub branch_sample_type: u64,
    pub sample_regs_user: u64,
    pub sample_stack_user: u32,
    pub clockid: i32,
    pub sample_regs_intr: u64,
    pub aux_watermark: u32,
    pub sample_max_stack: u16,
    pub __reserved_2: u16,
    pub aux_sample_size: u32,
    pub __reserved_3: u32,
    pub sig_data: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SampleUnion {
    pub sample_period: u64,
    pub sample_freq: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union WakeupUnion {
    pub wakeup_events: u32,
    pub wakeup_watermark: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union Config1Union {
    pub bp_addr: u64,
    pub kprobe_func: u64,
    pub uprobe_path: u64,
    pub config1: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union Config2Union {
    pub bp_len: u64,
    pub kprobe_addr: u64,
    pub probe_offset: u64,
    pub config2: u64,
}

// ビットフィールドを64bit整数で表現
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Flags {
    pub bits: u64,
}

impl Flags {
    pub fn set(&mut self, bit: usize, val: bool) {
        if bit >= 64 {
            return;
        }
        if val {
            self.bits |= 1 << bit;
        } else {
            self.bits &= !(1 << bit);
        }
    }

    pub fn get(&self, bit: usize) -> bool {
        if bit >= 64 {
            false
        } else {
            (self.bits & (1 << bit)) != 0
        }
    }
}
