#[repr(C)]
#[derive(Debug, Clone)]
pub struct BtfHeader {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
    pub hdr_len: u32,
    pub type_off: u32,
    pub type_len: u32,
    pub str_off: u32,
    pub str_len: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtfKind {
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Func = 12,
    FuncProto = 13,
    Var = 14,
    DataSec = 15,
    Float = 16,
    DeclTag = 17,
    TypeTag = 18,
    Enum64 = 19,
}

impl TryFrom<u32> for BtfKind {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(BtfKind::Int),
            2 => Ok(BtfKind::Ptr),
            3 => Ok(BtfKind::Array),
            4 => Ok(BtfKind::Struct),
            5 => Ok(BtfKind::Union),
            6 => Ok(BtfKind::Enum),
            7 => Ok(BtfKind::Fwd),
            8 => Ok(BtfKind::Typedef),
            9 => Ok(BtfKind::Volatile),
            10 => Ok(BtfKind::Const),
            11 => Ok(BtfKind::Restrict),
            12 => Ok(BtfKind::Func),
            13 => Ok(BtfKind::FuncProto),
            14 => Ok(BtfKind::Var),
            15 => Ok(BtfKind::DataSec),
            16 => Ok(BtfKind::Float),
            17 => Ok(BtfKind::DeclTag),
            18 => Ok(BtfKind::TypeTag),
            19 => Ok(BtfKind::Enum64),
            _ => Err(anyhow::anyhow!("Invalid BTF kind: {}", value)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BtfType {
    pub name_off: u32,
    pub vlen: u16,
    pub kind: BtfKind,
    pub kind_flag: bool,
    pub size_or_type: u32,
    pub detail: BtfTypeDetail,
}

#[derive(Debug, Clone)]
pub enum BtfTypeDetail {
    None,
    Ignored,
    Struct(Vec<BtfMember>),
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct BtfMember {
    pub name_off: u32,
    pub type_id: u32,
    pub offset: u32,
}

impl BtfMember {
    pub fn get_offset(&self, kind_flag: bool) -> u32 {
        if kind_flag {
            self.offset & 0xffffff
        } else {
            self.offset
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct BtfExtHeader {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
    pub hdr_len: u32,
    pub func_info_off: u32,
    pub func_info_len: u32,
    pub line_info_off: u32,
    pub line_info_len: u32,
    pub core_relo_off: u32,
    pub core_relo_len: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum BpfCoreReloKind {
    FieldByteOffset = 0,
    FieldByteSize = 1,
    FieldExists = 2,
    FieldSigned = 3,
    FieldLShiftU64 = 4,
    FieldRShiftU64 = 5,
    TypeIdLocal = 6,
    TypeIdTarget = 7,
    TypeExists = 8,
    TypeSize = 9,
    EnumValExists = 10,
    EnumValValue = 11,
    TypeMatches = 12,
}

impl TryFrom<u32> for BpfCoreReloKind {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BpfCoreReloKind::FieldByteOffset),
            1 => Ok(BpfCoreReloKind::FieldByteSize),
            2 => Ok(BpfCoreReloKind::FieldExists),
            3 => Ok(BpfCoreReloKind::FieldSigned),
            4 => Ok(BpfCoreReloKind::FieldLShiftU64),
            5 => Ok(BpfCoreReloKind::FieldRShiftU64),
            6 => Ok(BpfCoreReloKind::TypeIdLocal),
            7 => Ok(BpfCoreReloKind::TypeIdTarget),
            8 => Ok(BpfCoreReloKind::TypeExists),
            9 => Ok(BpfCoreReloKind::TypeSize),
            10 => Ok(BpfCoreReloKind::EnumValExists),
            11 => Ok(BpfCoreReloKind::EnumValValue),
            12 => Ok(BpfCoreReloKind::TypeMatches),
            _ => Err(anyhow::anyhow!(
                "Invalid BPF core relocation kind: {}",
                value
            )),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct BpfCoreRelo {
    pub insn_off: u32,
    pub type_id: u32,
    pub access_str_off: u32,
    pub kind: BpfCoreReloKind,
}

#[derive(Debug, Clone)]
pub struct BtfExtInfoSec<T> {
    pub sec_name_off: u32,
    pub data: Vec<T>,
}

#[derive(Debug, Clone)]
pub struct Btf<'a> {
    pub header: &'a BtfHeader,
    pub string_section: &'a [u8],
    pub type_section: Vec<BtfType>,
}

#[derive(Debug, Clone)]
pub struct BtfExt<'a> {
    pub header: &'a BtfExtHeader,
    pub core_relo_part: Vec<BtfExtInfoSec<BpfCoreRelo>>,
}
