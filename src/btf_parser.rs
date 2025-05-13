use anyhow::{bail, Context as _, Result};

use crate::{
    btf::{
        BpfCoreRelo, BpfCoreReloKind, BtfExtHeader, BtfExtInfoSec, BtfHeader, BtfKind, BtfMember,
        BtfType, BtfTypeDetail,
    },
    common,
};

fn parse_btf_header(data: &[u8], offset: usize) -> Result<&BtfHeader> {
    let btf_header =
        common::read_struct::<BtfHeader>(data, offset).context("File too small for BTF header")?;
    if btf_header.magic != 0xeb9f {
        bail!("Not a BTF file");
    }
    Ok(btf_header)
}

fn parse_btf_string_section<'a>(
    data: &'a [u8],
    offset: usize,
    btf_header: &'a BtfHeader,
) -> Result<&'a [u8]> {
    let str_offset = btf_header.str_off as usize;
    let str_size = btf_header.str_len as usize;
    let start = str_offset + offset;
    let end = start + str_size;
    if end <= data.len() {
        Ok(&data[start..end])
    } else {
        bail!("String section out of bounds");
    }
}

fn parse_btf_type_section<'a>(
    data: &'a [u8],
    offset: usize,
    btf_header: &'a BtfHeader,
) -> Result<Vec<BtfType>> {
    let type_offset = btf_header.type_off as usize;
    let type_size = btf_header.type_len as usize;
    let mut start = type_offset + offset;
    let end = start + type_size;
    if end <= data.len() {
        let dummy = BtfType {
            name_off: 0,
            vlen: 0,
            kind: BtfKind::Int,
            kind_flag: false,
            size_or_type: 0,
            detail: BtfTypeDetail::None,
        };
        let mut types = vec![dummy];
        while start < end {
            let name_off =
                *common::read_struct::<u32>(data, start).context("Failed to read name offset")?;
            let info =
                *common::read_struct::<u32>(data, start + 4).context("Failed to read info")?;
            let vlen = (info & 0xffff) as u16;
            let kind: BtfKind = BtfKind::try_from((info >> 24) & 0x1f)?;
            let kind_flag = (info >> 31) != 0;
            let size_or_type =
                *common::read_struct::<u32>(data, start + 8).context("Failed to read size/type")?;
            start += 12;

            let detail = match kind {
                BtfKind::Int => {
                    start += std::mem::size_of::<u32>();
                    BtfTypeDetail::Ignored
                }
                BtfKind::Ptr => BtfTypeDetail::None,
                BtfKind::Array => {
                    start += std::mem::size_of::<u32>() * 3;
                    BtfTypeDetail::Ignored
                }
                BtfKind::Struct | BtfKind::Union => {
                    let mut members = Vec::new();
                    for _ in 0..vlen {
                        let btf_member = common::read_struct::<BtfMember>(data, start)
                            .context("Failed to read member")?
                            .clone();
                        members.push(btf_member);
                        start += std::mem::size_of::<BtfMember>();
                    }
                    BtfTypeDetail::Struct(members)
                }
                BtfKind::Enum => {
                    start += std::mem::size_of::<u32>() * 2 * vlen as usize;
                    BtfTypeDetail::Ignored
                }
                BtfKind::Fwd
                | BtfKind::Typedef
                | BtfKind::Volatile
                | BtfKind::Const
                | BtfKind::Restrict
                | BtfKind::Func => BtfTypeDetail::None,
                BtfKind::FuncProto => {
                    start += std::mem::size_of::<u32>() * 2 * vlen as usize;
                    BtfTypeDetail::Ignored
                }
                BtfKind::Var => {
                    start += std::mem::size_of::<u32>();
                    BtfTypeDetail::Ignored
                }
                BtfKind::DataSec => {
                    start += std::mem::size_of::<u32>() * 3 * vlen as usize;
                    BtfTypeDetail::Ignored
                }
                BtfKind::Float => BtfTypeDetail::None,
                BtfKind::DeclTag => {
                    start += std::mem::size_of::<u32>();
                    BtfTypeDetail::Ignored
                }
                BtfKind::TypeTag => BtfTypeDetail::None,
                BtfKind::Enum64 => {
                    start += std::mem::size_of::<u32>() * 3 * vlen as usize;
                    BtfTypeDetail::Ignored
                }
            };

            types.push(BtfType {
                name_off,
                vlen,
                kind,
                kind_flag,
                size_or_type,
                detail,
            });
        }
        if start != end {
            bail!("Type section size mismatch");
        }
        Ok(types)
    } else {
        bail!("Type section out of bounds");
    }
}

pub fn parse_btf(data: &[u8], offset: usize) -> Result<(&BtfHeader, &[u8], Vec<BtfType>)> {
    let btf_header = parse_btf_header(data, offset)?;
    let offset = offset + btf_header.hdr_len as usize;
    let str_section = parse_btf_string_section(data, offset, btf_header)?;
    let type_section = parse_btf_type_section(data, offset, btf_header)?;
    Ok((btf_header, str_section, type_section))
}

fn parse_btf_ext_header(data: &[u8], offset: usize) -> Result<&BtfExtHeader> {
    let btf_ext_header = common::read_struct::<BtfExtHeader>(data, offset)
        .context("File too small for BTF ext header")?;
    if btf_ext_header.magic != 0xeb9f {
        bail!("Not a BTF ext section");
    }
    if btf_ext_header.hdr_len != size_of::<BtfExtHeader>() as u32 {
        bail!("Require core_relo part");
    }
    Ok(btf_ext_header)
}

fn parse_btf_ext_core_relo<'a>(
    data: &'a [u8],
    offset: usize,
    btf_ext_header: &'a BtfExtHeader,
) -> Result<Vec<BtfExtInfoSec<BpfCoreRelo>>> {
    let core_relo_offset = btf_ext_header.core_relo_off as usize;
    let core_relo_size = btf_ext_header.core_relo_len as usize;
    let mut start = core_relo_offset + offset;
    let end = start + core_relo_size;
    if end <= data.len() {
        let mut info_sections = Vec::new();
        // while start < end {
        // }
        let core_relo_rec_size = *common::read_struct::<u32>(data, start)
            .context("Failed to read core relo record size")?;
        if core_relo_rec_size != 16 {
            bail!("expected core relo record size to be 16")
        }
        start += 4;
        while start < end {
            let sec_name_off = *common::read_struct::<u32>(data, start)
                .context("Failed to read section name offset")?;
            let num_info = *common::read_struct::<u32>(data, start + 4)
                .context("Failed to read number of info")?;
            start += 8;
            let mut relocations = Vec::new();
            for _ in 0..num_info {
                let insn_off = *common::read_struct::<u32>(data, start)
                    .context("Failed to read instruction offset")?;
                let type_id = *common::read_struct::<u32>(data, start + 4)
                    .context("Failed to read type ID")?;
                let access_str_off = *common::read_struct::<u32>(data, start + 8)
                    .context("Failed to read access string offset")?;
                let kind = *common::read_struct::<u32>(data, start + 12)
                    .context("Failed to read relocation kind")?;
                let kind =
                    BpfCoreReloKind::try_from(kind).context("Failed to parse relocation kind")?;
                relocations.push(BpfCoreRelo {
                    insn_off,
                    type_id,
                    access_str_off,
                    kind,
                });
                start += 16;
            }
            info_sections.push(BtfExtInfoSec {
                sec_name_off,
                data: relocations,
            });
        }
        if start != end {
            bail!("Core relocation section size mismatch");
        }
        Ok(info_sections)
    } else {
        bail!("Core relocation section out of bounds");
    }
}

pub fn parse_btf_ext(
    data: &[u8],
    offset: usize,
) -> Result<(&BtfExtHeader, Vec<BtfExtInfoSec<BpfCoreRelo>>)> {
    let btf_ext_header = parse_btf_ext_header(data, offset)?;
    let offset = offset + btf_ext_header.hdr_len as usize;
    let relocations = parse_btf_ext_core_relo(data, offset, btf_ext_header)?;
    Ok((btf_ext_header, relocations))
}
