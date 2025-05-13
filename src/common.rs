use anyhow::{bail, Context as _, Result};

pub fn read_struct<T>(data: &[u8], offset: usize) -> Option<&T> {
    if offset + size_of::<T>() > data.len() {
        return None;
    }
    unsafe {
        Some(
            data[offset..offset + size_of::<T>()]
                .as_ptr()
                .cast::<T>()
                .as_ref()
                .unwrap(),
        )
    }
}

pub fn get_name_from_string_section(string_encoding: &[u8], offset: usize) -> Result<&str> {
    let end = string_encoding[offset..]
        .iter()
        .position(|&c| c == 0)
        .map(|pos| offset + pos)
        .unwrap_or(string_encoding.len());
    Ok(std::str::from_utf8(&string_encoding[offset..end])?)
}
