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
