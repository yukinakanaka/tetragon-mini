pub fn offset_of<T>(field: fn(*const T) -> *const u8) -> usize {
    let base = core::ptr::null();
    let field_ptr = field(base);
    field_ptr as usize - base as usize
}
