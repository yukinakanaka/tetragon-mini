pub fn args_decoder(s: &[u8], _flags: u32) -> (String, String) {
    let args = String::from_utf8(
        s.split(|&b| b == 0) // Split by null (`\0`) bytes
            .filter(|s| !s.is_empty()) // Remove empty slices
            .collect::<Vec<_>>() // Convert to `Vec<Vec<u8>>`
            .join(&b' '), // Join elements with a space (`b' '`)
    )
    .unwrap_or("Unknown".to_owned());
    (args, "foo".to_string())
}
