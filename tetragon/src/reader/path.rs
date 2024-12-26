use std::path::Path;

pub fn get_binary_absolute_path(binary: &str, cwd: &str) -> String {
    let binary_path = Path::new(binary);

    if binary_path.is_absolute() {
        binary.to_string()
    } else {
        Path::new(cwd)
            .join(binary_path)
            .to_str()
            .unwrap()
            .to_string()
    }
}
