pub fn bytes_to_u24(bytes: [u8; 3]) -> u32 {
    ((bytes[0] as u32) << 16) + ((bytes[1] as u32) << 8) + (bytes[2] as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_u24() {
        assert_eq!(bytes_to_u24([0, 0, 0]), 0);
        assert_eq!(bytes_to_u24([0, 0, 1]), 1);
        assert_eq!(bytes_to_u24([0, 1, 0]), u8::MAX as u32 + 1);
        assert_eq!(bytes_to_u24([1, 0, 0]), u16::MAX as u32 + 1);
        assert_eq!(bytes_to_u24([u8::MAX, u8::MAX, u8::MAX]), 16777215);
    }
}
