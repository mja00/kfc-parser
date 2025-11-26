/// Content wrapper header detection and stripping
/// 
/// Some content blobs are wrapped with a 03022307 header:
/// - Magic bytes at offset 0: 0x07230203 (little-endian "03022307")
/// - Secondary header at offset 8: 0x000e0000
/// - Tertiary header at offset 20: 0x00020011
/// - Raw content data starts at offset 24

const WRAPPER_MAGIC: u32 = 0x07230203;
const WRAPPER_SECONDARY: u32 = 0x000e0000;
const WRAPPER_TERTIARY: u32 = 0x00020011;
const WRAPPER_DATA_OFFSET: usize = 24;

/// Check if data has the 03022307 wrapper header
pub fn has_wrapper(data: &[u8]) -> bool {
    if data.len() < WRAPPER_DATA_OFFSET {
        return false;
    }
    
    let magic = u32::from_le_bytes(
        data[0..4].try_into().unwrap_or([0; 4])
    );
    
    if magic != WRAPPER_MAGIC {
        return false;
    }
    
    // Verify secondary header if present
    if data.len() >= 12 {
        let secondary = u32::from_le_bytes(
            data[8..12].try_into().unwrap_or([0; 4])
        );
        if secondary != WRAPPER_SECONDARY {
            return false;
        }
    }
    
    // Verify tertiary header if present
    if data.len() >= 24 {
        let tertiary = u32::from_le_bytes(
            data[20..24].try_into().unwrap_or([0; 4])
        );
        if tertiary != WRAPPER_TERTIARY {
            return false;
        }
    }
    
    true
}

/// Strip the 03022307 wrapper header if present, returning the raw content
pub fn strip_content_wrapper(data: &[u8]) -> &[u8] {
    if has_wrapper(data) {
        &data[WRAPPER_DATA_OFFSET..]
    } else {
        data
    }
}

/// Strip the wrapper and return owned data
pub fn strip_content_wrapper_owned(data: Vec<u8>) -> Vec<u8> {
    if has_wrapper(&data) {
        data.into_iter().skip(WRAPPER_DATA_OFFSET).collect()
    } else {
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_wrapper() {
        // Valid wrapper
        let mut wrapped = vec![0u8; 32];
        wrapped[0..4].copy_from_slice(&WRAPPER_MAGIC.to_le_bytes());
        wrapped[8..12].copy_from_slice(&WRAPPER_SECONDARY.to_le_bytes());
        wrapped[20..24].copy_from_slice(&WRAPPER_TERTIARY.to_le_bytes());
        assert!(has_wrapper(&wrapped));
        
        // No wrapper
        let raw = vec![0u8; 32];
        assert!(!has_wrapper(&raw));
        
        // Too short
        let short = vec![0u8; 10];
        assert!(!has_wrapper(&short));
    }

    #[test]
    fn test_strip_wrapper() {
        let mut wrapped = vec![0u8; 50];
        wrapped[0..4].copy_from_slice(&WRAPPER_MAGIC.to_le_bytes());
        wrapped[8..12].copy_from_slice(&WRAPPER_SECONDARY.to_le_bytes());
        wrapped[20..24].copy_from_slice(&WRAPPER_TERTIARY.to_le_bytes());
        wrapped[24..].fill(0xFF);
        
        let stripped = strip_content_wrapper(&wrapped);
        assert_eq!(stripped.len(), 26);
        assert!(stripped.iter().all(|&b| b == 0xFF));
        
        // No wrapper - should return original
        let raw = vec![0xAA; 20];
        let result = strip_content_wrapper(&raw);
        assert_eq!(result.len(), 20);
        assert_eq!(result, raw.as_slice());
    }
}




