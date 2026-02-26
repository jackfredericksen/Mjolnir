/// Calculate Shannon entropy of a byte slice (0.0 = uniform, 8.0 = max random)
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Calculate entropy for a sliding window across the data
pub fn windowed_entropy(data: &[u8], window_size: usize, step: usize) -> Vec<f64> {
    if data.len() < window_size {
        return vec![calculate_entropy(data)];
    }

    let mut results = Vec::new();
    let mut offset = 0;

    while offset + window_size <= data.len() {
        results.push(calculate_entropy(&data[offset..offset + window_size]));
        offset += step;
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy() {
        let data = vec![0u8; 1000];
        let entropy = calculate_entropy(&data);
        assert!(entropy < 0.001);
    }

    #[test]
    fn test_max_entropy() {
        // Uniform distribution of all 256 byte values
        let data: Vec<u8> = (0..=255).cycle().take(256 * 100).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.99);
    }

    #[test]
    fn test_empty() {
        assert_eq!(calculate_entropy(&[]), 0.0);
    }

    #[test]
    fn test_windowed() {
        let data = vec![0u8; 2000];
        let windows = windowed_entropy(&data, 256, 128);
        assert!(!windows.is_empty());
        for e in &windows {
            assert!(*e < 0.001);
        }
    }
}
