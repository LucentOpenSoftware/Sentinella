//! Path deduplication for scan targets.

use std::collections::HashSet;
use std::path::PathBuf;

/// Deduplicate and canonicalize scan target paths.
pub fn deduplicate(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for path in paths {
        // Canonicalize to resolve symlinks + case.
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        let key = canonical.to_string_lossy().to_lowercase();

        if seen.insert(key) {
            result.push(canonical);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_removes_duplicates() {
        let paths = vec![
            PathBuf::from("C:\\Windows\\System32"),
            PathBuf::from("C:\\WINDOWS\\SYSTEM32"),
            PathBuf::from("C:\\Windows\\System32"),
        ];
        let deduped = deduplicate(paths);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn dedup_preserves_unique() {
        let paths = vec![PathBuf::from("C:\\Windows"), PathBuf::from("C:\\Users")];
        let deduped = deduplicate(paths);
        assert_eq!(deduped.len(), 2);
    }
}
