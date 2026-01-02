//! Secure Memory Handling
//!
//! Protection for sensitive data in memory:
//! - Zeroization on drop
//! - Memory locking (mlock) where available
//! - Secure comparison to prevent timing attacks
//! - Protected string/buffer types

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::ptr;

/// Securely zero memory
///
/// Uses volatile write to prevent compiler optimization
pub fn zeroize_memory(data: &mut [u8]) {
    // Use volatile to prevent optimization
    for byte in data.iter_mut() {
        unsafe {
            ptr::write_volatile(byte, 0);
        }
    }
    // Memory barrier to ensure write completes
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Constant-time comparison to prevent timing attacks
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Secure buffer that zeros on drop
#[derive(Clone)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    /// Create new secure buffer
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    /// Create from existing data
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    /// Create from vec (takes ownership)
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Resize buffer (zeroizing old if shrinking)
    pub fn resize(&mut self, new_size: usize) {
        if new_size < self.data.len() {
            // Zero the part being removed
            zeroize_memory(&mut self.data[new_size..]);
        }
        self.data.resize(new_size, 0);
    }

    /// Clear and zero
    pub fn clear(&mut self) {
        zeroize_memory(&mut self.data);
        self.data.clear();
    }

    /// Expose as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Expose as mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Constant-time comparison
    pub fn secure_eq(&self, other: &[u8]) -> bool {
        secure_compare(&self.data, other)
    }

    /// Try to lock memory (prevent swapping)
    #[cfg(unix)]
    pub fn lock(&self) -> Result<(), std::io::Error> {
        use std::os::raw::c_void;
        let result = unsafe {
            libc::mlock(
                self.data.as_ptr() as *const c_void,
                self.data.len(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Try to lock memory (no-op on non-Unix)
    #[cfg(not(unix))]
    pub fn lock(&self) -> Result<(), std::io::Error> {
        Ok(())
    }

    /// Unlock memory
    #[cfg(unix)]
    pub fn unlock(&self) -> Result<(), std::io::Error> {
        use std::os::raw::c_void;
        let result = unsafe {
            libc::munlock(
                self.data.as_ptr() as *const c_void,
                self.data.len(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Unlock memory (no-op on non-Unix)
    #[cfg(not(unix))]
    pub fn unlock(&self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        zeroize_memory(&mut self.data);
    }
}

impl Deref for SecureBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't expose contents
        write!(f, "SecureBuffer([REDACTED; {} bytes])", self.data.len())
    }
}

impl AsRef<[u8]> for SecureBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for SecureBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

/// Secure string that zeros on drop
#[derive(Clone)]
pub struct SecureString {
    inner: SecureBuffer,
}

impl SecureString {
    /// Create new empty secure string
    pub fn new() -> Self {
        Self {
            inner: SecureBuffer::new(0),
        }
    }

    /// Create from string slice
    pub fn from_str(s: &str) -> Self {
        Self {
            inner: SecureBuffer::from_slice(s.as_bytes()),
        }
    }

    /// Create from String (consumes and zeros original)
    pub fn from_string(mut s: String) -> Self {
        let result = Self {
            inner: SecureBuffer::from_slice(s.as_bytes()),
        };
        // Zero original string
        unsafe {
            zeroize_memory(s.as_bytes_mut());
        }
        result
    }

    /// Get as string slice (may fail if not valid UTF-8)
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.inner)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Get length in bytes
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Constant-time comparison
    pub fn secure_eq(&self, other: &str) -> bool {
        self.inner.secure_eq(other.as_bytes())
    }

    /// Clear and zero
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

impl Default for SecureString {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureString([REDACTED; {} bytes])", self.inner.len())
    }
}

impl fmt::Display for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        SecureString::from_str(s)
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        SecureString::from_string(s)
    }
}

/// Guard that ensures memory is zeroed when scope exits
pub struct ZeroizeGuard<'a> {
    data: &'a mut [u8],
}

impl<'a> ZeroizeGuard<'a> {
    /// Create new guard
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }
}

impl<'a> Drop for ZeroizeGuard<'a> {
    fn drop(&mut self) {
        zeroize_memory(self.data);
    }
}

impl<'a> Deref for ZeroizeGuard<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl<'a> DerefMut for ZeroizeGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data
    }
}

/// Macro to create a scope where a variable will be zeroed on exit
#[macro_export]
macro_rules! with_secure {
    ($name:ident, $value:expr, $body:block) => {
        {
            let mut $name = $value;
            let _guard = $crate::resilience::memory::ZeroizeGuard::new(
                $name.as_mut_slice()
            );
            $body
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroize_memory() {
        let mut data = vec![1u8, 2, 3, 4, 5];
        zeroize_memory(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_compare() {
        assert!(secure_compare(b"hello", b"hello"));
        assert!(!secure_compare(b"hello", b"world"));
        assert!(!secure_compare(b"hello", b"hell"));
    }

    #[test]
    fn test_secure_buffer() {
        let mut buf = SecureBuffer::from_slice(b"secret");
        assert_eq!(buf.len(), 6);
        assert_eq!(&*buf, b"secret");

        buf.clear();
        assert!(buf.is_empty());
    }

    #[test]
    fn test_secure_buffer_debug() {
        let buf = SecureBuffer::from_slice(b"password");
        let debug = format!("{:?}", buf);
        assert!(!debug.contains("password"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_secure_string() {
        let s = SecureString::from_str("password123");
        assert_eq!(s.len(), 11);
        assert_eq!(s.as_str().unwrap(), "password123");
        assert!(s.secure_eq("password123"));
        assert!(!s.secure_eq("password"));
    }

    #[test]
    fn test_secure_string_display() {
        let s = SecureString::from_str("secret");
        let display = format!("{}", s);
        assert_eq!(display, "[REDACTED]");
        assert!(!display.contains("secret"));
    }

    #[test]
    fn test_zeroize_guard() {
        let mut data = vec![0xFFu8; 16];

        {
            let _guard = ZeroizeGuard::new(&mut data);
            // Guard will zero on drop
        }

        assert!(data.iter().all(|&b| b == 0));
    }
}
