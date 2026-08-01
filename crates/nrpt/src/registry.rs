//! The Windows registry half.
//!
//! This is the FIRST registry write anywhere in this product — everything
//! else in the tree is read-only `reg.exe query`. Two consequences shape
//! the code below.
//!
//! Every handle is closed on every path, including the error paths, because
//! this runs inside a long-lived service in the daemon's future use and a
//! leaked HKEY is a handle leak that only shows up after weeks of uptime.
//!
//! And every failure is DISTINGUISHED rather than collapsed into a bool.
//! `targeting/startup.rs:160` in the daemon ignores `reg.exe`'s exit status
//! entirely, so "the key is absent" and "the query failed" are the same
//! answer there. For a reconciler that decides whether to delete a rule,
//! collapsing those two is how you get "I could not read the registry, so I
//! assume there is no rule" — and the rule stays, pointing the machine at a
//! dead port.

use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, WIN32_ERROR,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_READ, KEY_WOW64_64KEY, KEY_WRITE,
    REG_DWORD, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW,
    RegDeleteKeyExW, RegEnumKeyExW, RegOpenKeyExW, RegSetValueExW,
};

use super::Error;

/// Guard so no early return can leak the handle.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // Nothing useful to do with a close failure.
            let _ = unsafe { RegCloseKey(self.0) };
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn map_err(rc: WIN32_ERROR, what: &str) -> Error {
    match rc {
        ERROR_FILE_NOT_FOUND => Error::NoPolicyContainer,
        ERROR_ACCESS_DENIED => Error::AccessDenied(what.to_string()),
        other => Error::Registry(format!("{what}: Win32 error {}", other.0)),
    }
}

/// Open a subkey of HKLM for reading.
///
/// KEY_WOW64_64KEY is explicit: this product ships 64-bit, but a 32-bit
/// build or a WOW64 host would otherwise be silently redirected to
/// `Wow6432Node`, where the DNS policy does not live — and the reconciler
/// would cheerfully report "no rule" on a machine that has one.
fn open_read(path: &str) -> Result<Key, Error> {
    let mut h = HKEY::default();
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(wide(path).as_ptr()),
            0,
            KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY,
            &mut h,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(map_err(rc, path));
    }
    Ok(Key(h))
}

pub fn subkey_exists(path: &str, guid: &str) -> Result<bool, Error> {
    let parent = open_read(path)?;
    let mut child = HKEY::default();
    let rc = unsafe {
        RegOpenKeyExW(
            parent.0,
            windows::core::PCWSTR(wide(guid).as_ptr()),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut child,
        )
    };
    match rc {
        ERROR_SUCCESS => {
            let _ = Key(child); // closed on drop
            Ok(true)
        }
        // The rule is genuinely absent — distinct from the CONTAINER being
        // absent, which open_read already reported.
        ERROR_FILE_NOT_FOUND => Ok(false),
        other => Err(map_err(other, &format!("{path}\\{guid}"))),
    }
}

pub fn delete_subkey(path: &str, guid: &str) -> Result<(), Error> {
    // Open the container for WRITE by way of the delete API: RegDeleteKeyExW
    // takes the parent handle and the child name, so the child name is the
    // only untrusted input — and it has already been validated as a GUID by
    // the caller. That is why this function is not public.
    let mut parent = HKEY::default();
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(wide(path).as_ptr()),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut parent,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(map_err(rc, path));
    }
    let parent = Key(parent);

    let rc = unsafe {
        RegDeleteKeyExW(
            parent.0,
            windows::core::PCWSTR(wide(guid).as_ptr()),
            KEY_WOW64_64KEY.0,
            0,
        )
    };
    match rc {
        ERROR_SUCCESS => Ok(()),
        // Already gone. Idempotent by design: the reconciler is reaching a
        // state, not performing an action.
        ERROR_FILE_NOT_FOUND => Ok(()),
        other => Err(map_err(other, &format!("delete {path}\\{guid}"))),
    }
}

pub fn list_subkeys(path: &str) -> Result<Vec<String>, Error> {
    let key = open_read(path)?;
    let mut out = Vec::new();
    let mut index = 0u32;
    loop {
        // Registry key names are capped at 255 chars; +1 for the NUL.
        let mut buf = [0u16; 256];
        let mut len = buf.len() as u32;
        let rc = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut len,
                None,
                windows::core::PWSTR::null(),
                None,
                None,
            )
        };
        match rc {
            ERROR_SUCCESS => {
                out.push(String::from_utf16_lossy(&buf[..len as usize]));
                index += 1;
            }
            ERROR_NO_MORE_ITEMS => break,
            other => return Err(map_err(other, &format!("enumerate {path}"))),
        }
        // A container with this many rules is not a thing; bail rather than
        // loop forever if the API ever stops advancing.
        if index > 4096 {
            return Err(Error::Registry(format!("{path}: implausible subkey count")));
        }
    }
    Ok(out)
}

/// Create (or open) the rule subkey and write its values in one shot.
///
/// ORDER MATTERS INSIDE HERE TOO. The values are written BEFORE the key is
/// considered complete by anything reading it, and the DNS Client only
/// consults the policy when it reloads — so a half-written rule cannot be
/// observed as a routing decision. What it CAN be observed as is a key with
/// our GUID, which is why the caller records the GUID first: the reconciler
/// must be able to name and delete even a rule that was interrupted
/// mid-write.
pub fn write_rule(
    path: &str,
    guid: &str,
    namespace: &str,
    servers: &str,
    config_options: u32,
    version: u32,
    comment: &str,
) -> Result<(), Error> {
    let mut parent = HKEY::default();
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(wide(path).as_ptr()),
            0,
            KEY_WRITE | KEY_WOW64_64KEY,
            &mut parent,
        )
    };
    // The container does not exist on a machine that has never had a rule.
    // Creating it is legitimate: it is a standard Windows key, and the DNS
    // Client tolerates its absence and its presence equally.
    let parent = if rc == ERROR_SUCCESS {
        Key(parent)
    } else if rc == ERROR_FILE_NOT_FOUND {
        Key(create_key(HKEY_LOCAL_MACHINE, path)?)
    } else {
        return Err(map_err(rc, path));
    };

    let child = Key(create_key(parent.0, guid)?);

    set_multi_sz(child.0, "Name", &[namespace])?;
    set_sz(child.0, "GenericDNSServers", servers)?;
    set_dword(child.0, "ConfigOptions", config_options)?;
    set_dword(child.0, "Version", version)?;
    if !comment.is_empty() {
        // Diagnostic only. NEVER an identity: matching on this string is
        // the check-then-act failure the crate docs refuse.
        set_sz(child.0, "Comment", comment)?;
    }
    Ok(())
}

fn create_key(parent: HKEY, name: &str) -> Result<HKEY, Error> {
    let mut h = HKEY::default();
    let rc = unsafe {
        RegCreateKeyExW(
            parent,
            windows::core::PCWSTR(wide(name).as_ptr()),
            0,
            windows::core::PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE | KEY_READ | KEY_WOW64_64KEY,
            None,
            &mut h,
            None,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(map_err(rc, name));
    }
    Ok(h)
}

fn set_sz(key: HKEY, name: &str, value: &str) -> Result<(), Error> {
    let data = wide(value);
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(data.as_ptr() as *const u8, std::mem::size_of_val(&data[..]))
    };
    let rc = unsafe {
        RegSetValueExW(
            key,
            windows::core::PCWSTR(wide(name).as_ptr()),
            0,
            REG_SZ,
            Some(bytes),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(map_err(rc, name));
    }
    Ok(())
}

/// REG_MULTI_SZ: each string NUL-terminated, the whole block terminated by
/// one more NUL. An empty list still needs the final terminator, and
/// getting that wrong yields a value Windows reads as garbage.
fn set_multi_sz(key: HKEY, name: &str, values: &[&str]) -> Result<(), Error> {
    let mut data: Vec<u16> = Vec::new();
    for v in values {
        data.extend(v.encode_utf16());
        data.push(0);
    }
    data.push(0);
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(data.as_ptr() as *const u8, std::mem::size_of_val(&data[..]))
    };
    let rc = unsafe {
        RegSetValueExW(
            key,
            windows::core::PCWSTR(wide(name).as_ptr()),
            0,
            REG_MULTI_SZ,
            Some(bytes),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(map_err(rc, name));
    }
    Ok(())
}

fn set_dword(key: HKEY, name: &str, value: u32) -> Result<(), Error> {
    let rc = unsafe {
        RegSetValueExW(
            key,
            windows::core::PCWSTR(wide(name).as_ptr()),
            0,
            REG_DWORD,
            Some(&value.to_ne_bytes()),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(map_err(rc, name));
    }
    Ok(())
}
