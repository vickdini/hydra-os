//! vfs-server's change calls (wave 10, Group V1): the ACL rules against the kernel's
//! `compat/linux/acl.rs` behaviour (Linux's `posix_acl_create`, `posix_acl_chmod`,
//! `posix_acl_valid`), the times calls' arguments, the xattr namespace rules and which opens
//! vfs-server serves.

use hydra_hosttests_w10_v1::calls::acl::*;
use hydra_hosttests_w10_v1::calls::rules::*;

const UO: u16 = 0x01;
const U: u16 = 0x02;
const GO: u16 = 0x04;
const M: u16 = 0x10;
const O: u16 = 0x20;

fn acl(e: &[(u16, u16, u32)]) -> Vec<u8> {
    encode(e)
}

// ----------------------------------------------------------------------
// ACLs
// ----------------------------------------------------------------------

#[test]
fn parse_validates_like_linux() {
    let ok = acl(&[(UO, 6, 0), (U, 4, 1000), (GO, 4, 0), (M, 5, 0), (O, 0, 0)]);
    assert_eq!(parse(&ok).unwrap().len(), 5);
    // the minimal ACL (three entries)
    assert!(parse(&acl(&[(UO, 6, 0), (GO, 4, 0), (O, 4, 0)])).is_ok());
    // a named user without a mask
    assert_eq!(parse(&acl(&[(UO, 6, 0), (U, 4, 1000), (GO, 4, 0), (O, 0, 0)])), Err(-22));
    // named users out of order, twice the same
    assert_eq!(parse(&acl(&[(UO, 6, 0), (U, 4, 1001), (U, 4, 1000), (GO, 4, 0), (M, 7, 0), (O, 0, 0)])), Err(-22));
    assert_eq!(parse(&acl(&[(UO, 6, 0), (U, 4, 1000), (U, 4, 1000), (GO, 4, 0), (M, 7, 0), (O, 0, 0)])), Err(-22));
    // a permission beyond rwx
    assert_eq!(parse(&acl(&[(UO, 8, 0), (GO, 4, 0), (O, 4, 0)])), Err(-22));
    // a missing other entry; no entries; a broken length; another version
    assert_eq!(parse(&acl(&[(UO, 6, 0), (GO, 4, 0)])), Err(-22));
    assert_eq!(parse(&acl(&[])), Err(-22));
    assert_eq!(parse(&[2, 0, 0, 0, 1]), Err(-22));
    let mut v3 = ok.clone();
    v3[0] = 3;
    assert_eq!(parse(&v3), Err(-95));
    // encode is parse's inverse
    assert_eq!(encode(&parse(&ok).unwrap()), ok);
}

#[test]
fn mode_bits_take_the_mask_for_the_group() {
    let e = parse(&acl(&[(UO, 6, 0), (U, 4, 1000), (GO, 4, 0), (M, 5, 0), (O, 1, 0)])).unwrap();
    assert_eq!(mode_bits(&e), 0o651);
    let e = parse(&acl(&[(UO, 7, 0), (GO, 4, 0), (O, 0, 0)])).unwrap();
    assert_eq!(mode_bits(&e), 0o740);
}

#[test]
fn create_without_a_default_acl_applies_the_umask() {
    assert_eq!(create_mode(None, 0o666, 0o022, false), (0o644, Inherit::default()));
    // an unreadable default ACL counts as none
    assert_eq!(create_mode(Some(&[1, 2, 3]), 0o777, 0o077, true), (0o700, Inherit::default()));
}

#[test]
fn create_with_a_default_acl_ignores_the_umask() {
    let def = acl(&[(UO, 7, 0), (U, 5, 1000), (GO, 5, 0), (M, 7, 0), (O, 0, 0)]);
    // a file asked 0666: the mask limits the group bits; the access ACL is the default
    // limited by the mode
    let (mode, plan) = create_mode(Some(&def), 0o666, 0o077, false);
    assert_eq!(mode, 0o660);
    let access = parse(plan.access.as_ref().unwrap()).unwrap();
    assert_eq!(access, vec![(UO, 6, 0), (U, 5, 1000), (GO, 5, 0), (M, 6, 0), (O, 0, 0)]);
    assert!(plan.default.is_none(), "a file gets no default ACL");
    // a directory asked 0777 also gets the default ACL as its own
    let (mode, plan) = create_mode(Some(&def), 0o777, 0o077, true);
    assert_eq!(mode, 0o770);
    assert_eq!(plan.default.as_deref(), Some(&def[..]));
    // a default ACL equivalent to a mode: no access ACL, the mode alone
    let min = acl(&[(UO, 6, 0), (GO, 4, 0), (O, 4, 0)]);
    let (mode, plan) = create_mode(Some(&min), 0o666, 0o077, false);
    assert_eq!(mode, 0o644);
    assert!(plan.access.is_none());
    assert!(plan.labels.is_none());
    assert!(plan.is_empty());
}

#[test]
fn chmod_rewrites_owner_mask_and_other() {
    let a = acl(&[(UO, 6, 0), (U, 4, 1000), (GO, 4, 0), (M, 5, 0), (O, 1, 0)]);
    let new = on_chmod(&a, 0o600).unwrap();
    assert_eq!(parse(&new).unwrap(), vec![(UO, 6, 0), (U, 4, 1000), (GO, 4, 0), (M, 0, 0), (O, 0, 0)]);
    // without a mask the owning group takes the group bits
    let a = acl(&[(UO, 6, 0), (GO, 4, 0), (O, 4, 0)]);
    assert_eq!(parse(&on_chmod(&a, 0o751).unwrap()).unwrap(), vec![(UO, 7, 0), (GO, 5, 0), (O, 1, 0)]);
    // nothing changes: None; an unreadable ACL: None
    let a = acl(&[(UO, 6, 0), (GO, 4, 0), (O, 4, 0)]);
    assert_eq!(on_chmod(&a, 0o644), None);
    assert_eq!(on_chmod(&[0, 0], 0o644), None);
}

#[test]
fn setting_an_access_acl_sets_the_mode() {
    let a = acl(&[(UO, 6, 0), (U, 4, 1000), (GO, 4, 0), (M, 5, 0), (O, 0, 0)]);
    let (keep, mode) = set_access(&a, 0o102644, true).unwrap();
    assert_eq!(keep.as_deref(), Some(&a[..]));
    assert_eq!(mode, 0o2650);
    // set-group-ID goes for a non-member without CAP_FSETID
    let (_, mode) = set_access(&a, 0o102644, false).unwrap();
    assert_eq!(mode, 0o650);
    // three entries: equivalent to the mode, not kept
    let min = acl(&[(UO, 7, 0), (GO, 5, 0), (O, 4, 0)]);
    assert_eq!(set_access(&min, 0o100600, true).unwrap(), (None, 0o754));
    assert_eq!(set_access(&[1, 2, 3, 4], 0o644, true), Err(-95));
    assert_eq!(set_access(&[2, 0, 0], 0o644, true), Err(-22));
}

// ----------------------------------------------------------------------
// The times calls
// ----------------------------------------------------------------------

fn le(v: &[i64]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

#[test]
fn times_of_each_call() {
    let now = (1_700_000_000, 5);
    // NULL: both now, not explicit
    assert_eq!(utimes(280, None, now), Ok((Some(now), Some(now))));
    assert!(!times_explicit(280, None));
    assert!(!times_explicit(132, None));
    // utime: two seconds
    assert_eq!(utimes(132, Some(&le(&[10, 20])), now), Ok((Some((10, 0)), Some((20, 0)))));
    assert!(times_explicit(132, Some(&le(&[10, 20]))));
    // utimes / futimesat: microseconds to nanoseconds; out of range EINVAL
    assert_eq!(utimes(235, Some(&le(&[10, 3, 20, 999_999])), now), Ok((Some((10, 3000)), Some((20, 999_999_000)))));
    assert_eq!(utimes(261, Some(&le(&[10, 1_000_000, 20, 0])), now), Err(EINVAL));
    assert_eq!(utimes(235, Some(&le(&[10, -1, 20, 0])), now), Err(EINVAL));
    // utimensat: UTIME_NOW, UTIME_OMIT, nanoseconds checked
    assert_eq!(utimes(280, Some(&le(&[0, UTIME_OMIT, 0, UTIME_NOW])), now), Ok((None, Some(now))));
    assert!(!times_explicit(280, Some(&le(&[0, UTIME_OMIT, 0, UTIME_NOW]))));
    assert!(times_explicit(280, Some(&le(&[5, 6, 0, UTIME_NOW]))));
    assert_eq!(utimes(280, Some(&le(&[5, 6, 7, 8])), now), Ok((Some((5, 6)), Some((7, 8)))));
    assert_eq!(utimes(280, Some(&le(&[5, 1_000_000_000, 7, 8])), now), Err(EINVAL));
    assert_eq!(utimes(280, Some(&le(&[0, UTIME_OMIT, 0, UTIME_OMIT])), now), Ok((None, None)));
}

// ----------------------------------------------------------------------
// xattrs
// ----------------------------------------------------------------------

#[test]
fn xattr_namespaces() {
    assert_eq!(xattr_ns(b"user.a"), Ok(XattrNs::User));
    assert_eq!(xattr_ns(b"trusted.overlay.opaque"), Ok(XattrNs::Trusted));
    assert_eq!(xattr_ns(b"security.capability"), Ok(XattrNs::Security));
    assert_eq!(xattr_ns(b"security.hydra.labels"), Ok(XattrNs::Security));
    assert_eq!(xattr_ns(b"system.posix_acl_access"), Ok(XattrNs::Acl(false)));
    assert_eq!(xattr_ns(b"system.posix_acl_default"), Ok(XattrNs::Acl(true)));
    assert_eq!(xattr_ns(b"system.nfs4_acl"), Ok(XattrNs::System));
    assert_eq!(xattr_ns(b"user."), Err(EINVAL));
    assert_eq!(xattr_ns(b"other.x"), Err(EOPNOTSUPP));
    assert_eq!(xattr_ns(b""), Err(ERANGE));
    let long = [b'u'; 256];
    assert_eq!(xattr_ns(&long), Err(ERANGE));
}

#[test]
fn file_capabilities_are_checked() {
    let mut v2 = vec![0u8; 20];
    v2[..4].copy_from_slice(&0x0200_0001u32.to_le_bytes());
    assert!(fcaps_valid(&v2));
    let mut v3 = vec![0u8; 24];
    v3[..4].copy_from_slice(&0x0300_0000u32.to_le_bytes());
    assert!(fcaps_valid(&v3));
    // wrong length for the revision, unknown flag bits
    assert!(!fcaps_valid(&v2[..19]));
    v2[..4].copy_from_slice(&0x0200_0002u32.to_le_bytes());
    assert!(!fcaps_valid(&v2));
    assert!(!fcaps_valid(b"bad"));
}

#[test]
fn lists_hide_trusted_names_and_reads_fit_or_say_erange() {
    let names = b"user.a\0trusted.b\0security.c\0\0";
    assert_eq!(xattr_list_shown(names, true), b"user.a\0trusted.b\0security.c\0".to_vec());
    assert_eq!(xattr_list_shown(names, false), b"user.a\0security.c\0".to_vec());
    assert_eq!(xattr_fits(10, 0), Ok(10));
    assert_eq!(xattr_fits(10, 10), Ok(10));
    assert_eq!(xattr_fits(10, 9), Err(ERANGE));
    assert_eq!(xattr_fits(0, 4), Ok(0));
}

// ----------------------------------------------------------------------
// Opens
// ----------------------------------------------------------------------

#[test]
fn which_opens_are_served() {
    assert!(servable(O_CREAT | O_EXCL | O_WRONLY));
    assert!(servable(O_WRONLY | O_TRUNC));
    assert!(servable(O_PATH | O_NOFOLLOW));
    assert!(servable(O_TMPFILE_MASK | O_DIRECTORY | 2));
    assert!(!servable(O_TMPFILE_MASK | 2));
    assert!(!servable(O_TMPFILE_MASK | O_DIRECTORY | O_PATH));
    assert!(!servable(O_CREAT | O_DIRECTORY | O_WRONLY));
}

#[test]
fn labels_and_acl_names() {
    assert_eq!(ACCESS, b"system.posix_acl_access");
    assert_eq!(DEFAULT, b"system.posix_acl_default");
    assert_eq!(LABELS, b"security.hydra.labels");
}
