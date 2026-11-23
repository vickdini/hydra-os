//! vfs-server's Landlock rules on a domain copy, against the kernel's
//! (`src/compat/linux/landlock.rs`).

use hydra_hosttests_w9_6b3::ll::*;

/// A domain in `LX_FH_LANDLOCK`'s format: `(fs, rules)` per layer.
fn wire(id: u64, layers: &[(u64, &[(u64, u64)])]) -> Vec<u8> {
    let mut v = Vec::new();
    let mut put = |x: u64| v.extend_from_slice(&x.to_le_bytes());
    put(id);
    put(layers.len() as u64);
    for (fs, rules) in layers {
        put(*fs);
        put(rules.len() as u64);
        for (i, r) in rules.iter() {
            put(*i);
            put(*r);
        }
    }
    v
}

fn dom(layers: &[(u64, &[(u64, u64)])]) -> Domain {
    parse(&wire(7, layers)).expect("parses")
}

const ALL: u64 = (1 << 15) - 1;

#[test]
fn parse_round_trip_sorts_and_merges() {
    let d = parse(&wire(42, &[(READ_FILE | WRITE_FILE, &[(30, READ_FILE), (10, WRITE_FILE), (30, WRITE_FILE)])])).unwrap();
    assert_eq!(d.id, 42);
    assert_eq!(d.layers.len(), 1);
    assert_eq!(d.layers[0].fs, READ_FILE | WRITE_FILE);
    assert_eq!(d.layers[0].rules, vec![(10, WRITE_FILE), (30, READ_FILE | WRITE_FILE)]);
}

#[test]
fn parse_rejects_malformed() {
    assert!(parse(&[]).is_none());
    let mut w = wire(1, &[(READ_FILE, &[(5, READ_FILE)])]);
    w.pop();
    assert!(parse(&w).is_none(), "short");
    let mut w = wire(1, &[(READ_FILE, &[])]);
    w.push(0);
    assert!(parse(&w).is_none(), "trailing bytes");
    let mut w = Vec::new();
    w.extend_from_slice(&1u64.to_le_bytes());
    w.extend_from_slice(&17u64.to_le_bytes());
    assert!(parse(&w).is_none(), "too many layers");
    let mut w = Vec::new();
    for x in [1u64, 1, READ_FILE, 1 << 20] {
        w.extend_from_slice(&x.to_le_bytes());
    }
    assert!(parse(&w).is_none(), "too many rules");
    assert_eq!(parse(&wire(3, &[])).unwrap().layers.len(), 0);
}

#[test]
fn refused_by_chain_and_layers() {
    // chain: file 100 in dir 20 under 10 (root 1)
    let chain = [100, 20, 10, 1];
    let d = dom(&[(READ_FILE | WRITE_FILE, &[(10, READ_FILE)])]);
    assert_eq!(refused(&d, &chain, READ_FILE), 0, "granted on an ancestor");
    assert_eq!(refused(&d, &chain, WRITE_FILE), WRITE_FILE);
    assert_eq!(refused(&d, &chain, EXECUTE), 0, "unhandled right");
    assert_eq!(refused(&d, &[200, 1], READ_FILE), READ_FILE, "outside the rule");
    // A second layer restricts further; both must grant
    let d2 = dom(&[(READ_FILE, &[(10, READ_FILE)]), (READ_FILE, &[(30, READ_FILE)])]);
    assert_eq!(refused(&d2, &chain, READ_FILE), READ_FILE);
    let d3 = dom(&[(READ_FILE, &[(10, READ_FILE)]), (READ_FILE, &[(100, READ_FILE)])]);
    assert_eq!(refused(&d3, &chain, READ_FILE), 0);
    assert_eq!(refused(&dom(&[]), &chain, ALL), 0, "no layers");
}

#[test]
fn rights_of_types_and_opens() {
    assert_eq!(make_right(0o040000), MAKE_DIR);
    assert_eq!(make_right(0o120000), MAKE_SYM);
    assert_eq!(make_right(0o140000), MAKE_SOCK);
    assert_eq!(make_right(0o010000), MAKE_FIFO);
    assert_eq!(make_right(0o020000), MAKE_CHAR);
    assert_eq!(make_right(0o060000), MAKE_BLOCK);
    assert_eq!(make_right(0o100000), MAKE_REG);
    assert_eq!(remove_right(0o040000), REMOVE_DIR);
    assert_eq!(remove_right(0o100000), REMOVE_FILE);
    assert_eq!(open_rights(0, true), READ_DIR);
    assert_eq!(open_rights(0, false), READ_FILE);
    assert_eq!(open_rights(1, false), WRITE_FILE);
    assert_eq!(open_rights(2, false), READ_FILE | WRITE_FILE);
    assert_eq!(open_rights(0o1000, false), READ_FILE | TRUNCATE);
    assert_eq!(open_rights(0o1001, false), WRITE_FILE | TRUNCATE);
}

#[test]
fn moves_and_refer() {
    let (s, t) = ([20u64, 10, 1], [30u64, 10, 1]);
    // Everything granted under 10, REFER too: a move is fine
    let d = dom(&[(ALL, &[(10, ALL)])]);
    assert_eq!(check_move(&d, &s, &t, false, 0o100000, true, 0), Ok(()));
    // No REFER handled (ABI 1): never across directories, fine within one
    let d1 = dom(&[(ALL & !REFER, &[(10, ALL & !REFER)])]);
    assert_eq!(check_move(&d1, &s, &t, false, 0o100000, true, 0), Err(EXDEV));
    assert_eq!(check_move(&d1, &s, &s, true, 0o100000, true, 0), Ok(()));
    // REFER on the source only
    let d2 = dom(&[(ALL, &[(20, ALL), (30, ALL & !REFER)])]);
    assert_eq!(check_move(&d2, &s, &t, false, 0o100000, true, 0), Err(EXDEV));
    // The new place may not add rights
    let d3 = dom(&[(ALL, &[(20, REFER | REMOVE_FILE | MAKE_REG), (30, REFER | MAKE_REG | READ_FILE)])]);
    assert_eq!(check_move(&d3, &s, &t, false, 0o100000, true, 0), Err(EXDEV));
    let d4 = dom(&[(ALL, &[(20, REFER | REMOVE_FILE | MAKE_REG | READ_FILE), (30, REFER | MAKE_REG | READ_FILE)])]);
    assert_eq!(check_move(&d4, &s, &t, false, 0o100000, true, 0), Ok(()));
    // Removing at the source, making at the target, replacing an entry
    let d5 = dom(&[(ALL, &[(10, ALL & !REMOVE_FILE)])]);
    assert_eq!(check_move(&d5, &s, &t, false, 0o100000, true, 0), Err(EACCES));
    assert_eq!(check_move(&d5, &s, &t, false, 0o100000, false, 0), Ok(()), "a link removes nothing");
    let d6 = dom(&[(ALL, &[(10, ALL & !MAKE_DIR)])]);
    assert_eq!(check_move(&d6, &s, &t, false, 0o040000, true, 0), Err(EACCES));
    assert_eq!(check_move(&d5, &[20, 10], &[20, 10], true, 0o040000, true, REMOVE_FILE), Err(EACCES), "replacing a file needs REMOVE_FILE");
    // Unhandled layer (fs 0) does not refuse
    let d7 = dom(&[(0, &[]), (ALL, &[(10, ALL)])]);
    assert_eq!(check_move(&d7, &s, &t, false, 0o100000, true, 0), Ok(()));
}
