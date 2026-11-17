//! Text tools (no kernel help needed beyond reading files): echo, head, tail, wc, grep,
//! more, basename, dirname, seq, yes, true, false, sleep.

use alloc::string::String;
use alloc::vec::Vec;

use crate::proto::*;
use crate::sys::*;
use crate::{normalize_path, usage, Shell};
use hydra_rt::{print, println};

/// The inputs of a text command: `(name, contents)` of each file operand, or the pipeline's
/// input when there is none. Prints errors as `<cmd>: <file>: <error>`.
fn inputs(sh: &mut Shell, cmd: &str, files: &[&str]) -> Vec<(String, Vec<u8>)> {
    if files.is_empty() {
        return match sh.take_stdin() {
            Some(d) => alloc::vec![(String::from("-"), d)],
            None => {
                color(LIGHT_RED);
                println!("{}: missing file operand", cmd);
                Vec::new()
            }
        };
    }
    let mut out = Vec::new();
    for &f in files {
        match read_file(&normalize_path(&sh.cwd, f), 16 << 20) {
            Ok(d) => out.push((String::from(f), d)),
            Err(e) => {
                color(LIGHT_RED);
                println!("{}: cannot open '{}': {}", cmd, f, e);
                sh.status = 1;
            }
        }
    }
    out
}

/// `-n N` / `-N` and the file operands.
fn count_and_files<'a>(args: &[&'a str], default: usize) -> (usize, Vec<&'a str>) {
    let mut n = default;
    let mut files = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a == "-n" {
            n = args.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(default);
            i += 1;
        } else if let Some(v) = a.strip_prefix("-n").or_else(|| a.strip_prefix('-')).filter(|v| !v.is_empty()) {
            n = v.parse().unwrap_or(default);
        } else {
            files.push(a);
        }
        i += 1;
    }
    (n, files)
}

pub fn echo(_sh: &mut Shell, args: &[&str]) {
    println!("{}", args.join(" "));
}

/// `head` and `tail`.
fn head_tail(sh: &mut Shell, args: &[&str], cmd: &str, tail: bool) {
    let (n, files) = count_and_files(args, 10);
    let all = inputs(sh, cmd, &files);
    let many = all.len() > 1;
    color(WHITE);
    for (name, data) in all {
        if many {
            println!("==> {} <==", name);
        }
        let text = String::from_utf8_lossy(&data);
        let lines: Vec<&str> = text.lines().collect();
        let part = if tail { &lines[lines.len().saturating_sub(n)..] } else { &lines[..n.min(lines.len())] };
        for l in part {
            if interrupted() {
                println!("^C");
                return;
            }
            println!("{}", l);
        }
    }
}

pub fn head(sh: &mut Shell, args: &[&str]) {
    head_tail(sh, args, "head", false)
}

pub fn tail(sh: &mut Shell, args: &[&str]) {
    head_tail(sh, args, "tail", true)
}

pub fn wc(sh: &mut Shell, args: &[&str]) {
    let flags: String = args.iter().filter(|a| a.starts_with('-')).flat_map(|a| a.chars().skip(1)).collect();
    let files: Vec<&str> = args.iter().copied().filter(|a| !a.starts_with('-')).collect();
    let (mut l, mut w, mut c) = (flags.contains('l'), flags.contains('w'), flags.contains('c'));
    if !(l || w || c) {
        (l, w, c) = (true, true, true);
    }
    let show = |lines: usize, words: usize, bytes: usize, name: &str| {
        if l {
            print!("{:>7} ", lines);
        }
        if w {
            print!("{:>7} ", words);
        }
        if c {
            print!("{:>7} ", bytes);
        }
        println!("{}", name);
    };
    let all = inputs(sh, "wc", &files);
    let many = all.len() > 1;
    let (mut tl, mut tw, mut tc) = (0, 0, 0);
    for (name, data) in all {
        let text = String::from_utf8_lossy(&data);
        let (lines, words) = (text.lines().count(), text.split_whitespace().count());
        tl += lines;
        tw += words;
        tc += data.len();
        color(WHITE);
        show(lines, words, data.len(), if name == "-" { "" } else { &name });
    }
    if many {
        color(YELLOW);
        show(tl, tw, tc, "total");
    }
}

pub fn grep(sh: &mut Shell, args: &[&str]) {
    let flags: String = args.iter().filter(|a| a.starts_with('-') && a.len() > 1).flat_map(|a| a.chars().skip(1)).collect();
    let ops: Vec<&str> = args.iter().copied().filter(|a| !(a.starts_with('-') && a.len() > 1)).collect();
    let Some((&pattern, files)) = ops.split_first() else {
        color(LIGHT_RED);
        println!("grep: missing pattern operand");
        return;
    };
    let (icase, number, invert, count) = (flags.contains('i'), flags.contains('n'), flags.contains('v'), flags.contains('c'));
    let pat = if icase { pattern.to_lowercase() } else { String::from(pattern) };
    let all = inputs(sh, "grep", files);
    let many = all.len() > 1;
    let mut found = false;
    for (name, data) in all {
        let text = String::from_utf8_lossy(&data);
        let mut matches = 0;
        for (i, line) in text.lines().enumerate() {
            let hit = if icase { line.to_lowercase().contains(&pat) } else { line.contains(&pat) };
            if hit == invert {
                continue;
            }
            matches += 1;
            if count {
                continue;
            }
            if interrupted() {
                println!("^C");
                return;
            }
            color(WHITE);
            let mut prefix = String::new();
            if many {
                prefix.push_str(&name);
                prefix.push(':');
            }
            if number {
                prefix.push_str(&alloc::format!("{}:", i + 1));
            }
            println!("{}{}", prefix, line);
        }
        found |= matches > 0;
        if count {
            if many {
                println!("{}:{}", name, matches);
            } else {
                println!("{}", matches);
            }
        }
    }
    sh.status = if found { 0 } else { 1 };
}

/// `more`: a page at a time (Space: next page, Enter/Down: next line, q/Esc/Ctrl+C: quit).
pub fn more(sh: &mut Shell, args: &[&str]) {
    let Some(&file) = args.first() else { return usage("more <file>") };
    let data = match read_file(&normalize_path(&sh.cwd, file), 16 << 20) {
        Ok(d) => d,
        Err(e) => {
            color(LIGHT_RED);
            println!("more: cannot open '{}': {}", file, e);
            return;
        }
    };
    let Ok(text) = core::str::from_utf8(&data) else {
        color(YELLOW);
        println!("{}: binary file ({} bytes)", file, data.len());
        return;
    };
    let rows = (ctl(CTL_SIZE, 0, 0, 0, &[])[1] as usize).max(3);
    let lines: Vec<&str> = text.lines().collect();
    let mut shown = 0;
    let mut page = rows - 1;
    color(WHITE);
    while shown < lines.len() {
        let end = (shown + page).min(lines.len());
        for l in &lines[shown..end] {
            println!("{}", l);
        }
        shown = end;
        if shown >= lines.len() || crate::redirected() {
            continue;
        }
        color(YELLOW);
        print!("-- More ({}%) --", shown * 100 / lines.len());
        color(WHITE);
        let k = read_key(u64::MAX, u64::MAX);
        print!("\r                    \r");
        match (k.kind, k.code) {
            (KEY_CHAR, 32) | (KEY_SPECIAL, SC_PAGE_DOWN) => page = rows - 1,
            (KEY_CHAR, 13) | (KEY_CHAR, 10) | (KEY_SPECIAL, SC_DOWN) => page = 1,
            _ => break,
        }
    }
}

pub fn basename(_sh: &mut Shell, args: &[&str]) {
    let Some(&p) = args.first() else { return usage("basename <path> [suffix]") };
    let raw = p.trim_end_matches(['/', '\\']);
    let file = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let result = args.get(1).and_then(|s| file.strip_suffix(*s)).unwrap_or(file);
    color(WHITE);
    println!("{}", result);
}

pub fn dirname(_sh: &mut Shell, args: &[&str]) {
    let Some(&p) = args.first() else { return usage("dirname <path>") };
    let raw = p.trim_end_matches(['/', '\\']);
    let result = match raw.rfind(['/', '\\']) {
        Some(0) => "/",
        Some(i) => &raw[..i],
        None => ".",
    };
    color(WHITE);
    println!("{}", result);
}

pub fn seq(_sh: &mut Shell, args: &[&str]) {
    let nums: Vec<i64> = args.iter().filter_map(|a| a.parse().ok()).collect();
    let (first, step, last) = match nums.as_slice() {
        [l] => (1, 1, *l),
        [f, l] => (*f, 1, *l),
        [f, s, l, ..] => (*f, *s, *l),
        _ => return usage("seq [FIRST [INCREMENT]] LAST"),
    };
    if step == 0 {
        return;
    }
    let mut cur = first;
    color(WHITE);
    while (step > 0 && cur <= last) || (step < 0 && cur >= last) {
        println!("{}", cur);
        cur += step;
        if interrupted() {
            println!("^C");
            return;
        }
    }
}

pub fn yes(_sh: &mut Shell, args: &[&str]) {
    let msg = if args.is_empty() { String::from("y") } else { args.join(" ") };
    // Into a pipe: one pipe's worth, not forever
    let limit = if crate::redirected() { 4096 } else { usize::MAX };
    for _ in 0..limit {
        println!("{}", msg);
        if interrupted() {
            println!("^C");
            return;
        }
    }
}

pub fn true_cmd(sh: &mut Shell, _args: &[&str]) {
    sh.status = 0;
}

pub fn false_cmd(sh: &mut Shell, _args: &[&str]) {
    sh.status = 1;
}

pub fn sleep(sh: &mut Shell, args: &[&str]) {
    let Some(&a) = args.first() else { return usage("sleep <seconds>") };
    let secs: u64 = match a.trim_end_matches('s').parse() {
        Ok(s) => s,
        Err(_) => {
            color(LIGHT_RED);
            println!("sleep: invalid time interval '{}'", a);
            sh.status = 1;
            return;
        }
    };
    // Waiting for keys, so that Ctrl+C stops it (other keys are dropped)
    for _ in 0..secs * 10 {
        let k = read_key(100, u64::MAX);
        if k.kind == KEY_CHAR && (k.code == 3 || k.code == 28) {
            println!("^C");
            sh.status = 130;
            return;
        }
    }
}
