use uefi::proto::console::text::Color;

use crate::console::set_color;
use crate::fs::client::{normalize_path, ZfsClient};
use crate::shell::command::{parse_usize, Command};
use crate::shell::state::ShellState;

/// Output the first part of files (default 10 lines).
pub struct HeadCommand;

impl Command for HeadCommand {
    fn name(&self) -> &'static str {
        "head"
    }

    fn description(&self) -> &'static str {
        "Output the first part of files (options: -n <lines> or -<lines>)"
    }

    fn usage(&self) -> &'static str {
        "head [-n lines] <file...>"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let mut max_lines = 10usize;
        let mut target_files: [&str; 4] = [""; 4];
        let mut file_count = 0;

        let mut idx = 0;
        while idx < args.len() {
            let arg = args[idx];
            if arg == "-n" && idx + 1 < args.len() {
                idx += 1;
                if let Some(n) = parse_usize(args[idx]) {
                    max_lines = n;
                }
            } else if arg.starts_with('-') && arg.len() > 1 && arg[1..].chars().all(|c| c.is_ascii_digit()) {
                if let Some(n) = parse_usize(&arg[1..]) {
                    max_lines = n;
                }
            } else if file_count < target_files.len() {
                target_files[file_count] = arg;
                file_count += 1;
            }
            idx += 1;
        }

        if file_count == 0 {
            set_color(Color::LightRed, Color::Black);
            println!("head: missing file operand");
            return;
        }

        for i in 0..file_count {
            let file = target_files[i];
            let mut norm_buf = [0u8; 128];
            let path = normalize_path(state.cwd_str(), file, &mut norm_buf);

            let mut buf = [0u8; 4096];
            match ZfsClient::read_file_by_path(path, &mut buf) {
                Ok(bytes_read) => {
                    if file_count > 1 {
                        set_color(Color::Yellow, Color::Black);
                        println!("==> {} <==", file);
                    }
                    set_color(Color::White, Color::Black);

                    let text = core::str::from_utf8(&buf[..bytes_read]).unwrap_or("");
                    let mut lines_printed = 0;
                    for line in text.lines() {
                        if crate::console::check_interrupt() {
                            println!("^C");
                            state.last_status = 130;
                            return;
                        }
                        if lines_printed >= max_lines {
                            break;
                        }
                        println!("{}", line);
                        lines_printed += 1;
                    }
                }
                Err(e) => {
                    set_color(Color::LightRed, Color::Black);
                    println!("head: cannot open '{}': {}", file, e);
                }
            }
        }
    }
}

/// Output the last part of files (default 10 lines).
pub struct TailCommand;

impl Command for TailCommand {
    fn name(&self) -> &'static str {
        "tail"
    }

    fn description(&self) -> &'static str {
        "Output the last part of files (options: -n <lines> or -<lines>)"
    }

    fn usage(&self) -> &'static str {
        "tail [-n lines] <file...>"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let mut max_lines = 10usize;
        let mut target_files: [&str; 4] = [""; 4];
        let mut file_count = 0;

        let mut idx = 0;
        while idx < args.len() {
            let arg = args[idx];
            if arg == "-n" && idx + 1 < args.len() {
                idx += 1;
                if let Some(n) = parse_usize(args[idx]) {
                    max_lines = n;
                }
            } else if arg.starts_with('-') && arg.len() > 1 && arg[1..].chars().all(|c| c.is_ascii_digit()) {
                if let Some(n) = parse_usize(&arg[1..]) {
                    max_lines = n;
                }
            } else if file_count < target_files.len() {
                target_files[file_count] = arg;
                file_count += 1;
            }
            idx += 1;
        }

        if file_count == 0 {
            set_color(Color::LightRed, Color::Black);
            println!("tail: missing file operand");
            return;
        }

        for i in 0..file_count {
            let file = target_files[i];
            let mut norm_buf = [0u8; 128];
            let path = normalize_path(state.cwd_str(), file, &mut norm_buf);

            let mut buf = [0u8; 4096];
            match ZfsClient::read_file_by_path(path, &mut buf) {
                Ok(bytes_read) => {
                    if file_count > 1 {
                        set_color(Color::Yellow, Color::Black);
                        println!("==> {} <==", file);
                    }
                    set_color(Color::White, Color::Black);

                    let text = core::str::from_utf8(&buf[..bytes_read]).unwrap_or("");
                    let total_lines = text.lines().count();
                    let skip_lines = total_lines.saturating_sub(max_lines);

                    for line in text.lines().skip(skip_lines) {
                        if crate::console::check_interrupt() {
                            println!("^C");
                            state.last_status = 130;
                            return;
                        }
                        println!("{}", line);
                    }
                }
                Err(e) => {
                    set_color(Color::LightRed, Color::Black);
                    println!("tail: cannot open '{}': {}", file, e);
                }
            }
        }
    }
}

/// Print newline, word, and byte counts for each file.
pub struct WcCommand;

impl Command for WcCommand {
    fn name(&self) -> &'static str {
        "wc"
    }

    fn description(&self) -> &'static str {
        "Print newline, word, and byte counts for files (options: -l lines, -w words, -c bytes)"
    }

    fn usage(&self) -> &'static str {
        "wc [-l] [-w] [-c] <file...>"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let mut opt_l = false;
        let mut opt_w = false;
        let mut opt_c = false;
        let mut files: [&str; 4] = [""; 4];
        let mut file_count = 0;

        for &arg in args {
            if arg.starts_with('-') && arg.len() > 1 {
                for c in arg.chars().skip(1) {
                    match c {
                        'l' => opt_l = true,
                        'w' => opt_w = true,
                        'c' | 'm' => opt_c = true,
                        _ => {}
                    }
                }
            } else if file_count < files.len() {
                files[file_count] = arg;
                file_count += 1;
            }
        }

        // Default to all three if no option flag specified
        if !opt_l && !opt_w && !opt_c {
            opt_l = true;
            opt_w = true;
            opt_c = true;
        }

        if file_count == 0 {
            let mut input = alloc::vec::Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = crate::task::with_current_fds_mut(|fds| {
                    if let Some(desc) = fds.get_mut(0) {
                        desc.read(&mut chunk).unwrap_or(0)
                    } else {
                        0
                    }
                });
                if n == 0 {
                    break;
                }
                input.extend_from_slice(&chunk[..n]);
            }
            let text = core::str::from_utf8(&input).unwrap_or("");
            let lines = text.lines().count();
            let words = text.split_whitespace().count();
            let bytes_cnt = input.len();
            set_color(Color::White, Color::Black);
            print_wc_counts(opt_l, opt_w, opt_c, lines, words, bytes_cnt, "");
            return;
        }

        let mut total_lines = 0;
        let mut total_words = 0;
        let mut total_bytes = 0;

        for i in 0..file_count {
            let file = files[i];
            let mut norm_buf = [0u8; 128];
            let path = normalize_path(state.cwd_str(), file, &mut norm_buf);

            let mut buf = [0u8; 4096];
            match ZfsClient::read_file_by_path(path, &mut buf) {
                Ok(bytes_read) => {
                    let bytes = &buf[..bytes_read];
                    let text = core::str::from_utf8(bytes).unwrap_or("");

                    let lines = text.lines().count();
                    let words = text.split_whitespace().count();
                    let bytes_cnt = bytes_read;

                    total_lines += lines;
                    total_words += words;
                    total_bytes += bytes_cnt;

                    set_color(Color::White, Color::Black);
                    print_wc_counts(opt_l, opt_w, opt_c, lines, words, bytes_cnt, file);
                }
                Err(e) => {
                    set_color(Color::LightRed, Color::Black);
                    println!("wc: {}: {}", file, e);
                }
            }
        }

        if file_count > 1 {
            set_color(Color::Yellow, Color::Black);
            print_wc_counts(opt_l, opt_w, opt_c, total_lines, total_words, total_bytes, "total");
        }
    }
}

fn print_wc_counts(opt_l: bool, opt_w: bool, opt_c: bool, l: usize, w: usize, c: usize, name: &str) {
    if opt_l {
        print!("{:>7} ", l);
    }
    if opt_w {
        print!("{:>7} ", w);
    }
    if opt_c {
        print!("{:>7} ", c);
    }
    println!("{}", name);
}

/// Print lines matching a pattern.
pub struct GrepCommand;

impl Command for GrepCommand {
    fn name(&self) -> &'static str {
        "grep"
    }

    fn description(&self) -> &'static str {
        "Search for pattern in files (options: -i ignore case, -n line numbers, -v invert, -c count)"
    }

    fn usage(&self) -> &'static str {
        "grep [-i] [-n] [-v] [-c] <pattern> [file...]"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let mut ignore_case = false;
        let mut line_numbers = false;
        let mut invert = false;
        let mut count_only = false;
        let mut positional: [&str; 6] = [""; 6];
        let mut pos_count = 0;

        for &arg in args {
            if arg.starts_with('-') && arg.len() > 1 {
                for c in arg.chars().skip(1) {
                    match c {
                        'i' => ignore_case = true,
                        'n' => line_numbers = true,
                        'v' => invert = true,
                        'c' => count_only = true,
                        _ => {}
                    }
                }
            } else if pos_count < positional.len() {
                positional[pos_count] = arg;
                pos_count += 1;
            }
        }

        if pos_count < 1 {
            set_color(Color::LightRed, Color::Black);
            println!("grep: missing pattern operand");
            return;
        }

        let pattern = positional[0];

        if pos_count == 1 {
            let mut input = alloc::vec::Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = crate::task::with_current_fds_mut(|fds| {
                    if let Some(desc) = fds.get_mut(0) {
                        desc.read(&mut chunk).unwrap_or(0)
                    } else {
                        0
                    }
                });
                if n == 0 {
                    break;
                }
                input.extend_from_slice(&chunk[..n]);
            }

            let text = core::str::from_utf8(&input).unwrap_or("");
            let mut match_count = 0;
            for (line_idx, line) in text.lines().enumerate() {
                if crate::console::check_interrupt() {
                    println!("^C");
                    state.last_status = 130;
                    return;
                }
                let is_match = if ignore_case {
                    line_contains_case_insensitive(line, pattern)
                } else {
                    line.contains(pattern)
                };
                let selected = if invert { !is_match } else { is_match };
                if selected {
                    match_count += 1;
                    if !count_only {
                        if line_numbers {
                            set_color(Color::LightGreen, Color::Black);
                            print!("{}:", line_idx + 1);
                        }
                        set_color(Color::White, Color::Black);
                        println!("{}", line);
                    }
                }
            }
            if count_only {
                set_color(Color::White, Color::Black);
                println!("{}", match_count);
            }
            state.last_status = if match_count > 0 { 0 } else { 1 };
            return;
        }

        let file_args = &positional[1..pos_count];

        for &file in file_args {
            let mut norm_buf = [0u8; 128];
            let path = normalize_path(state.cwd_str(), file, &mut norm_buf);

            let mut buf = [0u8; 4096];
            match ZfsClient::read_file_by_path(path, &mut buf) {
                Ok(bytes_read) => {
                    let text = core::str::from_utf8(&buf[..bytes_read]).unwrap_or("");
                    let mut match_count = 0;

                    for (line_idx, line) in text.lines().enumerate() {
                        if crate::console::check_interrupt() {
                            println!("^C");
                            state.last_status = 130;
                            return;
                        }
                        let is_match = if ignore_case {
                            line_contains_case_insensitive(line, pattern)
                        } else {
                            line.contains(pattern)
                        };

                        let selected = if invert { !is_match } else { is_match };

                        if selected {
                            match_count += 1;
                            if !count_only {
                                if file_args.len() > 1 {
                                    set_color(Color::LightCyan, Color::Black);
                                    print!("{}:", file);
                                }
                                if line_numbers {
                                    set_color(Color::LightGreen, Color::Black);
                                    print!("{}:", line_idx + 1);
                                }
                                set_color(Color::White, Color::Black);
                                println!("{}", line);
                            }
                        }
                    }

                    if count_only {
                        set_color(Color::White, Color::Black);
                        if file_args.len() > 1 {
                            println!("{}:{}", file, match_count);
                        } else {
                            println!("{}", match_count);
                        }
                    }
                }
                Err(e) => {
                    set_color(Color::LightRed, Color::Black);
                    println!("grep: {}: {}", file, e);
                }
            }
        }
    }
}

fn line_contains_case_insensitive(line: &str, pattern: &str) -> bool {
    let line_b = line.as_bytes();
    let pat_b = pattern.as_bytes();
    if pat_b.is_empty() { return true; }
    if pat_b.len() > line_b.len() { return false; }

    for i in 0..=(line_b.len() - pat_b.len()) {
        let mut matches = true;
        for j in 0..pat_b.len() {
            let lc = line_b[i + j].to_ascii_lowercase();
            let pc = pat_b[j].to_ascii_lowercase();
            if lc != pc {
                matches = false;
                break;
            }
        }
        if matches {
            return true;
        }
    }
    false
}

/// Strip directory and suffix from filenames.
pub struct BasenameCommand;

impl Command for BasenameCommand {
    fn name(&self) -> &'static str {
        "basename"
    }

    fn description(&self) -> &'static str {
        "Strip directory and suffix from filenames"
    }

    fn usage(&self) -> &'static str {
        "basename <path> [suffix]"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let raw = args[0].trim_end_matches(['/', '\\']);
        let filename = raw.rsplit(['/', '\\']).next().unwrap_or(raw);

        let result = if args.len() > 1 {
            let suffix = args[1];
            filename.strip_suffix(suffix).unwrap_or(filename)
        } else {
            filename
        };

        set_color(Color::White, Color::Black);
        println!("{}", result);
    }
}

/// Strip last component from filename.
pub struct DirnameCommand;

impl Command for DirnameCommand {
    fn name(&self) -> &'static str {
        "dirname"
    }

    fn description(&self) -> &'static str {
        "Strip last component from filename"
    }

    fn usage(&self) -> &'static str {
        "dirname <path>"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let raw = args[0].trim_end_matches(['/', '\\']);
        let result = match raw.rfind(['/', '\\']) {
            Some(0) => "/",
            Some(idx) => &raw[..idx],
            None => ".",
        };

        set_color(Color::White, Color::Black);
        println!("{}", result);
    }
}

/// Paginate file output with full interactive scrolling.
pub struct MoreCommand;

impl Command for MoreCommand {
    fn name(&self) -> &'static str {
        "more"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["less", "page"]
    }

    fn description(&self) -> &'static str {
        "Paginate file contents with interactive scrolling (Up/Down, PgUp/PgDn, q: quit)"
    }

    fn usage(&self) -> &'static str {
        "more <file>"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let file = args[0];
        let mut norm_buf = [0u8; 128];
        let path = normalize_path(state.cwd_str(), file, &mut norm_buf);

        let mut buf = [0u8; 8192];
        match ZfsClient::read_file_by_path(path, &mut buf) {
            Ok(bytes_read) => {
                if let Ok(text) = core::str::from_utf8(&buf[..bytes_read]) {
                    crate::shell::pager::paginate_text(file, text);
                } else {
                    set_color(Color::Yellow, Color::Black);
                    println!("{}: binary file ({} bytes)", file, bytes_read);
                }
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("more: cannot open '{}': {}", file, e);
            }
        }
    }
}

