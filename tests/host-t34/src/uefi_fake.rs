//! A fake UEFI system table with a text console, so the console's firmware paths
//! (`uefi::system::with_stdout` / `with_stdin`) run on the host.
//!
//! The text output keeps a cursor (80x25) and logs, per thread, what was written, the
//! colours set, cursor moves, clears and cursor visibility. The text input delivers the
//! keys queued in `fake::State::uefi_keys`.

use std::cell::RefCell;
use std::sync::Once;

use uefi::proto::console::text::Key;
use uefi_raw::protocol::console::{InputKey, SimpleTextInputProtocol, SimpleTextOutputMode, SimpleTextOutputProtocol};
use uefi_raw::table::system::SystemTable;
use uefi_raw::{Boolean, Char16, Status};

/// What the firmware console was asked to do (this thread).
#[derive(Default, Debug, Clone)]
pub struct Screen {
    /// Text written (`\r\n` as written).
    pub text: String,
    /// Attributes set (`bg << 4 | fg`).
    pub attrs: Vec<usize>,
    /// Cursor moves `(col, row)`.
    pub moves: Vec<(usize, usize)>,
    /// Screen clears.
    pub clears: usize,
    /// Cursor visibility changes.
    pub cursor: Vec<bool>,
}

thread_local! {
    static SCREEN: RefCell<Screen> = RefCell::new(Screen::default());
}

/// The firmware console's log so far (cleared).
pub fn take() -> Screen {
    SCREEN.with(|s| std::mem::take(&mut *s.borrow_mut()))
}

static mut MODE: SimpleTextOutputMode =
    SimpleTextOutputMode { max_mode: 1, mode: 0, attribute: 0x0F, cursor_column: 0, cursor_row: 0, cursor_visible: Boolean::TRUE };

const COLS: i32 = 80;
const ROWS: i32 = 25;

unsafe extern "efiapi" fn reset_out(_this: *mut SimpleTextOutputProtocol, _ext: Boolean) -> Status {
    Status::SUCCESS
}

unsafe extern "efiapi" fn output_string(_this: *mut SimpleTextOutputProtocol, s: *const Char16) -> Status {
    let mut n = 0;
    let mut text = String::new();
    loop {
        let c = *s.add(n);
        if c == 0 {
            break;
        }
        text.push(char::from_u32(c as u32).unwrap_or('?'));
        n += 1;
    }
    let mode = &mut *core::ptr::addr_of_mut!(MODE);
    for c in text.chars() {
        match c {
            '\r' => mode.cursor_column = 0,
            '\n' => mode.cursor_row = (mode.cursor_row + 1).min(ROWS - 1),
            _ => {
                mode.cursor_column += 1;
                if mode.cursor_column >= COLS {
                    mode.cursor_column = 0;
                    mode.cursor_row = (mode.cursor_row + 1).min(ROWS - 1);
                }
            }
        }
    }
    SCREEN.with(|sc| sc.borrow_mut().text.push_str(&text));
    Status::SUCCESS
}

unsafe extern "efiapi" fn test_string(_this: *mut SimpleTextOutputProtocol, _s: *const Char16) -> Status {
    Status::SUCCESS
}

unsafe extern "efiapi" fn query_mode(_this: *const SimpleTextOutputProtocol, mode: usize, cols: *mut usize, rows: *mut usize) -> Status {
    if mode != 0 {
        return Status::UNSUPPORTED;
    }
    *cols = COLS as usize;
    *rows = ROWS as usize;
    Status::SUCCESS
}

unsafe extern "efiapi" fn set_mode(_this: *mut SimpleTextOutputProtocol, _mode: usize) -> Status {
    Status::SUCCESS
}

unsafe extern "efiapi" fn set_attribute(_this: *mut SimpleTextOutputProtocol, attr: usize) -> Status {
    (*core::ptr::addr_of_mut!(MODE)).attribute = attr as i32;
    SCREEN.with(|sc| sc.borrow_mut().attrs.push(attr));
    Status::SUCCESS
}

unsafe extern "efiapi" fn clear_screen(_this: *mut SimpleTextOutputProtocol) -> Status {
    let mode = &mut *core::ptr::addr_of_mut!(MODE);
    mode.cursor_column = 0;
    mode.cursor_row = 0;
    SCREEN.with(|sc| sc.borrow_mut().clears += 1);
    Status::SUCCESS
}

unsafe extern "efiapi" fn set_cursor_position(_this: *mut SimpleTextOutputProtocol, col: usize, row: usize) -> Status {
    if col >= COLS as usize || row >= ROWS as usize {
        return Status::UNSUPPORTED;
    }
    let mode = &mut *core::ptr::addr_of_mut!(MODE);
    mode.cursor_column = col as i32;
    mode.cursor_row = row as i32;
    SCREEN.with(|sc| sc.borrow_mut().moves.push((col, row)));
    Status::SUCCESS
}

unsafe extern "efiapi" fn enable_cursor(_this: *mut SimpleTextOutputProtocol, visible: Boolean) -> Status {
    SCREEN.with(|sc| sc.borrow_mut().cursor.push(bool::from(visible)));
    Status::SUCCESS
}

unsafe extern "efiapi" fn reset_in(_this: *mut SimpleTextInputProtocol, _ext: Boolean) -> Status {
    Status::SUCCESS
}

unsafe extern "efiapi" fn read_key_stroke(_this: *mut SimpleTextInputProtocol, key: *mut InputKey) -> Status {
    match crate::fake::with(|s| s.uefi_keys.pop_front()) {
        Some(Key::Printable(c)) => {
            *key = InputKey { scan_code: 0, unicode_char: u16::from(c) };
            Status::SUCCESS
        }
        Some(Key::Special(sc)) => {
            *key = InputKey { scan_code: sc.0, unicode_char: 0 };
            Status::SUCCESS
        }
        None => Status::NOT_READY,
    }
}

static mut OUT: SimpleTextOutputProtocol = SimpleTextOutputProtocol {
    reset: reset_out,
    output_string,
    test_string,
    query_mode,
    set_mode,
    set_attribute,
    clear_screen,
    set_cursor_position,
    enable_cursor,
    mode: core::ptr::null(),
};

static mut INPUT: SimpleTextInputProtocol =
    SimpleTextInputProtocol { reset: reset_in, read_key_stroke, wait_for_key: core::ptr::null_mut() };

/// Boot services: every entry answers `UNSUPPORTED` (so `uefi::boot` calls fail cleanly:
/// no GOP, no load options; `stall` returns at once).
static mut BOOT_SERVICES_DUMMY: [usize; 64] = [0; 64];

unsafe extern "efiapi" fn unsupported() -> Status {
    Status::UNSUPPORTED
}

static mut TABLE: Option<SystemTable> = None;

/// Installs the fake system table (once per test binary).
pub fn install() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        let mut st: SystemTable = core::mem::zeroed();
        OUT.mode = core::ptr::addr_of!(MODE);
        st.stdout = core::ptr::addr_of_mut!(OUT);
        st.stderr = core::ptr::addr_of_mut!(OUT);
        st.stdin = core::ptr::addr_of_mut!(INPUT);
        let bs = &mut *core::ptr::addr_of_mut!(BOOT_SERVICES_DUMMY);
        for slot in bs.iter_mut().skip(3) {
            *slot = unsupported as *const () as usize;
        }
        st.boot_services = bs.as_mut_ptr().cast();
        TABLE = Some(st);
        let p: *const SystemTable = (*core::ptr::addr_of!(TABLE)).as_ref().unwrap();
        uefi::table::set_system_table(p);
        static mut IMAGE: u64 = 0;
        uefi::boot::set_image_handle(uefi::Handle::from_ptr(core::ptr::addr_of_mut!(IMAGE).cast()).unwrap());
    });
}

/// Homes the cursor and clears this thread's log.
pub fn reset() {
    unsafe {
        let mode = &mut *core::ptr::addr_of_mut!(MODE);
        mode.cursor_column = 0;
        mode.cursor_row = 0;
        mode.attribute = 0x0F;
    }
    take();
}

/// Puts the firmware cursor at `(col, row)` without logging a move.
pub fn place_cursor(col: usize, row: usize) {
    unsafe {
        let mode = &mut *core::ptr::addr_of_mut!(MODE);
        mode.cursor_column = col as i32;
        mode.cursor_row = row as i32;
    }
}
