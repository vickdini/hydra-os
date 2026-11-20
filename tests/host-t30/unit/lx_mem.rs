//! Tests of `src/lx/mem.rs`: memory objects, handles, kept objects, `SYS_LX_MEM`.

use super::*;

/// No handle tables, no kept objects.
pub(crate) fn reset() {
    TABLES.lock().clear();
    KEPT.lock().clear();
}
