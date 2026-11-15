// VibePerf: one process, no browser engine, the software renderer.
#![windows_subsystem = "windows"]

use slint::ComponentHandle;

/// The real release-list fetcher (WinHTTP), the exe's alone: it is in no test build, not the
/// lib's, not the integration tests', not this exe's own unit tests', so no test can go online
/// (review RAB-2; tests/pe.rs checks this line).
#[cfg(not(test))]
mod net;

/// The window's Win32 handle, for `host::fit_to_work_area`.
fn hwnd_of(w: &slint::winit_030::winit::window::Window) -> Option<isize> {
    use slint::winit_030::winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match w.window_handle().ok()?.as_raw() {
        RawWindowHandle::Win32(h) => Some(h.hwnd.get()),
        _ => None,
    }
}

fn main() -> Result<(), slint::PlatformError> {
    // LINK-1, first of all: every DLL loaded from here on comes from System32, never from the
    // exe's own folder (the elevated firewall helper is this exe). The static imports are
    // covered by the link flag /DEPENDENTLOADFLAG:0x800 (build.rs).
    // SAFETY: a process-wide setting with a valid flag; nothing has been loaded by name yet.
    unsafe {
        use windows_sys::Win32::System::LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories};
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
    // No Windows "No Disk" box: a file call on an empty card reader or drive gets its error back
    // instead of a modal box (review fix-popup, RX1). tests/pe.rs checks this block comes next.
    // SAFETY: a process-wide setting with a valid flag, the bits already set kept.
    unsafe {
        use windows_sys::Win32::System::Diagnostics::Debug::{GetErrorMode, SEM_FAILCRITICALERRORS, SetErrorMode};
        SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS);
    }
    // The command line (lib.rs `command_line`): nothing, `--server`, one `<host>`, the firewall
    // helper's exact `--firewall <id> <pid>`, or files dropped on the exe (every argument a path
    // by its shape: the window, and a toast that they were left alone). Anything else ends the
    // process before any window, file or instance contact (exit code 2). args_os: an argument
    // that is not Unicode is never a host and never a panic (RH3-I4).
    let raw: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let Some(start) = vibeperf::command_line(&raw) else { std::process::exit(2) };
    let mut dropped = None;
    let args: Vec<String> = match start {
        // The elevated firewall helper: no window, one bounded job (src/helper.rs).
        vibeperf::Start::Firewall { id, pid } => std::process::exit(vibeperf::helper::run(&id, pid)),
        vibeperf::Start::Server => vec!["--server".into()],
        vibeperf::Start::Host(h) => vec![h],
        vibeperf::Start::Window => Vec::new(),
        vibeperf::Start::Dropped(note) => {
            dropped = Some(note);
            Vec::new()
        }
    };
    #[allow(unused_mut)]
    let mut paths = vibeperf::host::paths();
    #[allow(unused_mut)]
    let mut bind = vibeperf::controller::SERVER_BIND;
    // Live checks and measurements only: the app's folders in a place of the developer's choosing,
    // so nothing touches the real profile, and (VIBEPERF_DEV_BIND) a server on loopback only.
    // Never in a shipped build.
    #[cfg(feature = "dev-hooks")]
    {
        if let Some(home) = std::env::var_os("VIBEPERF_DEV_HOME").map(std::path::PathBuf::from) {
            paths = vibeperf::host::Paths { config: home.join("config"), local_data: home.join("local") };
        }
        if let Some(b) = std::env::var("VIBEPERF_DEV_BIND").ok().and_then(|b| b.parse().ok()) {
            bind = b;
        }
    }
    // The probe hands back the value it was asked about, and `main` goes on with that one only: the
    // old binding is gone (`dev_probe`, review RRF-2).
    #[cfg(feature = "dev-hooks")]
    let paths = dev_probe(paths);
    let prefs = vibeperf::prefs::Store::new(paths.config.join("prefs.json"));
    let ui = vibeperf::window(prefs.clone())?;
    // The one place that names the real release-list fetcher (tests/pe.rs checks it): every test
    // hands the controller a fake, so no test goes online. This exe's unit-test build has no
    // `net` and never runs `main`: it gets a stand-in that fetches nothing.
    #[cfg(not(test))]
    let fetch = std::sync::Arc::new(net::fetch_release_list);
    #[cfg(test)]
    let fetch = std::sync::Arc::new(|_: &str| vibeperf::check::Fetched::Failed("a test build has no fetcher".into()));
    let mut svc = vibeperf::controller::Services::system(&paths, fetch);
    svc.bind = bind;
    let app = vibeperf::controller::App::attach(&ui, prefs, svc);
    app.command_line(&args);
    if let Some(note) = dropped {
        app.toast(&note, vibeperf::ToastKind::Info);
    }
    // The window opens at its preferred size; on a small or highly scaled screen that runs past
    // the taskbar, so the first window event once it is on screen fits it into the monitor's work
    // area (X15A11Y-3), once (a minimized start waits for the restore, X15RFTP-4).
    let fitted = std::cell::Cell::new(false);
    {
        use slint::winit_030::{EventResult, WinitWindowAccessor};
        ui.window().on_winit_window_event(move |window, _| {
            if !fitted.get() && window.with_winit_window(hwnd_of).flatten().and_then(vibeperf::host::fit_to_work_area).is_some() {
                fitted.set(true);
            }
            EventResult::Propagate
        });
    }
    let ran = ui.run();
    app.finish(); // the server and its firewall rules, a test, the last prefs and history changes
    ran
}

/// Live checks only (review RRE-5, RRF-2): with VIBEPERF_DEV_PROBE set, `main` writes the
/// app's data folders, one a line on stdout, and ends (exit 0) right after the dev home, before
/// any of them is used and before any window. Else it hands back the value it was given,
/// unchanged, and `main` goes on with it (`let paths = dev_probe(paths);`), so the folders the
/// probe names are the ones `main` uses. tests/pe.rs asks this before it starts the exe for real
/// (`run_exe`): every folder must be inside the scratch dev home it gave, so an override that is
/// gone, compiled out or too late fails there, by what the exe does.
#[cfg(feature = "dev-hooks")]
fn dev_probe(paths: vibeperf::host::Paths) -> vibeperf::host::Paths {
    use std::io::Write;
    if std::env::var_os("VIBEPERF_DEV_PROBE").is_some() {
        let mut out = std::io::stdout().lock();
        for f in [&paths.config, &paths.local_data] {
            let _ = writeln!(out, "{}", f.display());
        }
        let _ = out.flush();
        std::process::exit(0);
    }
    paths
}
