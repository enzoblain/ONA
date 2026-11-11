//! ONA desktop app for Windows and Linux (Tauri): runs the agent (ona-core) on this computer and serves the phone.
//! Same protocol and behaviour as the macOS app (desktop/ONADesktop).

// No console window next to the app on Windows (release builds).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine;
mod http;
mod pairing;
mod protocol;
mod router;
mod server;
mod tor;
mod worker;

use serde_json::Value;
use tauri::{Manager, RunEvent, State};

use worker::{Mode, Worker};

type Reply = Result<Value, String>;

fn call(worker: &Worker, job: impl FnOnce(&mut worker::App) -> Reply + Send + 'static) -> Reply {
    worker.call(job).unwrap_or_else(|| Err("ONA s'est arrêté".into()))
}

#[tauri::command]
async fn state(worker: State<'_, Worker>) -> Reply {
    call(&worker, |app| Ok(app.view()))
}

#[tauri::command]
async fn chat(worker: State<'_, Worker>, id: String) -> Reply {
    call(&worker, move |app| Ok(app.engine.chat_json(&id).unwrap_or(Value::Null)))
}

#[tauri::command]
async fn create_chat(worker: State<'_, Worker>, text: String) -> Reply {
    call(&worker, move |app| app.engine.create(&text).map(Value::String).map_err(|e| e.code().into()))
}

#[tauri::command]
async fn post_message(worker: State<'_, Worker>, id: String, text: String) -> Reply {
    call(&worker, move |app| app.engine.post(&text, &id).map(|_| Value::Null).map_err(|e| e.code().into()))
}

#[tauri::command]
async fn delete_chat(worker: State<'_, Worker>, id: String) -> Reply {
    call(&worker, move |app| app.engine.delete(&id).map(|_| Value::Null).map_err(|e| e.code().into()))
}

/// A decision taken on this computer, on the same confirmation the phone sees.
#[tauri::command]
async fn confirm(worker: State<'_, Worker>, id: String, decision: String, firm: Option<String>, digest: Option<String>) -> Reply {
    call(&worker, move |app| {
        app.engine.confirm(Some(&id), Some(&decision), firm.as_deref(), digest.as_deref()).map(|_| Value::Null)
    })
}

/// The person saw the same 6-digit code on both screens.
#[tauri::command]
async fn confirm_code(worker: State<'_, Worker>) -> Reply {
    call(&worker, |app| app.pairing.confirm_code().map(|_| Value::Null))
}

/// The codes differ, or the person no longer trusts the phone: a new QR code is issued. An error means the change
/// could not be written: the window shows it (the phone would be trusted again after a restart).
#[tauri::command]
async fn forget_phone(worker: State<'_, Worker>) -> Reply {
    call(&worker, |app| app.pairing.forget_phone().map(|_| Value::Null))
}

#[tauri::command]
async fn set_mode(worker: State<'_, Worker>, mode: String) -> Reply {
    let mode = Mode::parse(&mode, worker::LOCAL_MODE_ALLOWED).ok_or("mode inconnu")?;
    call(&worker, move |app| app.set_mode(mode).map(|_| Value::Null))
}

/// The computer's name, shown on the phone after pairing.
fn computer_name() -> String {
    let from_env = std::env::var("COMPUTERNAME").ok();
    let from_file = || std::fs::read_to_string("/etc/hostname").ok();
    let from_command = || {
        std::process::Command::new("hostname").output().ok().and_then(|o| String::from_utf8(o.stdout).ok())
    };
    from_env.or_else(from_file).or_else(from_command)
        .map(|n| n.trim().to_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "Mon ordinateur".into())
}

/// Debug builds only: prints the pairing text on stdout (for the iOS simulator, which cannot scan a QR code) and,
/// with ONA_AUTO_CONFIRM_PAIRING=1, confirms the 6-digit code without a click.
#[cfg(debug_assertions)]
fn debug_hooks(worker: Worker) {
    let auto_confirm = std::env::var("ONA_AUTO_CONFIRM_PAIRING").as_deref() == Ok("1");
    std::thread::spawn(move || {
        let mut printed = None;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let Some((payload, awaiting)) = worker.call(|app| (app.payload(), app.pairing.awaiting.is_some())) else { return };
            if payload.is_some() && payload != printed && worker.call(|app| app.pairing.record.phone.is_none()) == Some(true) {
                println!("ONA_PAIRING_PAYLOAD {}", payload.as_deref().unwrap_or_default());
                printed = payload;
            }
            if auto_confirm && awaiting {
                worker.call(|app| app.pairing.confirm_code().is_ok());
            }
        }
    });
}

fn main() {
    let app = tauri::Builder::default()
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            // Port 0: chosen by the system at each start (Tor mode), so another program cannot take it in advance.
            let worker = Worker::start(computer_name(), data_dir, 0);
            #[cfg(debug_assertions)]
            debug_hooks(worker.clone());
            app.manage(worker);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            state, chat, create_chat, post_message, delete_chat, confirm, confirm_code, forget_phone, set_mode
        ])
        .build(tauri::generate_context!())
        .expect("ONA could not start");
    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            // Stops tor with the app.
            if let Some(worker) = handle.try_state::<Worker>() {
                worker.call(|app| app.stop());
            }
        }
    });
}
