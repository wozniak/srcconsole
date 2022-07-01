mod remote_ops;
mod sigscan;

use std::ffi::{CStr, CString};
use std::mem::{size_of, transmute, zeroed};
use winapi::um::tlhelp32::*;

use winapi::shared::minwindef::*;
use winapi::um::minwinbase::*;

use winapi::um::winbase::*;

use remote_ops::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::*;

use winapi::ctypes::*;
use winapi::um::memoryapi::*;

use winapi::um::synchapi::*;

use winapi::um::handleapi::*;
use winapi::um::psapi::{GetModuleInformation, MODULEINFO};
use std::convert::TryInto;
use winapi::um::errhandlingapi::GetLastError;

#[macro_export]
macro_rules! try_bool {
    ($n:expr) => {{
        let r = $n;
        if !r {
            None
        } else {
            Some(())
        }
    }};
}

/// A struct for doing various things with the source engine console;
pub struct SourceConsole {
    game_process: HANDLE,
    msg_func_pointer: FARPROC,
    warning_func_pointer: FARPROC,
    error_func_pointer: FARPROC,
    log_func_pointer: FARPROC,
    cbuf_addtext_func_pointer: Option<FARPROC>,
}

unsafe impl Send for SourceConsole {}

impl SourceConsole {
    pub fn new<S: AsRef<str>>(proc_name: S) -> Option<Self> {
        unsafe {
            let proc_name_cstring = CString::new(proc_name.as_ref()).unwrap();

            let mut entry = zeroed::<PROCESSENTRY32>();
            entry.dwSize = size_of::<PROCESSENTRY32>() as DWORD;

            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

            while Process32Next(snapshot, &mut entry as *mut PROCESSENTRY32) == TRUE {
                if CStr::from_ptr(entry.szExeFile.as_ptr()) == proc_name_cstring.as_c_str() {
                    let game_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

                    let tier0 = get_remote_module_handle(game_process, "tier0.dll")?;

                    let ptr_vec = ["Log", "Msg", "Warning", "Error"]
                        .iter()
                        .map(|func_name| {
                            get_remote_proc_address(game_process, tier0, *func_name, 0, false)
                        })
                        .collect::<Vec<_>>();

                    let engine = get_remote_module_handle(game_process, "engine.dll")?;
                    let addtext_func_pointer = find_cbuf_addtext(game_process, engine);

                    return Some(Self {
                        game_process,
                        log_func_pointer: ptr_vec[0]?,
                        msg_func_pointer: ptr_vec[1]?,
                        warning_func_pointer: ptr_vec[2]?,
                        error_func_pointer: ptr_vec[3]?,
                        cbuf_addtext_func_pointer: addtext_func_pointer,
                    });
                }
            }

            None
        }
    }

    #[inline]
    pub fn msg<S: AsRef<str>>(&self, string: S) {
        unsafe { self.call_fn_with_string_param(string, self.msg_func_pointer) };
    }

    #[inline]
    pub fn log<S: AsRef<str>>(&self, string: S) {
        unsafe { self.call_fn_with_string_param(string, self.log_func_pointer) };
    }

    #[inline]
    pub fn warning<S: AsRef<str>>(&self, string: S) {
        unsafe { self.call_fn_with_string_param(string, self.warning_func_pointer) };
    }

    #[inline]
    pub fn error<S: AsRef<str>>(&self, string: S) {
        unsafe { self.call_fn_with_string_param(string, self.error_func_pointer) };
    }

    #[inline]
    pub fn exec<S: AsRef<str>>(&self, string: S) {
        if let Some(f) = self.cbuf_addtext_func_pointer {
            unsafe { self.call_fn_with_string_param(string, f) };
        }
    }

    unsafe fn call_fn_with_string_param<S: AsRef<str>>(&self, string: S, func: FARPROC) {
        let buf_size = string.as_ref().as_bytes().len();

        let string_buf = VirtualAllocEx(
            self.game_process,
            std::ptr::null_mut(),
            buf_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if string_buf == std::ptr::null_mut() {
            println!("{}", GetLastError());
            return;
        }

        let mut bytes_written: usize = 0;
        WriteProcessMemory(
            self.game_process,
            string_buf,
            string.as_ref().as_ptr() as *const _ as *const c_void,
            buf_size,
            &mut bytes_written,
        );

        let s = CreateRemoteThread(
            self.game_process,
            std::ptr::null_mut(),
            0,
            std::mem::transmute::<_, LPTHREAD_START_ROUTINE>(func),
            string_buf,
            0,
            std::ptr::null_mut(),
        );

        if s != std::ptr::null_mut() {
            WaitForSingleObject(s, 0xffffffff);
            TerminateThread(s, 0);
            CloseHandle(s);
        }

        VirtualFreeEx(self.game_process, string_buf, buf_size, MEM_RELEASE);
    }
}

unsafe fn find_cbuf_addtext(h_process: HANDLE, h_module: HMODULE) -> Option<FARPROC> {
    let mut module_information = zeroed::<MODULEINFO>();
    try_bool!(GetModuleInformation(
        h_process,
        h_module,
        &mut module_information as *mut MODULEINFO,
        size_of::<MODULEINFO>() as u32
    ) != 0)?;

    let module_base = module_information.lpBaseOfDll as usize;

    // check dos header sig
    let mut dos_header = zeroed::<IMAGE_DOS_HEADER>();
    remote_ops::read_process_memory(h_process, module_base, &mut dos_header, None)?;
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    // read file header
    let mut file_header = zeroed::<IMAGE_FILE_HEADER>();
    remote_ops::read_process_memory(h_process, module_base + size_of::<IMAGE_DOS_HEADER>(), &mut file_header, None)?;

    if file_header.SizeOfOptionalHeader as usize == size_of::<IMAGE_OPTIONAL_HEADER64>() {
        println!("this function can't run on 64-bit modules");
    }

    // read full image for scanning
    let mut image = vec![0_u8; module_information.SizeOfImage as usize];
    remote_ops::read_process_memory(h_process, module_base, image.as_mut_ptr(), Some(image.len()));
    let image = image;

    // find where the string is
    let str_addr = module_base + sigscan::scan(&image, &b"exec config_default.cfg"[..])?;

    // find where the push instruction is
    let push_sig: &[u8] = &[&[0x68][..], &(str_addr as u32).to_le_bytes()].concat();
    let push_addr = sigscan::scan(&image, push_sig)?;

    // find the function pointer from the next call
    let mut fn_ptr = None;
    for (i, w) in image[push_addr + 5..push_addr + 55].windows(5).enumerate() {
        if w[0] == 0xe8 {
            let ptr = i32::from_le_bytes(w[1..].try_into().unwrap());

            // since call uses a relative address, find the actual address
            let (neg, ptr) = (ptr.is_negative(), ptr.abs() as u32);

            let fn_addr;
            if neg {
                fn_addr = (push_addr + i + 5) as u32 + 5 - ptr;
            } else {
                fn_addr = (push_addr + i + 5) as u32 + 5 + ptr;
            }

            // check to make sure the fn address is inside the module
            if fn_addr < module_information.SizeOfImage {
                fn_ptr = Some((fn_addr as usize + module_base) as FARPROC);
                break
            }
        }
    }

    fn_ptr
}