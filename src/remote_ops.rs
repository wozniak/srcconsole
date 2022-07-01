use std::any::Any;
use std::ffi::CStr;
use std::mem::{size_of, size_of_val, zeroed};
use winapi::ctypes::*;
use winapi::shared::minwindef::*;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::psapi::*;
use winapi::um::winnt::*;

macro_rules! try_bool {
    ($n:expr) => {{
        let r = $n;
        if !r {
            println!("e: {}", GetLastError());
            None
        } else {
            Some(())
        }
    }};
}

pub(crate) unsafe fn get_remote_module_handle(
    handle: HANDLE,
    lp_module_name: &str,
) -> Option<HMODULE> {
    let mut module_array = vec![std::mem::zeroed(); 250];
    let mut num_modules: DWORD = 0;

    // get handles to all the modules in the target process
    if EnumProcessModulesEx(
        handle,
        module_array.as_mut_ptr(),
        250 * std::mem::size_of::<HMODULE>() as u32,
        &mut num_modules as LPDWORD,
        LIST_MODULES_ALL,
    ) == 0
    {
        return None;
    }

    // if we guessed too little modules, try again with the exact number given by the function
    if num_modules as usize > module_array.len() {
        module_array = vec![std::mem::zeroed(); num_modules as usize];
        if EnumProcessModulesEx(
            handle,
            module_array.as_mut_ptr(),
            num_modules * std::mem::size_of::<HMODULE>() as u32,
            &mut num_modules as LPDWORD,
            LIST_MODULES_ALL,
        ) == 0
        {
            return None;
        };
    }

    // Convert module name to all lowercase so the comparison isn't case sensitive
    let lp_module_name = lp_module_name.to_lowercase();

    // iter through the modules and check if the name matches the goal
    for module in module_array {
        let mut module_name = [0; MAX_PATH];
        GetModuleBaseNameA(
            handle,
            module,
            module_name.as_mut_ptr() as *mut c_char,
            MAX_PATH as DWORD,
        );

        let module_name = CStr::from_ptr(module_name.as_ptr()).to_str().ok()?;

        if module_name.to_lowercase() == lp_module_name {
            return Some(module);
        }
    }

    // if the module isn't picked up by the for loop, it doesn't exist
    None
}

pub(crate) unsafe fn get_remote_proc_address(
    h_process: HANDLE,
    h_module: HMODULE,
    func_name_goal: &str,
    ordinal: u32,
    use_ordinal: bool,
) -> Option<FARPROC> {
    let is_64_bit;
    let mut remote_module_info = zeroed::<MODULEINFO>();
    let mut dos_header = zeroed::<IMAGE_DOS_HEADER>();
    let mut signature: DWORD = 0;
    let mut file_header = zeroed::<IMAGE_FILE_HEADER>();
    let mut opt_header_64 = zeroed::<IMAGE_OPTIONAL_HEADER64>();
    let mut opt_header_32 = zeroed::<IMAGE_OPTIONAL_HEADER32>();
    let mut export_directory = zeroed::<IMAGE_DATA_DIRECTORY>();
    let mut export_table = zeroed::<IMAGE_EXPORT_DIRECTORY>();

    /* Get the base address of the remote module along with some other info we don't need */
    try_bool!(GetModuleInformation(
        h_process,
        h_module,
        &mut remote_module_info as *mut MODULEINFO,
        size_of::<MODULEINFO>() as u32,
    )
    .eq(&1))?;

    let remote_module_base_va = remote_module_info.lpBaseOfDll as usize;

    /* Read the DOS header and check it's magic number */
    read_process_memory(h_process, remote_module_base_va, &mut dos_header, None)?;
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    /* Read and check the NT signature */
    read_process_memory(
        h_process,
        remote_module_base_va + dos_header.e_lfanew as usize,
        &mut signature,
        None,
    )?;
    if signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    /* Read the main header */
    read_process_memory(
        h_process,
        remote_module_base_va + dos_header.e_lfanew as usize + size_of_val(&signature),
        &mut file_header,
        None,
    )?;

    /* Which type of optional header is the right size? */
    if file_header.SizeOfOptionalHeader == size_of::<IMAGE_OPTIONAL_HEADER64>() as u16 {
        is_64_bit = true;
    } else if file_header.SizeOfOptionalHeader == size_of::<IMAGE_OPTIONAL_HEADER32>() as u16 {
        is_64_bit = false;
    } else {
        return None;
    }

    /* Read the optional header and check it's magic number */
    if is_64_bit {
        read_process_memory(
            h_process,
            remote_module_base_va
                + dos_header.e_lfanew as usize
                + size_of_val(&signature)
                + size_of::<IMAGE_FILE_HEADER>(),
            &mut opt_header_64,
            None,
        )?;
        if opt_header_64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return None;
        }
    } else {
        read_process_memory(
            h_process,
            remote_module_base_va
                + dos_header.e_lfanew as usize
                + size_of_val(&signature)
                + size_of::<IMAGE_FILE_HEADER>(),
            &mut opt_header_32,
            None,
        )?;
        if opt_header_32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC {
            return None;
        }
    }

    // Make sure the remote module has an export
    // directory and if it does save it's relative
    // address and size

    if is_64_bit && opt_header_64.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT as u32 {
        export_directory.VirtualAddress =
            opt_header_64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
        export_directory.Size =
            opt_header_64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].Size;
    } else if opt_header_32.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT as u32 {
        export_directory.VirtualAddress =
            opt_header_32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
        export_directory.Size =
            opt_header_32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].Size;
    } else {
        return None;
    }

    // read the main export table
    read_process_memory(
        h_process,
        remote_module_base_va + export_directory.VirtualAddress as usize,
        &mut export_table,
        None,
    )?;

    // Save the absolute address of the tables so we don't need to keep adding the base address
    let export_function_table_va = remote_module_base_va + export_table.AddressOfFunctions as usize;
    let export_name_table_va = remote_module_base_va + export_table.AddressOfNames as usize;
    let export_ordinal_table_va =
        remote_module_base_va + export_table.AddressOfNameOrdinals as usize;

    let mut export_function_table = vec![0_u32; export_table.NumberOfFunctions as usize];
    let mut export_name_table = vec![0_u32; export_table.NumberOfNames as usize];
    let mut export_ordinal_table = vec![0_u16; export_table.NumberOfNames as usize];

    // get a copy of the function table
    read_process_memory(
        h_process,
        export_function_table_va,
        export_function_table.as_mut_ptr(),
        Some(export_function_table.len() * 4),
    );

    // get a copy of the name table
    read_process_memory(
        h_process,
        export_name_table_va,
        export_name_table.as_mut_ptr(),
        Some(export_name_table.len() * 4),
    );

    // get a copy of the ordinal table
    read_process_memory(
        h_process,
        export_ordinal_table_va,
        export_ordinal_table.as_mut_ptr(),
        Some(export_ordinal_table.len() * 2),
    )?;

    if use_ordinal {
        // NOTE:
        // Microsoft's PE/COFF specification does NOT say we need to subtract the ordinal base
        // from our ordinal but it seems to always give the wrong function if we don't

        // make sure the ordinal is valid
        if ordinal < export_table.Base
            || (ordinal - export_table.Base) >= export_table.NumberOfFunctions
        {
            return None;
        }

        let function_table_index = (ordinal - export_table.Base) as usize;

        // check if the function is forwarded and if so get the real address
        if export_function_table[function_table_index] >= export_directory.VirtualAddress
            && export_function_table[function_table_index]
                <= export_directory.VirtualAddress + export_directory.Size
        {
            let tmp = read_process_memory_string(
                h_process,
                remote_module_base_va + export_function_table[function_table_index] as usize,
            )?;

            // temporary varaibles that hold parts of the forwarder string
            let mut split_iter = tmp.split(".");
            let real_module_name = split_iter.next()?;
            let mut real_function_id = split_iter.next()?;

            let real_module = get_remote_module_handle(h_process, real_module_name)?;

            // figure out if the function was exported by name or by ordinal
            if real_function_id.starts_with('#') {
                // exported by ordinal
                real_function_id = real_function_id.trim_start_matches("#");
                let real_ordinal: UINT = real_function_id.parse().ok()?;

                get_remote_proc_address(h_process, real_module, "", real_ordinal, true)
            } else {
                // exported by name
                get_remote_proc_address(h_process, real_module, real_function_id, 0, false)
            }
        } else {
            // not forwarded
            Some((remote_module_base_va + export_function_table[function_table_index] as usize) as FARPROC)
        }
    } else {
        let mut temp_return = None;

        // iterate through all the names to see if they match the one we are looking for
        for i in 0..export_table.NumberOfNames as usize {
            let func_name = read_process_memory_string(
                h_process,
                remote_module_base_va + export_name_table[i] as usize,
            )?;

            if func_name.as_str() == func_name_goal {
                /* Check if the function is forwarded and if so get the real address*/
                if export_function_table[export_ordinal_table[i] as usize]
                    >= export_directory.VirtualAddress
                    && export_function_table[export_ordinal_table[i] as usize]
                        <= export_directory.VirtualAddress + export_directory.Size
                {
                    let tmp = read_process_memory_string(
                        h_process,
                        remote_module_base_va + export_function_table[i] as usize,
                    )?;

                    // temporary varaibles that hold parts of the forwarder string
                    let mut split_iter = tmp.split('.');
                    let real_module_name = split_iter.next()?;
                    let real_function_id = split_iter.next()?;

                    let real_module = get_remote_module_handle(h_process, real_module_name)?;

                    // figure out if the function was exported by name or by ordinal
                    if real_function_id.starts_with('#') {
                        // exported by ordinal

                        let real_function_id = real_function_id.trim_start_matches('#');
                        let real_ordinal: UINT = real_function_id.parse().ok()?;

                        temp_return =
                            get_remote_proc_address(h_process, real_module, "", real_ordinal, true);
                    } else {
                        // exported by name
                        temp_return = get_remote_proc_address(
                            h_process,
                            real_module,
                            real_function_id,
                            0,
                            false,
                        );
                    }
                } else {
                    // not forwarded
                    // NOTE:
                    // Microsoft's PE/COFF specification says we need to subtract the ordinal base
                    // from the value in the ordinal table but that seems to always give the wrong function
                    // so we do it this way instead

                    temp_return = Some((remote_module_base_va + export_function_table[export_ordinal_table[i] as usize] as usize) as FARPROC)
                }

                break;
            }
        }

        temp_return
    }
}

pub(crate) unsafe fn read_process_memory<T: Any>(
    h_process: HANDLE,
    lp_base: usize,
    target: *mut T,
    bytes: Option<usize>,
) -> Option<()> {
    try_bool!(
        ReadProcessMemory(
            h_process,
            lp_base as *mut c_void,
            target as *mut c_void,
            bytes.unwrap_or(size_of_val(&*target)),
            std::ptr::null_mut(),
        ) == 1
    )
}

unsafe fn read_process_memory_string(h_process: HANDLE, lp_base: usize) -> Option<String> {
    let mut vec = vec![];

    let mut n = 0;

    // read char-by-char because we don't know how long the string is
    loop {
        let mut ch = zeroed::<c_char>();

        read_process_memory(h_process, lp_base + n, &mut ch, None)?;

        vec.push(ch);

        if ch == 0 {
            break;
        }

        n += 1;
    }

    CStr::from_ptr(vec.as_ptr())
        .to_str()
        .ok()
        .map(|s| s.to_string())
}
