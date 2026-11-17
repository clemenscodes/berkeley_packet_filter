mod attribute;
mod call;
mod command;

use crate::attribute::Attribute;
use crate::command::Command;
use std::ffi::CStr;
use std::ffi::CString;
use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const LOG_SIZE: u32 = 16384;

pub fn create_hash_map(key_size: u32, value_size: u32, entry_limit: u32) -> io::Result<OwnedFd> {
    let mut attribute = Attribute::compose_map(key_size, value_size, entry_limit);
    let command = u32::from(Command::MapCreation);
    call::try_call_bpf(command, attribute.bytes_mut())
}

pub fn update_element(map: BorrowedFd<'_>, key: &[u8], value: &[u8]) -> io::Result<()> {
    let map_descriptor = descriptor(map);
    let key_address = address(key.as_ptr());
    let value_address = address(value.as_ptr());
    let mut attribute = Attribute::compose_update(map_descriptor, key_address, value_address);
    let command = u32::from(Command::MapUpdate);
    call::try_outcome(command, attribute.bytes_mut())
}

pub fn delete_element(map: BorrowedFd<'_>, key: &[u8]) -> io::Result<()> {
    let map_descriptor = descriptor(map);
    let key_address = address(key.as_ptr());
    let mut attribute = Attribute::compose_deletion(map_descriptor, key_address);
    let command = u32::from(Command::MapDeletion);
    call::try_outcome(command, attribute.bytes_mut())
}

pub fn load_device_program(instructions: &[u8], license: &CStr) -> io::Result<OwnedFd> {
    let instruction_count = try_instruction_count(instructions)?;
    let license_bytes = license.to_bytes_with_nul();
    let log_usage = usize::try_from(LOG_SIZE).unwrap_or_default();
    let mut log: Vec<u8> = vec![0; log_usage];
    let instruction_address = address(instructions.as_ptr());
    let license_address = address(license_bytes.as_ptr());
    let log_address = address(log.as_mut_ptr());
    let mut attribute = Attribute::compose_program(
        instruction_count,
        instruction_address,
        license_address,
        LOG_SIZE,
        log_address,
    );
    let command = u32::from(Command::ProgramLoad);
    match call::try_call_bpf(command, attribute.bytes_mut()) {
        Ok(descriptor) => Ok(descriptor),
        Err(error) => {
            let length = log.iter().position(|byte| *byte == 0).unwrap_or(log.len());
            let report = String::from_utf8_lossy(&log[..length]);
            if report.is_empty() {
                Err(error)
            } else {
                let text = format!("{error}, {report}");
                Err(io::Error::new(error.kind(), text))
            }
        }
    }
}

pub fn pin_object(object: BorrowedFd<'_>, path: &Path) -> io::Result<()> {
    let path_text = try_path(path)?;
    let path_address = address(path_text.as_ptr());
    let object_descriptor = descriptor(object);
    let mut attribute = Attribute::compose_pin(path_address, object_descriptor);
    let command = u32::from(Command::ObjectPin);
    call::try_outcome(command, attribute.bytes_mut())
}

pub fn open_object(path: &Path) -> io::Result<OwnedFd> {
    let path_text = try_path(path)?;
    let path_address = address(path_text.as_ptr());
    let mut attribute = Attribute::compose_lookup(path_address);
    let command = u32::from(Command::ObjectLookup);
    call::try_call_bpf(command, attribute.bytes_mut())
}

pub fn attach_device_program(
    cgroup: BorrowedFd<'_>,
    program: BorrowedFd<'_>,
    multiple: bool,
) -> io::Result<()> {
    let cgroup_descriptor = descriptor(cgroup);
    let program_descriptor = descriptor(program);
    let flags = if multiple { MULTIPLE_FLAG } else { 0 };
    let mut attribute = Attribute::compose_attachment(cgroup_descriptor, program_descriptor, flags);
    let command = u32::from(Command::ProgramAttachment);
    call::try_outcome(command, attribute.bytes_mut())
}

pub fn detach_device_program(cgroup: BorrowedFd<'_>, program: BorrowedFd<'_>) -> io::Result<()> {
    let cgroup_descriptor = descriptor(cgroup);
    let program_descriptor = descriptor(program);
    let mut attribute = Attribute::compose_attachment(cgroup_descriptor, program_descriptor, 0);
    let command = u32::from(Command::ProgramDetachment);
    call::try_outcome(command, attribute.bytes_mut())
}

const MULTIPLE_FLAG: u32 = 2;

fn try_instruction_count(instructions: &[u8]) -> io::Result<u32> {
    if !instructions.len().is_multiple_of(8) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    u32::try_from(instructions.len() / 8).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn try_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn descriptor(borrowed: BorrowedFd<'_>) -> u32 {
    u32::try_from(borrowed.as_raw_fd()).unwrap_or_default()
}

fn address<AddressType>(pointer: *const AddressType) -> u64 {
    u64::try_from(pointer.addr()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    mod helper {
        use super::*;
        use std::env;
        use std::fs;
        use std::path::PathBuf;
        use std::process;

        const ALLOWANCE_PROGRAM: [u8; 16] = [0xB7, 0, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];

        pub(crate) fn privilege() -> bool {
            env::var_os("BERKELEY_PACKET_FILTER_PRIVILEGE").is_some()
        }

        pub(crate) fn try_exercise() -> io::Result<()> {
            let suffix = process::id();
            let cgroup_path = PathBuf::from(format!(
                "/sys/fs/cgroup/berkeley_packet_filter_test_{suffix}"
            ));
            let pin_path =
                PathBuf::from(format!("/sys/fs/bpf/berkeley_packet_filter_test_{suffix}"));
            let outcome = try_run(&cgroup_path, &pin_path);
            drop(fs::remove_file(&pin_path));
            drop(fs::remove_dir(&cgroup_path));
            outcome
        }

        fn try_run(cgroup_path: &Path, pin_path: &Path) -> io::Result<()> {
            fs::create_dir(cgroup_path)?;
            let cgroup = fs::File::open(cgroup_path)?;
            let map = create_hash_map(4, 4, 1)?;
            let key = [0; 4];
            let value = [0; 4];
            update_element(map.as_fd(), &key, &value)?;
            delete_element(map.as_fd(), &key)?;
            let license = c"GPL";
            let program = load_device_program(&ALLOWANCE_PROGRAM, license)?;
            attach_device_program(cgroup.as_fd(), program.as_fd(), false)?;
            detach_device_program(cgroup.as_fd(), program.as_fd())?;
            pin_object(map.as_fd(), pin_path)?;
            let reopened = open_object(pin_path)?;
            drop(reopened);
            Ok(())
        }
    }

    #[test]
    fn a_privileged_run_exercises_every_call_against_the_kernel() {
        if !helper::privilege() {
            return;
        }

        let outcome = helper::try_exercise();

        outcome.unwrap();
    }

    #[test]
    fn a_program_of_a_length_that_is_no_multiple_of_eight_is_refused() {
        let instructions = [0; 7];
        let license = c"GPL";

        let outcome = load_device_program(&instructions, license);

        assert_eq!(outcome.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_path_that_holds_a_zero_byte_is_refused() {
        let stdin = io::stdin();
        let path = Path::new("devices\0program");

        let pin = pin_object(stdin.as_fd(), path);
        let lookup = open_object(path);

        assert_eq!(pin.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(lookup.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
}
