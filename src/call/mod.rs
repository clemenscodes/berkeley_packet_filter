use std::io;
use std::mem;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

pub(crate) fn try_outcome(command: u32, attribute: &mut [u8]) -> io::Result<()> {
    let acknowledgement = try_call_bpf(command, attribute)?;
    mem::forget(acknowledgement);
    Ok(())
}

#[allow(unsafe_code)]
pub(crate) fn try_call_bpf(command: u32, attribute: &mut [u8]) -> io::Result<OwnedFd> {
    let attribute_pointer = attribute.as_mut_ptr();
    let attribute_size = attribute.len();
    let answer =
        unsafe { libc::syscall(libc::SYS_bpf, command, attribute_pointer, attribute_size) };
    let descriptor = i32::try_from(answer)
        .ok()
        .filter(|descriptor| *descriptor >= 0)
        .ok_or_else(io::Error::last_os_error)?;
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_load_of_an_empty_program_answers_an_error_of_the_kernel() {
        let mut attribute = vec![0; 128];

        let outcome = try_call_bpf(5, &mut attribute);

        assert!(outcome.is_err());
    }

    #[test]
    fn an_unprivileged_creation_of_a_map_answers_an_error_of_the_kernel() {
        let mut attribute = vec![0; 128];
        attribute[0..4].copy_from_slice(&1u32.to_le_bytes());
        attribute[4..8].copy_from_slice(&4u32.to_le_bytes());
        attribute[8..12].copy_from_slice(&4u32.to_le_bytes());
        attribute[12..16].copy_from_slice(&1u32.to_le_bytes());

        let outcome = try_outcome(0, &mut attribute);

        assert!(outcome.is_err());
    }
}
