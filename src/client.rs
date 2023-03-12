use num_derive::FromPrimitive;
use syscalls::{syscall as raw_syscall, Errno, Sysno};

#[derive(FromPrimitive, Debug)]
pub enum ToxicCommand {
    Set = 0,
    Exit,
    Remove,
}

pub struct Client {}

impl Client {
    pub fn set(syscall: Sysno, error: i32) -> Result<usize, Errno> {
        unsafe { raw_syscall!(Sysno::toxic, ToxicCommand::Set, syscall, error) }
    }
    pub fn remove(syscall: Sysno) -> Result<usize, Errno> {
        unsafe { raw_syscall!(Sysno::toxic, ToxicCommand::Remove, syscall) }
    }

    pub fn exit() -> Result<usize, Errno> {
        match unsafe { raw_syscall!(Sysno::toxic, ToxicCommand::Exit) } {
            Err(Errno::ENOSYS) => Ok(0),
            _ => {
                panic!("op exit should always return ENOSYS");
            }
        }
    }
}
