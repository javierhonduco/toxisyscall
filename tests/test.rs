use assert_cmd::prelude::*;
use core::time;

use std::os::fd::AsRawFd;
use std::fs::File;
use std::path::Path;
use std::process::Stdio;
use std::{
    process::{id, Command},
    thread,
};
use syscalls::*;
use toxisyscall::client::Client;
use test_log::test;

#[test]
fn test_toxisyscall() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("toxisyscall")?;
    cmd.arg("--pid").arg(format!("{}", id()));
    cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    println!("cmd: {cmd:?}");

    // Wait for toxisyscall to start.
    thread::sleep(time::Duration::from_millis(150));

    let syscall = Sysno::openat;
    let error: i32 = -libc::EBADMSG;
    let path = Path::new("/");

    // Check that the system call works before.
    assert!(File::open(path).is_ok());
    // Add toxic.
    assert!(Client::set(syscall, error).is_ok());
    // Check that toxic works.
    match File::open(path) {
        Err(e) => { assert_eq!(e.to_string(), "Bad message (os error 74)") }
        _ => { panic!("unexpected result")},
    }
    // Remove toxic.
    assert!(Client::remove(syscall).is_ok());
    // Check that toxic is no longer working.
    assert!(File::open(path).is_ok());
    // Request dettach.
    assert!(Client::exit().is_ok());

    Ok(())
}

// Also test without libc.
#[test]
fn test_toxisyscall_raw() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("toxisyscall")?;
    cmd.arg("--pid").arg(format!("{}", id()));
    cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    println!("cmd: {cmd:?}");

    // Wait for toxisyscall to start.
    thread::sleep(time::Duration::from_millis(150));

    let syscall = Sysno::openat;
    let error: i32 = -libc::EBADMSG;
    let path = Path::new("/");

    let s = "/\0";
    let fd = File::open(path).unwrap();
    assert!(unsafe { syscall!(Sysno::openat, fd.as_raw_fd(), s.as_ptr() as *const _, 0) }.is_ok());
    // Add toxic.
    assert!(Client::set(syscall, error).is_ok());
    // Check that toxic works.
    assert!(unsafe { syscall!(Sysno::openat, fd.as_raw_fd(), s.as_ptr() as *const _, 0) }.is_err());
    // Remove toxic.
    assert!(Client::remove(syscall).is_ok());
    // Check that toxic is no longer working.
    assert!(unsafe { syscall!(Sysno::openat, fd.as_raw_fd(), s.as_ptr() as *const _, 0) }.is_ok());
    // Request dettach.
    assert!(Client::exit().is_ok());

    Ok(())
}
