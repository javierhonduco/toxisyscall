use clap::Parser;

use libc::user_regs_struct;
use log::{debug, error, info};
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use num_traits::FromPrimitive;
use procfs::process::Process;
use std::collections::HashMap;
use std::process;
use syscalls::Sysno;
use toxisyscall::client::ToxicCommand;

const INVALID_SYSCALL: u64 = -libc::ENOSYS as u64;

#[derive(Parser)]
struct Cli {
    #[clap(short, long)]
    pid: i32,
}

#[derive(Clone)]
struct ErrorStrategy {
    dry_run_syscall: bool,
    error: u64,
}

type StrategyMap = HashMap<u64, ErrorStrategy>;
enum SyscallState {
    Entry,
    Exit,
}

impl Default for SyscallState {
    fn default() -> Self {
        SyscallState::Entry
    }
}

struct ToxiSyscall {
    // Mapping of TGIDs to strategy. These are the identifier
    // shared by sibling threads.
    config: HashMap<Pid, StrategyMap>,
    // Thread state, called PID by the kernel.
    state: HashMap<Pid, SyscallState>,
}

impl ToxiSyscall {
    fn new() -> Self {
        ToxiSyscall {
            config: HashMap::new(),
            state: HashMap::new(),
        }
    }

    fn add_process(&mut self, pid: Pid, strategy_map: StrategyMap) {
        let tgid = Pid::from_raw(Process::new(pid.into()).unwrap().status().unwrap().tgid);
        self.config.insert(tgid, strategy_map);
    }

    fn run(mut self) {
        self.attach_config_task();
        self.ptrace_loop();
    }

    fn threads(&mut self, pid: Pid) -> Vec<Pid> {
        let mut res = Vec::new();
        let children: Vec<i32> = Process::new(pid.into())
            .unwrap()
            .tasks()
            .unwrap()
            .flatten()
            .map(|t| t.tid)
            .collect();

        for child_pid in children.into_iter() {
            if pid != Pid::from_raw(child_pid) {
                res.push(Pid::from_raw(child_pid));
            }
        }

        res
    }

    fn attach_task(&mut self, pid: Pid) {
        debug!("attaching to pid {}", pid);
        match ptrace::attach(pid) {
            Err(e) => {
                error!("attach to pid {pid} failed with {e:?}");
                process::exit(-1);
            }
            Ok(..) => {
                self.state.insert(pid, SyscallState::default());

                let wait_result = waitpid(pid, None).unwrap();
                debug!("first wait {:?}", wait_result);
                ptrace::setoptions(
                    pid,
                    ptrace::Options::PTRACE_O_TRACESYSGOOD
                        | ptrace::Options::PTRACE_O_TRACEFORK
                        | ptrace::Options::PTRACE_O_TRACEVFORK
                        | ptrace::Options::PTRACE_O_TRACECLONE,
                )
                .unwrap();

                ptrace::syscall(pid, None).unwrap();
            }
        }
    }
    fn attach_config_task(&mut self) {
        let task_pids: Vec<Pid> = self.config.keys().copied().collect();
        for task_pid in task_pids {
            self.attach_task(task_pid);

            let sibling_thread_pids = self.threads(task_pid);
            for sibling_thread_pid in sibling_thread_pids {
                debug!("attaching sibling thread task {:?}", sibling_thread_pid);
                self.attach_task(sibling_thread_pid);
            }
        }
    }

    fn ptrace_loop(&mut self) {
        let mut prev_regs = None;

        loop {
            let w = waitpid(None, None);
            if w.is_err() {
                continue;
            }
            let wait_result = w.unwrap();
            debug!("wait_result: {wait_result:?}");

            match wait_result {
                WaitStatus::PtraceSyscall(pid) => {
                    let tgid =
                        Pid::from_raw(Process::new(pid.into()).unwrap().status().unwrap().tgid);
                    if self.config.get(&tgid).is_none() {
                        info!("no config for pid {}", pid);
                        ptrace::syscall(pid, None).unwrap();
                        continue;
                    }
                    let process_config_ref = self.config.get(&tgid).unwrap();
                    let mut process_config = HashMap::new();
                    process_config.clone_from(process_config_ref);

                    debug!("wait returned {:?}", wait_result);

                    let task_state = self.state.get(&pid).unwrap();
                    let regs = ptrace::getregs(pid).unwrap();
                    match task_state {
                        SyscallState::Entry => {
                            // On syscall entry rax should have this value.
                            if regs.rax != INVALID_SYSCALL {
                                error!("Expected to be in syscall entry");
                                ptrace::syscall(pid, None).unwrap();
                            }

                            if Sysno::from(regs.orig_rax as u32) == Sysno::toxic {
                                // In x86_64 the order of arguments for system calls is %rdi, %rsi, %rdx, %rcx, %r8 and %r9.
                                let op = FromPrimitive::from_u64(regs.rdi);
                                let syscall = regs.rsi;
                                let error = regs.rdx;

                                info!("requesting toxic {:?}", op);
                                let mut strategy_map = StrategyMap::new();

                                match op {
                                    Some(ToxicCommand::Set) => {
                                        strategy_map.insert(
                                            syscall,
                                            ErrorStrategy {
                                                error,
                                                dry_run_syscall: false,
                                            },
                                        );
                                        self.add_process(pid, strategy_map);
                                    }
                                    Some(ToxicCommand::Exit) => {
                                        // Return without fixing up return value.
                                        return;
                                    }
                                    Some(ToxicCommand::Remove) => {
                                        let strategy_map = StrategyMap::new();
                                        self.add_process(pid, strategy_map);
                                    }
                                    None => {
                                        error!("invalid operation {:?}", op);
                                    }
                                }
                            }

                            prev_regs = Some(regs);

                            if let Some(strategy) = process_config.get(&regs.orig_rax) {
                                if strategy.dry_run_syscall {
                                    let mut regs_copy: user_regs_struct = regs;
                                    regs_copy.orig_rax = u64::MAX;
                                    debug!("hijacking syscall to make it fail");
                                    ptrace::setregs(pid, regs_copy).unwrap();
                                }
                            };

                            self.state.insert(pid, SyscallState::Exit).unwrap();
                        }
                        SyscallState::Exit => {
                            if prev_regs.is_none() {
                                panic!("expected prev_regs to be populated in syscall return");
                            }

                            if regs.orig_rax == Sysno::toxic as u64 {
                                debug!("handling synthetic SYS_TOXIC syscall");
                                let mut regs_copy: user_regs_struct = regs;
                                regs_copy.rax = 0;
                                debug!("hijacking return value due to SYS_TOXIC");
                                ptrace::setregs(pid, regs_copy).unwrap();
                            }

                            if let Some(strategy) = process_config.get(&prev_regs.unwrap().orig_rax)
                            {
                                let mut regs_copy: user_regs_struct = regs;
                                regs_copy.rax = strategy.error;
                                debug!(
                                    "hijacking return value due to config to {:?}",
                                    strategy.error
                                );
                                ptrace::setregs(pid, regs_copy).unwrap();
                            };

                            self.state.insert(pid, SyscallState::Entry).unwrap();
                        }
                    }

                    debug!(
                        "ptrace::syscall {:?} after dealing with system call entry/exit",
                        pid
                    );
                    ptrace::syscall(pid, None).unwrap();
                }
                WaitStatus::Stopped(pid, signal) => {
                    debug!("stopped pid: {:?}, signal: {:?}", pid, signal);
                    ptrace::syscall(pid, signal).unwrap();
                }
                WaitStatus::PtraceEvent(pid, signal, event) => {
                    debug!(
                        "ptrace event pid: {}, signal: {:?}, event: {:?}",
                        pid, signal, event
                    );
                    ptrace::syscall(pid, signal).unwrap();
                }
                WaitStatus::Exited(pid, status) => {
                    debug!("task {} exited with status {}", pid, status);
                    ptrace::cont(pid, None).unwrap();
                }
                _ => {
                    error!("unhandled wait result {:?})", wait_result);
                }
            }
        }
    }
}

fn main() {
    env_logger::init();

    let args = Cli::parse();
    let pid = Pid::from_raw(args.pid);

    debug!("starting toxisyscall");
    let mut toxi_syscall = ToxiSyscall::new();
    let strategy_map = StrategyMap::new();
    toxi_syscall.add_process(pid, strategy_map);
    toxi_syscall.run();
    debug!("exiting");
}
