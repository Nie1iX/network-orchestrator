#[cfg(windows)]
mod imp {
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    pub struct ChildJob {
        handle: HANDLE,
    }

    impl ChildJob {
        pub fn new() -> io::Result<Self> {
            unsafe {
                let handle = CreateJobObjectW(None, PCWSTR::null())
                    .map_err(|_| io::Error::last_os_error())?;
                let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const _,
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
                .is_err()
                {
                    let err = io::Error::last_os_error();
                    let _ = CloseHandle(handle);
                    return Err(err);
                }
                Ok(Self { handle })
            }
        }

        pub fn assign(&self, child: &Child) -> io::Result<()> {
            unsafe {
                AssignProcessToJobObject(self.handle, HANDLE(child.as_raw_handle() as _))
                    .map_err(|_| io::Error::last_os_error())
            }
        }
    }

    impl Drop for ChildJob {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }

    unsafe impl Send for ChildJob {}
    unsafe impl Sync for ChildJob {}
}

#[cfg(not(windows))]
mod imp {
    use std::io;
    use std::process::Child;

    pub struct ChildJob;

    impl ChildJob {
        pub fn new() -> io::Result<Self> {
            Ok(Self)
        }

        pub fn assign(&self, _child: &Child) -> io::Result<()> {
            Ok(())
        }
    }
}

pub use imp::ChildJob;

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    #[cfg(windows)]
    use std::os::windows::process::CommandExt;

    #[cfg(windows)]
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    fn quick_exit_child() -> std::process::Child {
        #[cfg(windows)]
        {
            let mut command = Command::new("cmd");
            command
                .args(["/C", "exit 0"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW);
            command.spawn().unwrap()
        }
        #[cfg(not(windows))]
        {
            Command::new("sh")
                .args(["-c", "exit 0"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        }
    }

    #[test]
    fn child_job_assigns_running_child() {
        let mut child = quick_exit_child();
        let job = ChildJob::new().unwrap();
        job.assign(&child).unwrap();
        child.wait().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn dropping_job_terminates_assigned_child() {
        let mut child = {
            let mut command = Command::new("cmd");
            command
                .args(["/C", "ping", "-n", "30", "127.0.0.1", ">NUL"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW);
            command.spawn().unwrap()
        };
        let job = ChildJob::new().unwrap();
        job.assign(&child).unwrap();
        drop(job);

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("child survived job close");
                }
                Err(err) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("failed to poll child: {err}");
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn assigning_exited_child_does_not_hang() {
        let mut child = quick_exit_child();
        child.wait().unwrap();
        let job = ChildJob::new().unwrap();
        let _ = job.assign(&child);
    }
}
