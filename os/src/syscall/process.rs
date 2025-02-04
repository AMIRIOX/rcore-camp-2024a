//! Process management syscalls
use crate::{
    config::MAX_SYSCALL_NUM,
    task::{exit_current_and_run_next, suspend_current_and_run_next, TaskStatus},
    timer::get_time_us,
    timer::get_time_ms,
    task::TASK_MANAGER,
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("[kernel] Application exited with code {}", exit_code);
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// get time with second and microsecond
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    unsafe {
        *ts = TimeVal {
            sec: us / 1_000_000,
            usec: us % 1_000_000,
        };
    }
    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info");
    // 找到任务位置
    // 查1. status 2. syscall_id + count 3. 距离第一次调用的时长
    let inner = TASK_MANAGER.inner.exclusive_access();
    let current_task_id = inner.current_task;
    let time = get_time_ms() - inner.tasks[current_task_id].start_time;
    /*if inner.tasks[current_task_id].first_run {
        return -1;
    }*/
    unsafe {
        *_ti = TaskInfo{
            status: inner.tasks[current_task_id].task_status,  // status
            syscall_times: inner.syscall_cnt,       // syscall_times
            time: time,                                        // time
        }
    }
    drop(inner);
    0
}
