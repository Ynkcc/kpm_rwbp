#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    EPERM = -1,
    ENOENT = -2,
    ESRCH = -3,
    EINTR = -4,
    EIO = -5,
    ENXIO = -6,
    E2BIG = -7,
    ENOEXEC = -8,
    EBADF = -9,
    ECHILD = -10,
    EAGAIN = -11,
    ENOMEM = -12,
    EACCES = -13,
    EFAULT = -14,
    ENOTBLK = -15,
    EBUSY = -16,
    EEXIST = -17,
    EXDEV = -18,
    ENODEV = -19,
    ENOTDIR = -20,
    EISDIR = -21,
    EINVAL = -22,
    ENFILE = -23,
    EMFILE = -24,
    ENOTTY = -25,
    ETXTBSY = -26,
    EFBIG = -27,
    ENOSPC = -28,
    ESPIPE = -29,
    EROFS = -30,
    EMLINK = -31,
    EPIPE = -32,
    EDOM = -33,
    ERANGE = -34,
    EDEADLK = -35,
    ENAMETOOLONG = -36,
    ENOLCK = -37,
    ENOSYS = -38,
    ENOTEMPTY = -39,
    ELOOP = -40,
}

impl From<Error> for i32 {
    fn from(err: Error) -> Self {
        err as i32
    }
}

impl From<Error> for i64 {
    fn from(err: Error) -> Self {
        err as i64
    }
}

impl From<i32> for Error {
    fn from(code: i32) -> Self {
        match code {
            -1 => Error::EPERM,
            -2 => Error::ENOENT,
            -3 => Error::ESRCH,
            -4 => Error::EINTR,
            -5 => Error::EIO,
            -6 => Error::ENXIO,
            -7 => Error::E2BIG,
            -8 => Error::ENOEXEC,
            -9 => Error::EBADF,
            -10 => Error::ECHILD,
            -11 => Error::EAGAIN,
            -12 => Error::ENOMEM,
            -13 => Error::EACCES,
            -14 => Error::EFAULT,
            -15 => Error::ENOTBLK,
            -16 => Error::EBUSY,
            -17 => Error::EEXIST,
            -18 => Error::EXDEV,
            -19 => Error::ENODEV,
            -20 => Error::ENOTDIR,
            -21 => Error::EISDIR,
            -22 => Error::EINVAL,
            -23 => Error::ENFILE,
            -24 => Error::EMFILE,
            -25 => Error::ENOTTY,
            -26 => Error::ETXTBSY,
            -27 => Error::EFBIG,
            -28 => Error::ENOSPC,
            -29 => Error::ESPIPE,
            -30 => Error::EROFS,
            -31 => Error::EMLINK,
            -32 => Error::EPIPE,
            -33 => Error::EDOM,
            -34 => Error::ERANGE,
            -35 => Error::EDEADLK,
            -36 => Error::ENAMETOOLONG,
            -37 => Error::ENOLCK,
            -38 => Error::ENOSYS,
            -39 => Error::ENOTEMPTY,
            -40 => Error::ELOOP,
            _ => Error::EINVAL,
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}({})", self, *self as i32)
    }
}