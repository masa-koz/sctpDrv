MessageIdTypedef=NTSTATUS

SeverityNames = (
    Success       = 0x0:STATUS_SEVERITY_SUCCESS
    Informational = 0x1:STATUS_SEVERITY_INFORMATIONAL
    Warning       = 0x2:STATUS_SEVERITY_WARNING
    Error         = 0x3:STATUS_SEVERITY_ERROR
)

FacilityNames = (
    SOCK = 0xff:SOCK
)

MessageId=1 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EPERM
Language=English
Operation not permitted
.

MessageId=2 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOENT
Language=English
No such file or directory
.

MessageId=3 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ESRCH
Language=English
No such process
.

MessageId=4 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EINTR
Language=English
Interrupted system call
.

MessageId=5 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EIO
Language=English
Input/output error
.

MessageId=6 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENXIO
Language=English
Device not configured
.

MessageId=7 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_E2BIG
Language=English
Argument list too long
.

MessageId=8 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOEXEC
Language=English
Exec format error
.

MessageId=9 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EBADF
Language=English
Bad file descriptor
.

MessageId=10 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ECHILD
Language=English
No child processes
.

MessageId=11 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EDEADLK
Language=English
Resource deadlock avoided
.

MessageId=12 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOMEM
Language=English
Cannot allocate memory
.

MessageId=13 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EACCES
Language=English
Permission denied
.

MessageId=14 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EFAULT
Language=English
Bad address
.

MessageId=15 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOTBLK
Language=English
Block device required
.

MessageId=16 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EBUSY
Language=English
Device busy
.

MessageId=17 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EEXIST
Language=English
File exists
.

MessageId=18 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EXDEV
Language=English
Cross-device link
.

MessageId=19 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENODEV
Language=English
Operation not supported by device
.

MessageId=20 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOTDIR
Language=English
Not a directory
.

MessageId=21 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EISDIR
Language=English
Is a directory
.

MessageId=22 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EINVAL
Language=English
Invalid argument
.

MessageId=23 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENFILE
Language=English
Too many open files in system
.

MessageId=24 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EMFILE
Language=English
Too many open files
.

MessageId=25 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOTTY
Language=English
Inappropriate ioctl for device
.

MessageId=26 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ETXTBSY
Language=English
Text file busy
.

MessageId=27 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EFBIG
Language=English
File too large
.

MessageId=28 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOSPC
Language=English
No space left on device
.

MessageId=29 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ESPIPE
Language=English
Illegal seek
.

MessageId=30 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EROFS
Language=English
Read-only filesystem
.

MessageId=31 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EMLINK
Language=English
Too many links
.

MessageId=32 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EPIPE
Language=English
Broken pipe
.

MessageId=33 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EDOM
Language=English
Numerical argument out of domain
.

MessageId=34 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ERANGE
Language=English
Result too large
.

MessageId=35 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EWOULDBLOCK
Language=English
Resource temporarily unavailable
.

MessageId=36 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EINPROGRESS
Language=English
Operation now in progress
.

MessageId=37 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EALREADY
Language=English
Operation already in progress
.

MessageId=38 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOTSOCK
Language=English
Socket operation on non-socket
.

MessageId=39 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EDESTADDRREQ
Language=English
Destination address required
.

MessageId=40 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EMSGSIZE
Language=English
Message too long
.

MessageId=41 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EPROTOTYPE
Language=English
Protocol wrong type for socket
.

MessageId=42 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOPROTOOPT
Language=English
Protocol not available
.

MessageId=43 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EPROTONOSUPPORT
Language=English
Protocol not supported
.

MessageId=44 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ESOCKTNOSUPPORT
Language=English
Socket type not supported
.

MessageId=45 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EOPNOTSUPP
Language=English
Operation not supported
.

MessageId=46 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EPFNOSUPPORT
Language=English
Protocol family not supported
.

MessageId=47 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EAFNOSUPPORT
Language=English
Address family not supported by protocol family
.

MessageId=48 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EADDRINUSE
Language=English
Address already in use
.

MessageId=49 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EADDRNOTAVAIL
Language=English
Can't assign requested address
.

MessageId=50 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENETDOWN
Language=English
Network is down
.

MessageId=51 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENETUNREACH
Language=English
Network is unreachable
.

MessageId=52 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENETRESET
Language=English
Network dropped connection on reset
.

MessageId=53 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ECONNABORTED
Language=English
Software caused connection abort
.

MessageId=54 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ECONNRESET
Language=English
Connection reset by peer
.

MessageId=55 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOBUFS
Language=English
No buffer space available
.

MessageId=56 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EISCONN
Language=English
Socket is already connected
.

MessageId=57 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOTCONN
Language=English
Socket is not connected
.

MessageId=58 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ESHUTDOWN
Language=English
Can't send after socket shutdown
.

MessageId=59 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ETOOMANYREFS
Language=English
Too many references: can't splice
.

MessageId=60 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ETIMEDOUT
Language=English
Operation timed out
.

MessageId=61 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ECONNREFUSED
Language=English
Connection refused
.

MessageId=62 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ELOOP
Language=English
Too many levels of symbolic links
.

MessageId=63 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENAMETOOLONG
Language=English
File name too long
.

MessageId=64 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EHOSTDOWN
Language=English
Host is down
.

MessageId=65 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EHOSTUNREACH
Language=English
No route to host
.

MessageId=66 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOTEMPTY
Language=English
Directory not empty
.

MessageId=67 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EPROCLIM
Language=English
Too many processes
.

MessageId=68 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EUSERS
Language=English
Too many users
.

MessageId=69 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ESTALE
Language=English
Stale NFS file handle
.

MessageId=70 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EREMOTE
Language=English
Too many levels of remote in path
.

MessageId=71 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EBADRPC
Language=English
RPC struct is bad
.

MessageId=72 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ERPCMISMATCH
Language=English
RPC version wrong
.

MessageId=73 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EPROGUNAVAIL
Language=English
RPC prog. not avail
.

MessageId=74 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EPROGMISMATCH
Language=English
Program version wrong
.

MessageId=75 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EPROCUNAVAIL
Language=English
Bad procedure for program
.

MessageId=76 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOLCK
Language=English
No locks available
.

MessageId=77 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOSYS
Language=English
Function not implemented
.

MessageId=78 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EFTYPE
Language=English
Inappropriate file type or format
.

MessageId=79 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EAUTH
Language=English
Authentication error
.

MessageId=80 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENEEDAUTH
Language=English
Need authenticator
.

MessageId=81 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EIDRM
Language=English
Identifier removed
.

MessageId=82 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOMSG
Language=English
No message of desired type
.

MessageId=83 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EOVERFLOW
Language=English
Value too large to be stored in data type
.

MessageId=84 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ECANCELED
Language=English
Operation canceled
.

MessageId=85 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EILSEQ
Language=English
Illegal byte sequence
.

MessageId=86 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOATTR
Language=English
Attribute not found
.

MessageId=87 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EDOOFUS
Language=English
Programming error
.

MessageId=88 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EBADMSG
Language=English
Bad message
.

MessageId=89 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EMULTIHOP
Language=English
Multihop attempted
.

MessageId=90 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_ENOLINK
Language=English
Link has been severed
.

MessageId=91 Facility=SOCK Severity=Error SymbolicName=STATUS_SOCKET_EPROTO
Language=English
Protocol error
.
