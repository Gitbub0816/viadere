#if canImport(Glibc)
import Glibc
#endif
import Foundation

/// Process hardening of the authority (ledger L-14, condition C-15): `RLIMIT_CORE` 0 and `PR_SET_DUMPABLE` 0, so key material and HMAC keys in
/// memory cannot leave through a core dump or a same-user `ptrace`/`/proc/<pid>/mem` read. Startup fails closed if either cannot be applied.
public enum AuthorityProcessHardening {
    #if os(Linux)
    static let setDumpable: Int32 = 4 // PR_SET_DUMPABLE
    static let getDumpable: Int32 = 3 // PR_GET_DUMPABLE
    /// `prctl` is variadic in C and not importable; it is called through its symbol with the fixed five-argument signature.
    typealias PrctlFunction = @convention(c) (Int32, UInt, UInt, UInt, UInt) -> Int32

    static func prctl(_ option: Int32) -> Int32? {
        guard let symbol = dlsym(nil, "prctl") else { return nil }
        let function = unsafeBitCast(symbol, to: PrctlFunction.self)
        return function(option, 0, 0, 0, 0)
    }
    #endif

    /// Applies both settings; `false` if either failed.
    public static func apply() -> Bool {
        #if os(Linux)
        var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
        guard setrlimit(Int32(RLIMIT_CORE.rawValue), &noCore) == 0 else { return false }
        guard prctl(setDumpable) == 0 else { return false }
        return isApplied
        #else
        return true
        #endif
    }

    /// Whether the process is currently non-dumpable with a zero core limit.
    public static var isApplied: Bool {
        #if os(Linux)
        var limit = rlimit()
        guard getrlimit(Int32(RLIMIT_CORE.rawValue), &limit) == 0, limit.rlim_cur == 0, limit.rlim_max == 0 else { return false }
        return prctl(getDumpable) == 0
        #else
        return true
        #endif
    }
}
