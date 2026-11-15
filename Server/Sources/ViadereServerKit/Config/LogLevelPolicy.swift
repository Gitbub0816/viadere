import Logging

/// The log level the process actually uses. At `debug`/`trace` the database driver logs every query with its bound values (emails,
/// phone hashes, ciphertext), so staging and production are clamped to `info` or above whatever `LOG_LEVEL` says. Only an explicit
/// `development` or `test` environment may go lower.
public enum LogLevelPolicy {
    public static func effective(logLevel: String?, environment: String?) -> Logger.Level {
        let requested = logLevel.flatMap { Logger.Level(rawValue: $0.lowercased()) } ?? .info
        let permissive = environment.flatMap(DeploymentEnvironment.parse).map { !$0.isStrict } ?? false
        return permissive ? requested : max(requested, .info)
    }
}
