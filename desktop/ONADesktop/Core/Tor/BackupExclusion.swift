import Foundation

/// Keeps the app's folder (`~/Library/Application Support/ONA`: the onion service key, tor's state, `model.json`) out of
/// Time Machine backups, so that a copy of the onion key does not outlive this Mac in a backup. Conversations are not
/// there: they live in memory only and are gone when the app quits.
public enum BackupExclusion {
    public static var appFolder: URL {
        URL.applicationSupportDirectory.appending(path: "ONA", directoryHint: .isDirectory)
    }

    /// Creates the folder if needed and marks it excluded. Throws when the mark cannot be set.
    public static func exclude(_ folder: URL = appFolder) throws {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var folder = folder
        try folder.setResourceValues(values)
    }
}
