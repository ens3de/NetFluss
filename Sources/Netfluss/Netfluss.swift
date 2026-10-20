// Copyright (C) 2026 Rana GmbH
//
// This file is part of Netfluss.
//
// Netfluss is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Netfluss is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Netfluss. If not, see <https://www.gnu.org/licenses/>.

import SwiftUI

@main
struct NetFlussApp: App {
    // AppDelegate owns AppState so that StatusBarController (which calls
    // NSStatusBar) is created inside applicationDidFinishLaunching — after
    // the window-server connection is established.  Initialising it earlier
    // (e.g. as a @StateObject) causes an NSCGSPanic / EXC_BAD_INSTRUCTION
    // crash on Intel Macs running macOS 13.
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate

    var body: some Scene {
        // PreferencesWindowController manages its own NSWindow; this scene
        // is required by SwiftUI but produces no visible UI.
        Settings { EmptyView() }
            .commands {
                CommandGroup(replacing: .appSettings) {
                    Button("Preferences…") {
                        NotificationCenter.default.post(name: .showPreferences, object: nil)
                    }
                    .keyboardShortcut(",", modifiers: .command)
                }
            }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var appState: AppState?
    private var preferencesObserver: NSObjectProtocol?
    private var settingsWindowObserver: NSObjectProtocol?

    func applicationDidFinishLaunching(_ notification: Notification) {
        AppIconController.shared.start()
        appState = AppState()
        preferencesObserver = NotificationCenter.default.addObserver(
            forName: .showPreferences,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.appState?.showPreferences()
            }
        }

        // Linked against a recent SDK, SwiftUI opens the placeholder Settings
        // scene at launch — an empty "NetFluss Settings" window. The real
        // preferences live in PreferencesWindowController, so close it whenever
        // it shows up.
        closeEmptySettingsWindows()
        DispatchQueue.main.async { [weak self] in self?.closeEmptySettingsWindows() }
        settingsWindowObserver = NotificationCenter.default.addObserver(
            forName: NSWindow.didChangeOcclusionStateNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.closeEmptySettingsWindows()
            }
        }
    }

    private static let swiftUISettingsWindowID = "com_apple_SwiftUI_Settings_window"

    private func closeEmptySettingsWindows() {
        for window in NSApp.windows where window.isVisible
            && (window.identifier?.rawValue == Self.swiftUISettingsWindowID
                || window.frameAutosaveName == Self.swiftUISettingsWindowID) {
            window.close()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        appState?.flushStatistics()
        TrafficTimer.shared.persist()
        if let preferencesObserver {
            NotificationCenter.default.removeObserver(preferencesObserver)
        }
        if let settingsWindowObserver {
            NotificationCenter.default.removeObserver(settingsWindowObserver)
        }
    }
}
