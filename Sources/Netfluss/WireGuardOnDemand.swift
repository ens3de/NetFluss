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

import AppKit
import ApplicationServices
import SystemConfiguration

// MARK: - Reading

/// Tunnels of the official WireGuard app (com.wireguard.macos), which installs
/// each tunnel as a Network Extension VPN service. Their state and On-Demand
/// flag are readable from SystemConfiguration as an ordinary user; only
/// *changing* On-Demand needs the WireGuard app itself (see
/// `WireGuardAppAutomation`).
///
/// With On-Demand on, `scutil --nc stop` is undone by the system within seconds,
/// so `VPNManager` routes such tunnels through the WireGuard app's menu instead.
enum WireGuardAppReader {
    static let bundleIdentifier = "com.wireguard.macos"

    /// The WireGuard app tunnel behind the network service `serviceName`, or nil
    /// when that service belongs to another VPN app.
    static func tunnel(serviceName: String) -> NativeVPN.ServiceSnapshot? {
        NativeVPN.snapshot(of: serviceName).flatMap { $0.providerBundleID == bundleIdentifier ? $0 : nil }
    }

    /// Addresses and DNS of a connected tunnel, from its live connection —
    /// private keys are never touched.
    static func details(serviceID: String) -> WireGuardAppDetails? {
        guard let status = NativeVPN.extendedStatus(serviceID: serviceID) else { return nil }
        let addresses = ["IPv4", "IPv6"].flatMap {
            (status[$0] as? [String: Any])?["Addresses"] as? [String] ?? []
        }
        return WireGuardAppDetails(addresses: addresses, dnsServers: status["DNSServers"] as? [String] ?? [])
    }
}

/// Connection details of a WireGuard app tunnel, for display while it is up.
struct WireGuardAppDetails: Equatable, Sendable {
    /// Addresses assigned to the tunnel interface, IPv4 first.
    let addresses: [String]
    let dnsServers: [String]
}

// MARK: - Driving the WireGuard app

/// Toggles a tunnel's On-Demand flag by clicking the tunnel in the WireGuard
/// app's menu bar menu, through the Accessibility API.
///
/// There is no public API for this: a Network Extension configuration can only
/// be edited by the app that owns it, and the WireGuard app offers no URL scheme
/// or AppleScript dictionary. Its status menu, though, does exactly what is
/// needed — for a tunnel with On-Demand rules, clicking it flips On-Demand, and
/// turning On-Demand off also deactivates the tunnel (`StatusMenu.tunnelClicked`
/// in wireguard-apple).
enum WireGuardAppAutomation {
    enum Failure: Error, Equatable {
        case notTrusted
        case appNotFound
        case appDidNotLaunch
        case statusItemNotFound
        case menuDidNotOpen
        case tunnelNotInMenu(String)
        case pressFailed(Int32)

        var message: String {
            switch self {
            case .notTrusted:
                return L10n.text("NetFluss needs Accessibility access to change On-Demand in the WireGuard app. Allow it in System Settings → Privacy & Security → Accessibility, then try again.")
            case .appNotFound:
                return L10n.text("The WireGuard app is not installed.")
            case .appDidNotLaunch:
                return L10n.text("The WireGuard app did not start.")
            case .statusItemNotFound:
                return L10n.text("The WireGuard menu bar icon was not found.")
            case .menuDidNotOpen:
                return L10n.text("The WireGuard menu did not open.")
            case .tunnelNotInMenu(let name):
                return L10n.format("The tunnel \"%@\" is not in the WireGuard menu.", name)
            case .pressFailed(let code):
                return L10n.format("The WireGuard app did not respond (error %d).", Int(code))
            }
        }
    }

    /// Clicks the WireGuard menu item for `tunnelName`. Blocks for up to a few
    /// seconds while the WireGuard app launches and its menu opens, so call it
    /// off the main thread.
    ///
    /// The menu bar icon only exists while the WireGuard app runs. If it isn't
    /// running, it is launched in the background for the click and quit again
    /// once it has saved the new On-Demand setting — the tunnel itself lives in
    /// the Network Extension and is unaffected by the app quitting.
    ///
    /// While its menu is open the WireGuard app answers AX requests from inside
    /// menu tracking, one round trip at a time, so the number of requests is
    /// what makes this slow — every step below keeps that count down. Returns
    /// per-step timings for the diagnostics log.
    @discardableResult
    static func clickTunnel(named tunnelName: String) throws -> String {
        let clock = StepClock()
        guard AX.isTrusted(prompt: false) else { throw Failure.notTrusted }
        let (pid, launched) = try runningWireGuardPID()
        guard launched else {
            try clickTunnel(named: tunnelName, pid: pid, clock: clock, attempts: 1)
            return clock.summary
        }
        clock.mark("launched WireGuard")
        let onDemandBefore = WireGuardAppReader.tunnel(serviceName: tunnelName)?.isOnDemandEnabled
        defer {
            quitWhenSaved(pid: pid, tunnelName: tunnelName, onDemandBefore: onDemandBefore)
        }
        // Right after launch the icon can appear before the app has loaded its
        // tunnels into the menu, so give it a few tries.
        try clickTunnel(named: tunnelName, pid: pid, clock: clock, attempts: 10)
        return clock.summary
    }

    private static func clickTunnel(named tunnelName: String, pid: pid_t, clock: StepClock, attempts: Int) throws {
        let app = AXUIElementCreateApplication(pid)
        // A menu bar item whose menu is open keeps the owning app in menu
        // tracking, and AX calls into it can otherwise wait the default 6 s.
        AXUIElementSetMessagingTimeout(app, 1.5)

        guard let statusItem = AX.waitFor(timeout: 5, { AX.children(of: AX.attribute(app, "AXExtrasMenuBar")).first }) else {
            throw Failure.statusItemNotFound
        }
        clock.mark("status item")

        var item: AXUIElement?
        var menu: AXUIElement?
        for attempt in 1...attempts {
            // The press opens the menu, but the app does not reply until menu
            // tracking ends — so don't wait for that reply at all; the press is
            // delivered regardless, and the menu shows up in the AX tree.
            AX.pressWithoutWaiting(statusItem)
            // Queries are answered from inside menu tracking; give them room again.
            AXUIElementSetMessagingTimeout(statusItem, 1.5)
            guard let opened = AX.waitFor(timeout: 2, { AX.children(of: statusItem).first }) else {
                throw Failure.menuDidNotOpen
            }
            clock.mark("menu open")
            menu = opened
            item = findTunnelItem(named: tunnelName, in: opened)
            if item != nil { break }
            _ = AXUIElementPerformAction(opened, kAXCancelAction as CFString)
            if attempt < attempts { Thread.sleep(forTimeInterval: 0.3) }
        }
        guard let item, let menu else { throw Failure.tunnelNotInMenu(tunnelName) }
        clock.mark("item found")
        // Like the status item, the menu item's reply can trail the click (the
        // app runs its handler first); a timeout still means it was delivered.
        let result = AX.pressWithoutWaiting(item)
        guard result == .success || result == .cannotComplete else {
            _ = AXUIElementPerformAction(menu, kAXCancelAction as CFString)
            throw Failure.pressFailed(result.rawValue)
        }
        clock.mark("item pressed")
    }

    /// Quits a WireGuard app NetFluss launched, after it has written the
    /// toggled On-Demand flag (quitting earlier could drop the save).
    private static func quitWhenSaved(pid: pid_t, tunnelName: String, onDemandBefore: Bool?) {
        if let onDemandBefore {
            _ = AX.waitFor(timeout: 3) {
                WireGuardAppReader.tunnel(serviceName: tunnelName)?.isOnDemandEnabled != onDemandBefore ? true : nil
            }
        } else {
            // The flag couldn't be read, so there is nothing to watch for;
            // still give the app a moment to save before quitting it.
            Thread.sleep(forTimeInterval: 1)
        }
        NSRunningApplication(processIdentifier: pid)?.terminate()
    }

    /// Matches the titles `TunnelMenuItem.updateTitle()` sets: the bare tunnel
    /// name, or the name followed by " (On-Demand)". With more than ten tunnels
    /// the WireGuard app moves them into a "Tunnels" submenu, so submenus are
    /// searched too.
    static func isTunnelItemTitle(_ title: String, tunnelName: String) -> Bool {
        title == tunnelName || title.hasPrefix(tunnelName + " (")
    }

    /// One request per menu item (role and title together); submenus are only
    /// opened up when the tunnel is not at the top level.
    private static func findTunnelItem(named tunnelName: String, in menu: AXUIElement) -> AXUIElement? {
        let items = AX.children(of: menu).compactMap { item -> (AXUIElement, String)? in
            let values = AX.attributes(item, [kAXRoleAttribute, kAXTitleAttribute])
            guard values.first as? String == kAXMenuItemRole else { return nil }
            return (item, values.last as? String ?? "")
        }
        if let match = items.first(where: { isTunnelItemTitle($0.1, tunnelName: tunnelName) }) {
            return match.0
        }
        for (item, title) in items where !title.isEmpty {
            for submenu in AX.children(of: item) {
                if let found = findTunnelItem(named: tunnelName, in: submenu) { return found }
            }
        }
        return nil
    }

    /// Milliseconds since creation, per named step.
    private final class StepClock {
        private let start = DispatchTime.now()
        private var steps: [String] = []
        func mark(_ step: String) {
            let ms = (DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000
            steps.append("\(step) \(ms) ms")
        }
        var summary: String { steps.joined(separator: ", ") }
    }

    /// The WireGuard app's pid, launching it in the background if needed;
    /// `launched` tells whether NetFluss started it.
    private static func runningWireGuardPID() throws -> (pid: pid_t, launched: Bool) {
        if let app = NSRunningApplication.runningApplications(withBundleIdentifier: WireGuardAppReader.bundleIdentifier).first {
            return (app.processIdentifier, false)
        }
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: WireGuardAppReader.bundleIdentifier) else {
            throw Failure.appNotFound
        }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = false
        NSWorkspace.shared.openApplication(at: url, configuration: configuration, completionHandler: nil)
        guard let pid = AX.waitFor(timeout: 5, {
            NSRunningApplication.runningApplications(withBundleIdentifier: WireGuardAppReader.bundleIdentifier).first?.processIdentifier
        }) else {
            throw Failure.appDidNotLaunch
        }
        return (pid, true)
    }
}
