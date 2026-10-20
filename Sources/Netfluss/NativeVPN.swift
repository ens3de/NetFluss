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

import Foundation
import SystemConfiguration

/// Controls macOS-native VPN services (IKEv2 / IPsec / L2TP) via `scutil --nc`.
/// These are the VPNs configured in System Settings or installed from a provider
/// `.mobileconfig`; NetFluss starts/stops/queries them. Run as the user (native
/// VPNs are per-session), so no privileged helper is needed and no special
/// entitlement — unlike a Network Extension.
enum NativeVPN {
    struct Service: Identifiable, Equatable, Sendable {
        var id: String { name }
        let name: String
        let kind: String   // e.g. "IKEv2", "L2TP", "IPSec"
    }

    /// Configured native VPN services, parsed from `scutil --nc list`.
    static func list() -> [Service] {
        let output = run(["--nc", "list"]) ?? ""
        var services: [Service] = []
        for line in output.split(whereSeparator: \.isNewline) {
            // * (Disconnected)   <UUID> PPP --> L2TP   "Name"   [PPP:L2TP]
            guard let nameStart = line.firstIndex(of: "\""),
                  let nameEnd = line[line.index(after: nameStart)...].firstIndex(of: "\"") else { continue }
            let name = String(line[line.index(after: nameStart)..<nameEnd])
            var kind = "VPN"
            if let lb = line.lastIndex(of: "["), let rb = line.lastIndex(of: "]"), lb < rb {
                kind = String(line[line.index(after: lb)..<rb])
            }
            services.append(Service(name: name, kind: kind))
        }
        return services
    }

    // MARK: SystemConfiguration reads

    /// A service's connection state, from SystemConfiguration.
    enum ConnectionState: String, Sendable {
        case connected = "Connected"
        case connecting = "Connecting"
        case disconnecting = "Disconnecting"
        case disconnected = "Disconnected"
        case invalid = "Invalid"

        /// Definitely down — not merely between states (connecting, or an
        /// On-Demand reassert reported as connecting/disconnecting).
        var isDown: Bool { self == .disconnected || self == .invalid }
    }

    /// What NetFluss reads about one VPN service, in a single pass.
    struct ServiceSnapshot: Equatable, Sendable {
        let name: String
        /// The service ID, which `scutil --nc` and SCNetworkConnection accept.
        let serviceID: String
        /// Bundle identifier of the app providing a Network Extension VPN
        /// (e.g. "com.wireguard.macos"); nil for built-in IKEv2/L2TP services.
        let providerBundleID: String?
        let state: ConnectionState
        let isOnDemandEnabled: Bool
        /// On-Demand can only be toggled when rules are configured (in the
        /// WireGuard app: "On-Demand: Wi-Fi / Ethernet" in the tunnel editor).
        let hasOnDemandRules: Bool
    }

    /// `kSCNetworkInterfaceTypeVPN`, which the macOS SDK does not export: the
    /// type of every Network Extension VPN service, with the provider's bundle
    /// identifier as the type of the interface layered beneath it.
    private static let vpnInterfaceType = "VPN"

    /// Snapshots of the services named `names`, from one read of the network
    /// configuration. A fresh `SCPreferences` is created per call: it captures
    /// the configuration when created, and VPN apps change it underneath (the
    /// On-Demand flag whenever the WireGuard app saves a tunnel).
    static func snapshot(of names: Set<String>) -> [String: ServiceSnapshot] {
        guard !names.isEmpty,
              let preferences = SCPreferencesCreate(nil, "Netfluss.NativeVPN" as CFString, nil),
              let services = SCNetworkServiceCopyAll(preferences) as? [SCNetworkService] else {
            return [:]
        }
        var result: [String: ServiceSnapshot] = [:]
        for service in services {
            guard let name = SCNetworkServiceGetName(service) as String?, names.contains(name), result[name] == nil,
                  let serviceID = SCNetworkServiceGetServiceID(service) as String? else {
                continue
            }
            var provider: String?
            var configuration: [String: Any] = [:]
            if let interface = SCNetworkServiceGetInterface(service),
               SCNetworkInterfaceGetInterfaceType(interface) as String? == vpnInterfaceType {
                provider = SCNetworkInterfaceGetInterface(interface).flatMap { SCNetworkInterfaceGetInterfaceType($0) as String? }
                configuration = SCNetworkInterfaceGetConfiguration(interface) as? [String: Any] ?? [:]
            }
            result[name] = ServiceSnapshot(
                name: name,
                serviceID: serviceID,
                providerBundleID: provider,
                state: connectionState(serviceID: serviceID),
                isOnDemandEnabled: (configuration["OnDemandEnabled"] as? NSNumber)?.boolValue ?? false,
                hasOnDemandRules: !(configuration["OnDemandRules"] as? [Any] ?? []).isEmpty
            )
        }
        return result
    }

    static func snapshot(of name: String) -> ServiceSnapshot? {
        snapshot(of: [name])[name]
    }

    static func connectionState(serviceID: String) -> ConnectionState {
        guard let connection = SCNetworkConnectionCreateWithServiceID(nil, serviceID as CFString, nil, nil) else {
            return .invalid
        }
        switch SCNetworkConnectionGetStatus(connection) {
        case .connected: return .connected
        case .connecting: return .connecting
        case .disconnecting: return .disconnecting
        case .disconnected: return .disconnected
        default: return .invalid
        }
    }

    /// Live status of a connected service (addresses, DNS, …), as `scutil --nc
    /// status` prints under "Extended Status".
    static func extendedStatus(serviceID: String) -> [String: Any]? {
        guard let connection = SCNetworkConnectionCreateWithServiceID(nil, serviceID as CFString, nil, nil) else {
            return nil
        }
        return SCNetworkConnectionCopyExtendedStatus(connection) as? [String: Any]
    }

    /// Bytes received/sent by a connected service since it came up (what
    /// `scutil --nc statistics` prints). Network Extension VPNs report under
    /// "VPN", PPP-based ones under "PPP".
    static func byteCounts(serviceID: String) -> (bytesIn: UInt64, bytesOut: UInt64)? {
        guard let connection = SCNetworkConnectionCreateWithServiceID(nil, serviceID as CFString, nil, nil),
              let statistics = SCNetworkConnectionCopyStatistics(connection) as? [String: Any] else {
            return nil
        }
        for key in ["VPN", "PPP", "IPSec"] {
            if let counters = statistics[key] as? [String: Any],
               let bytesIn = (counters["BytesIn"] as? NSNumber)?.uint64Value,
               let bytesOut = (counters["BytesOut"] as? NSNumber)?.uint64Value {
                return (bytesIn, bytesOut)
            }
        }
        return nil
    }

    // MARK: scutil

    @discardableResult
    static func start(_ service: String) -> Bool {
        run(["--nc", "start", service]) != nil
    }

    @discardableResult
    static func stop(_ service: String) -> Bool {
        run(["--nc", "stop", service]) != nil
    }

    private static func run(_ args: [String]) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do { try process.run() } catch { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
