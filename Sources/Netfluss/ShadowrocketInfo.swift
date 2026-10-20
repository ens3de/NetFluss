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

/// The node and global routing mode Shadowrocket is using, for display next to
/// its system VPN service.
///
/// Shadowrocket exposes neither through an API (its "VPN Status" Shortcuts
/// action only reports whether it is connected), so they are read from its
/// shared app-group preferences. macOS guards other apps' group containers:
/// the first read asks the user to let NetFluss access Shadowrocket's data, and
/// until then — or if a Shadowrocket update renames the keys — this yields nil
/// and the popover simply shows nothing extra.
struct ShadowrocketInfo: Equatable, Sendable {
    let serverName: String?
    /// Raw `GlobalRoutingMethod` value as Shadowrocket stores it.
    let routingMethod: String?

    static let bundleIdentifier = "com.liguangming.Shadowrocket"

    private static let preferencesPath = NSHomeDirectory()
        + "/Library/Group Containers/group.com.liguangming.Shadowrocket"
        + "/Library/Preferences/group.com.liguangming.Shadowrocket.plist"

    static func read() -> ShadowrocketInfo? {
        guard let data = FileManager.default.contents(atPath: preferencesPath),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            return nil
        }
        let info = ShadowrocketInfo(
            serverName: plist["group.com.liguangming.SelectedServerName"] as? String,
            routingMethod: plist["group.com.liguangming.GlobalRoutingMethod"] as? String
        )
        return info.serverName == nil && info.routingMethod == nil ? nil : info
    }

    /// Localized name of the routing mode. Shadowrocket's own modes are Config,
    /// Proxy, Direct and Scene; anything else is shown as stored.
    var routingDisplayName: String? {
        guard let routingMethod, !routingMethod.isEmpty else { return nil }
        let value = routingMethod.lowercased()
        for (needle, name) in [("config", "Config"), ("proxy", "Proxy"), ("direct", "Direct"), ("scene", "Scene")]
            where value.contains(needle) {
            return L10n.text(name)
        }
        return routingMethod
    }
}
