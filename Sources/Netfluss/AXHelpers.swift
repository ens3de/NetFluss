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

import ApplicationServices
import Foundation

/// Small Accessibility helpers for driving another app's menu bar item (the
/// WireGuard app's menu). All calls block; use them off the main thread.
enum AX {
    /// Whether NetFluss may drive other apps. `prompt` shows the system's
    /// Accessibility request when access has not been granted yet.
    static func isTrusted(prompt: Bool) -> Bool {
        let key = kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String
        return AXIsProcessTrustedWithOptions([key: prompt] as CFDictionary)
    }

    static func attribute(_ element: AXUIElement?, _ name: String) -> AnyObject? {
        guard let element else { return nil }
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, name as CFString, &value) == .success else { return nil }
        return value
    }

    /// Several attributes in one round trip; a missing one comes back as an
    /// AXValue error, which the casts at the call site treat as nil.
    static func attributes(_ element: AXUIElement, _ names: [String]) -> [AnyObject] {
        var values: CFArray?
        guard AXUIElementCopyMultipleAttributeValues(element, names as CFArray, [], &values) == .success else {
            return []
        }
        return values as [AnyObject]? ?? []
    }

    static func children(of element: AnyObject?) -> [AXUIElement] {
        guard let element, CFGetTypeID(element) == AXUIElementGetTypeID() else { return [] }
        // swiftlint:disable:next force_cast
        return attribute((element as! AXUIElement), kAXChildrenAttribute) as? [AXUIElement] ?? []
    }

    /// Presses `element` without waiting for the app's reply. A menu bar item
    /// or menu entry often replies only once its menu closes or its handler
    /// ran; the press is delivered regardless.
    @discardableResult
    static func pressWithoutWaiting(_ element: AXUIElement) -> AXError {
        AXUIElementSetMessagingTimeout(element, 0.05)
        return AXUIElementPerformAction(element, kAXPressAction as CFString)
    }

    static func waitFor<T>(timeout: TimeInterval, _ probe: () -> T?) -> T? {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            if let value = probe() { return value }
            Thread.sleep(forTimeInterval: 0.02)
        } while Date() < deadline
        return nil
    }
}
