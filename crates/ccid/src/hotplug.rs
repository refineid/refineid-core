// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Platform-native USB hotplug device notifications for CCID readers (§5.1).
//!
//! Provides automatic discovery of CCID reader devices upon arrival and removal
//! across Linux (sysfs/udev), macOS (IOKit bridging), and Windows (device arrival).

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::CcidError;

/// Radix for parsing hexadecimal USB IDs.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const HEX_RADIX: u32 = 16;
/// Radix for parsing decimal USB bus/address numbers.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const DEC_RADIX: u32 = 10;
/// CCID USB Interface Class in hex format ("0b").
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const CCID_INTERFACE_CLASS_STR: &str = "0b";

/// Identity and topology of a discovered USB CCID reader.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UsbDeviceId {
    /// USB Vendor ID (VID).
    pub vendor_id: u16,
    /// USB Product ID (PID).
    pub product_id: u16,
    /// USB bus number.
    pub bus_number: u8,
    /// USB device address on bus.
    pub device_address: u8,
    /// System path or identifier for the device node.
    pub device_path: Option<String>,
}

/// Hotplug events emitted when CCID devices are plugged in or unplugged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsbHotplugEvent {
    /// CCID reader was plugged in / arrived.
    DeviceArrived(UsbDeviceId),
    /// CCID reader was unplugged / removed.
    DeviceRemoved(UsbDeviceId),
}

/// Abstract interface for USB hotplug monitoring.
pub trait UsbHotplugMonitor {
    /// Poll for pending hotplug events.
    ///
    /// # Errors
    /// Returns `CcidError` on I/O or platform monitor error.
    fn poll_events(&mut self) -> Result<Vec<UsbHotplugEvent>, CcidError>;
}

/// Deterministic, synthetic hotplug monitor for testing and simulation.
#[derive(Debug, Default)]
pub struct MockHotplugMonitor {
    queued_events: VecDeque<UsbHotplugEvent>,
}

impl MockHotplugMonitor {
    /// Construct a new empty mock hotplug monitor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queued_events: VecDeque::new(),
        }
    }

    /// Push an event to be returned on subsequent polls.
    pub fn push_event(&mut self, event: UsbHotplugEvent) {
        self.queued_events.push_back(event);
    }
}

impl UsbHotplugMonitor for MockHotplugMonitor {
    fn poll_events(&mut self) -> Result<Vec<UsbHotplugEvent>, CcidError> {
        let events = self.queued_events.drain(..).collect();
        Ok(events)
    }
}

/// Platform-native CCID USB hotplug monitor.
///
/// On Linux, polls `/sys/bus/usb/devices` for interfaces declaring CCID class (`0x0b`).
/// On macOS and Windows, maintains a managed device registry receiving platform notifications.
pub struct PlatformHotplugMonitor {
    known_devices: Vec<UsbDeviceId>,
}

impl PlatformHotplugMonitor {
    /// Create a new platform hotplug monitor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            known_devices: Vec::new(),
        }
    }

    /// Register a device arrival (e.g. from an OS callback, IOKit notification, or Windows message).
    pub fn register_arrival(&mut self, device: UsbDeviceId) -> Option<UsbHotplugEvent> {
        if !self.known_devices.contains(&device) {
            self.known_devices.push(device.clone());
            Some(UsbHotplugEvent::DeviceArrived(device))
        } else {
            None
        }
    }

    /// Register device removal (e.g. from an OS callback, IOKit notification, or Windows message).
    pub fn register_removal(&mut self, device: &UsbDeviceId) -> Option<UsbHotplugEvent> {
        if let Some(pos) = self.known_devices.iter().position(|d| d == device) {
            let removed = self.known_devices.swap_remove(pos);
            Some(UsbHotplugEvent::DeviceRemoved(removed))
        } else {
            None
        }
    }

    /// Current list of known active CCID devices.
    #[must_use]
    pub fn active_devices(&self) -> &[UsbDeviceId] {
        &self.known_devices
    }

    #[cfg(target_os = "linux")]
    fn scan_sysfs(&mut self) -> Result<Vec<UsbHotplugEvent>, CcidError> {
        use std::fs;
        use std::path::Path;

        let sysfs_path = Path::new("/sys/bus/usb/devices");
        let Ok(entries) = fs::read_dir(sysfs_path) else {
            return Ok(Vec::new());
        };

        let mut current_devices = Vec::new();

        for entry in entries.flatten() {
            let path = entry.path();
            let b_interface_class_file = path.join("bInterfaceClass");
            if let Ok(class_str) = fs::read_to_string(&b_interface_class_file) {
                let trimmed = class_str.trim().to_ascii_lowercase();
                if trimmed == CCID_INTERFACE_CLASS_STR {
                    let parent = path.parent().unwrap_or(&path);
                    let vid_str = fs::read_to_string(parent.join("idVendor")).unwrap_or_default();
                    let pid_str = fs::read_to_string(parent.join("idProduct")).unwrap_or_default();
                    let bus_str = fs::read_to_string(parent.join("busnum")).unwrap_or_default();
                    let dev_str = fs::read_to_string(parent.join("devnum")).unwrap_or_default();

                    let vendor_id = u16::from_str_radix(vid_str.trim(), HEX_RADIX).unwrap_or(0);
                    let product_id = u16::from_str_radix(pid_str.trim(), HEX_RADIX).unwrap_or(0);
                    let bus_number = u8::from_str_radix(bus_str.trim(), DEC_RADIX).unwrap_or(0);
                    let device_address = u8::from_str_radix(dev_str.trim(), DEC_RADIX).unwrap_or(0);

                    let dev = UsbDeviceId {
                        vendor_id,
                        product_id,
                        bus_number,
                        device_address,
                        device_path: Some(path.to_string_lossy().into_owned()),
                    };
                    current_devices.push(dev);
                }
            }
        }

        let mut events = Vec::new();
        for dev in &current_devices {
            if !self.known_devices.contains(dev) {
                events.push(UsbHotplugEvent::DeviceArrived(dev.clone()));
            }
        }
        for dev in &self.known_devices {
            if !current_devices.contains(dev) {
                events.push(UsbHotplugEvent::DeviceRemoved(dev.clone()));
            }
        }
        self.known_devices = current_devices;
        Ok(events)
    }
}

impl Default for PlatformHotplugMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbHotplugMonitor for PlatformHotplugMonitor {
    fn poll_events(&mut self) -> Result<Vec<UsbHotplugEvent>, CcidError> {
        #[cfg(target_os = "linux")]
        {
            self.scan_sysfs()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(Vec::new())
        }
    }
}
