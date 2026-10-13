//! Narrow packet broker. Only this executable needs Bluetooth capabilities.
#[cfg(any(target_os = "linux", test))]
mod diagnostics {
    use std::time::Instant;

    /// Metadata only. Called after a successful socket send/receive, never before.
    pub(super) struct Trace {
        started: Instant,
        pairing: bool,
    }

    impl Trace {
        pub(super) fn new() -> Self {
            Self {
                started: Instant::now(),
                pairing: false,
            }
        }

        pub(super) fn observe(&mut self, packet: &[u8], outgoing: bool) -> Option<String> {
            let detail = match packet.first()? {
                2 if packet.len() >= 9
                    && packet.len() == 5 + u16::from_le_bytes([packet[3], packet[4]]) as usize =>
                {
                    let pb = (packet[2] >> 4) & 3;
                    if pb != 0 && pb != 2 {
                        return None;
                    }
                    let cid = u16::from_le_bytes([packet[7], packet[8]]);
                    if cid != 6 && cid != 7 {
                        return None;
                    }
                    let opcode = packet
                        .get(9)
                        .map(|value| format!("0x{value:02X}"))
                        .unwrap_or_else(|| "none".into());
                    if matches!(packet.get(9), Some(1 | 2)) {
                        self.pairing = true;
                    }
                    if packet.get(9) == Some(&5) {
                        self.pairing = false;
                    }
                    format!("ACL cid=0x{cid:04X} pb={pb} opcode={opcode}")
                }
                4 if !outgoing && packet.len() >= 3 && packet.len() == 3 + packet[2] as usize => {
                    let code = packet[1];
                    if !matches!(code, 0x10 | 0x1A)
                        && !(self.pairing && matches!(code, 0x05 | 0x08 | 0x13 | 0x59))
                    {
                        return None;
                    }
                    if matches!(code, 0x05 | 0x08 | 0x59) {
                        self.pairing = false;
                    }
                    format!("EVENT code=0x{code:02X}")
                }
                1 if outgoing && packet.len() >= 4 && packet.len() == 4 + packet[3] as usize => {
                    let opcode = u16::from_le_bytes([packet[1], packet[2]]);
                    if opcode != 0x2019 {
                        return None;
                    }
                    format!("COMMAND opcode=0x{opcode:04X}")
                }
                _ => return None,
            };
            Some(format!(
                "HCI_BROKER_V1:{} {detail} bytes={} elapsedMs={}",
                if outgoing { "TX" } else { "RX" },
                packet.len(),
                self.started.elapsed().as_millis()
            ))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn smp(opcode: u8) -> Vec<u8> {
            vec![2, 0x42, 0, 6, 0, 2, 0, 6, 0, opcode, 0x2d]
        }

        #[test]
        fn logs_smp_metadata_without_addresses_or_payloads() {
            let mut trace = Trace::new();
            let line = trace.observe(&smp(1), true).unwrap();
            assert!(line.starts_with(
                "HCI_BROKER_V1:TX ACL cid=0x0006 pb=0 opcode=0x01 bytes=11 elapsedMs="
            ));
            assert!(!line.contains("2D"));
            let mut key = smp(0x0c);
            key.resize(74, 0x7e);
            key[3] = 69;
            let line = trace.observe(&key, false).unwrap();
            assert!(line.contains("RX ACL"));
            assert!(!line.contains("7E"));
        }

        #[test]
        fn tracks_completion_events_only_during_negotiation() {
            let mut trace = Trace::new();
            let completion = [4, 0x13, 5, 1, 0x42, 0, 1, 0];
            assert!(trace.observe(&completion, false).is_none());
            trace.observe(&smp(1), true);
            assert!(
                trace
                    .observe(&completion, false)
                    .unwrap()
                    .contains("EVENT code=0x13")
            );
            assert!(trace.observe(&[4, 8, 4, 0, 0x42, 0, 1], false).is_some());
            assert!(trace.observe(&completion, false).is_none());
        }

        #[test]
        fn encryption_command_never_logs_ltk() {
            let mut trace = Trace::new();
            let mut command = vec![1, 0x19, 0x20, 28];
            command.resize(32, 0xa5);
            let line = trace.observe(&command, true).unwrap();
            assert!(line.contains("COMMAND opcode=0x2019"));
            assert!(!line.contains("A5"));
        }

        #[test]
        fn ignores_unrelated_and_malformed_packets() {
            let mut trace = Trace::new();
            for packet in [&[][..], &[2, 0, 0][..], &[4, 8, 9][..], &[1, 3, 12, 0][..]] {
                assert!(trace.observe(packet, true).is_none());
            }
            let mut packet = smp(1);
            packet[7] = 0x40;
            assert!(trace.observe(&packet, true).is_none());
            packet[7] = 6;
            packet[2] = 0x10; // continuation bytes are not a new L2CAP header
            assert!(trace.observe(&packet, false).is_none());
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::diagnostics::Trace;
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    #[repr(C)]
    struct HciAddress {
        family: u16,
        device: u16,
        channel: u16,
    }

    fn valid_packet(packet: &[u8], outgoing: bool) -> bool {
        match packet.first() {
            Some(1) if outgoing => packet.len() >= 4 && packet.len() == 4 + packet[3] as usize,
            Some(2) => {
                packet.len() >= 5
                    && packet.len() == 5 + u16::from_le_bytes([packet[3], packet[4]]) as usize
            }
            Some(4) if !outgoing => packet.len() >= 3 && packet.len() == 3 + packet[2] as usize,
            _ => false,
        }
    }
    fn unbuffered_input(fd: i32) -> io::Result<std::fs::File> {
        // The duplicate is owned here; closing it never closes the caller's fd.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(std::fs::File::from(unsafe {
            OwnedFd::from_raw_fd(duplicate)
        }))
    }
    pub fn run() -> io::Result<()> {
        let index = std::env::args()
            .nth(1)
            .ok_or_else(|| io::Error::other("Missing controller index"))?;
        let device = index
            .parse::<u16>()
            .map_err(|_| io::Error::other("Invalid controller index"))?;
        if device == u16::MAX {
            return Err(io::Error::other("Invalid controller index"));
        }
        // Linux UAPI sockaddr_hci and HCI_CHANNEL_USER. A failed bind never
        // downgrades to shared RAW ownership; bluetoothd must release this adapter.
        let raw = unsafe { libc::socket(31, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 1) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let address = HciAddress {
            family: 31,
            device,
            channel: 1,
        };
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const HciAddress).cast(),
                std::mem::size_of::<HciAddress>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        // StdinLock uses an internal buffer. It can prefetch the next envelope,
        // making poll(0) see an empty pipe while an ACL continuation remains
        // buffered forever. Read directly from a duplicated fd with no read-ahead.
        let mut input = unbuffered_input(0)?;
        let mut output = io::stdout().lock();
        output.write_all(&[0, 1, 0])?;
        output.flush()?;
        let mut trace = Trace::new();
        let mut packet = vec![0_u8; 65535];
        loop {
            let mut fds = [
                libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: 0,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let result = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                let mut header = [0; 2];
                match input.read_exact(&mut header) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                    Err(error) => return Err(error),
                }
                let length = u16::from_be_bytes(header) as usize;
                input.read_exact(&mut packet[..length])?;
                if !valid_packet(&packet[..length], true) {
                    return Err(io::Error::other("Invalid outbound H4 packet"));
                }
                let count = unsafe {
                    libc::send(
                        fd.as_raw_fd(),
                        packet.as_ptr().cast(),
                        length,
                        libc::MSG_NOSIGNAL,
                    )
                };
                if count != length as isize {
                    return Err(io::Error::last_os_error());
                }
                if let Some(metadata) = trace.observe(&packet[..length], true) {
                    eprintln!("{metadata}");
                }
            }
            if fds[0].revents & libc::POLLIN != 0 {
                let count = unsafe {
                    libc::recv(fd.as_raw_fd(), packet.as_mut_ptr().cast(), packet.len(), 0)
                };
                if count <= 0 {
                    return Err(io::Error::last_os_error());
                }
                let length = count as usize;
                if valid_packet(&packet[..length], false) {
                    if let Some(metadata) = trace.observe(&packet[..length], false) {
                        eprintln!("{metadata}");
                    }
                    output.write_all(&(length as u16).to_be_bytes())?;
                    output.write_all(&packet[..length])?;
                    output.flush()?;
                }
            }
            if fds[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(io::Error::other("Controller disconnected"));
            }
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn coalesced_envelopes_remain_visible_to_poll() {
            let (read, mut write) = std::os::unix::net::UnixStream::pair().unwrap();
            let mut input = unbuffered_input(read.as_raw_fd()).unwrap();
            write
                .write_all(&[0, 4, 1, 3, 12, 0, 0, 4, 1, 3, 12, 0])
                .unwrap();
            let mut first = [0; 6];
            input.read_exact(&mut first).unwrap();
            let mut pending = libc::pollfd {
                fd: read.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut pending, 1, 0) }, 1);
            let mut second = [0; 6];
            input.read_exact(&mut second).unwrap();
            assert_eq!(first, second);
        }
        #[test]
        fn packet_boundary_rejects_truncation_and_wrong_direction() {
            assert!(valid_packet(&[1, 3, 12, 0], true));
            assert!(!valid_packet(&[1, 3, 12, 0], false));
            assert!(valid_packet(&[2, 1, 0, 2, 0, 0xaa, 0xbb], true));
            assert!(!valid_packet(&[2, 1, 0, 2, 0, 0xaa], true));
            assert!(valid_packet(&[4, 14, 1, 0], false));
            assert!(!valid_packet(&[4, 14, 1, 0], true));
            assert!(!valid_packet(&[], true));
        }
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = platform::run() {
        eprintln!("Linux HCI lease failed: {error}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("HCI user channel requires Linux");
        std::process::exit(1);
    }
}
