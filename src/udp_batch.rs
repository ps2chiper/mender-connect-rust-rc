use std::io;
use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant, timeout_at};

pub(crate) const FRAME: usize = 256 * 1024;
const DATAGRAM: usize = 65_507;
const COUNT: usize = 64;
const DELAY: Duration = Duration::from_millis(12);

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid UDP batch")
}

fn packets(frame: &[u8]) -> io::Result<(Duration, Vec<&[u8]>)> {
    if frame.len() < 4 || frame.len() > FRAME {
        return Err(invalid());
    }
    let (span, mut frame) = frame.split_at_checked(2).ok_or_else(invalid)?;
    let span = Duration::from_micros(u64::from(u16::from_be_bytes(
        span.try_into().map_err(|_| invalid())?,
    )));
    if span > DELAY {
        return Err(invalid());
    }
    let mut packets = Vec::new();
    while !frame.is_empty() {
        let (header, rest) = frame.split_at_checked(2).ok_or_else(invalid)?;
        let len = usize::from(u16::from_be_bytes(
            header.try_into().map_err(|_| invalid())?,
        ));
        if len > DATAGRAM || packets.len() == COUNT {
            return Err(invalid());
        }
        let (packet, tail) = rest.split_at_checked(len).ok_or_else(invalid)?;
        packets.push(packet);
        frame = tail;
    }
    Ok((span, packets))
}

// Commands can win the worker's select while a batch is filling. Keep every
// consumed datagram and the original flush deadline on the socket itself.
pub(crate) struct BatchUdp {
    socket: UdpSocket,
    scratch: Vec<u8>,
    pending: Vec<u8>,
    count: usize,
    deadline: Instant,
}
impl BatchUdp {
    pub(crate) fn new(socket: UdpSocket) -> Self {
        Self {
            socket,
            scratch: vec![0; DATAGRAM + 1],
            pending: Vec::new(),
            count: 0,
            deadline: Instant::now(),
        }
    }
    pub(crate) async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.count < COUNT && self.pending.len() + DATAGRAM + 2 <= FRAME {
            let n = if self.count == 0 {
                let n = self.socket.recv(&mut self.scratch).await?;
                self.deadline = Instant::now() + DELAY;
                self.pending.extend_from_slice(&[0, 0]);
                n
            } else {
                if Instant::now() >= self.deadline {
                    break;
                }
                match timeout_at(self.deadline, self.socket.recv(&mut self.scratch)).await {
                    Ok(result) => result?,
                    Err(_) => break,
                }
            };
            if n > DATAGRAM {
                return Err(invalid());
            }
            self.pending
                .extend_from_slice(&u16::try_from(n).map_err(|_| invalid())?.to_be_bytes());
            self.pending
                .extend_from_slice(self.scratch.get(..n).ok_or_else(invalid)?);
            self.count += 1;
        }
        let elapsed = Instant::now()
            .saturating_duration_since(self.deadline - DELAY)
            .min(DELAY);
        let micros = u16::try_from(elapsed.as_micros()).map_err(|_| invalid())?;
        self.pending
            .get_mut(..2)
            .ok_or_else(invalid)?
            .copy_from_slice(&micros.to_be_bytes());
        let n = self.pending.len();
        buf.get_mut(..n)
            .ok_or_else(invalid)?
            .copy_from_slice(&self.pending);
        self.pending.clear();
        self.count = 0;
        Ok(n)
    }
    pub(crate) async fn write(&self, frame: &[u8]) -> io::Result<()> {
        let (span, packets) = packets(frame)?;
        let total = u32::try_from(packets.len()).map_err(|_| invalid())?;
        let start = Instant::now();
        for (index, packet) in packets.into_iter().enumerate() {
            if index > 0 && index % 4 == 0 {
                let offset = span * u32::try_from(index).map_err(|_| invalid())? / (2 * total);
                tokio::time::sleep_until(start + offset).await;
            }
            if self.socket.send(packet).await? != packet.len() {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "short UDP send"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_empty_datagrams_and_rejects_malformed_batches() {
        assert_eq!(
            packets(&[0, 0, 0, 0, 0, 1, 42]).unwrap().1,
            vec![&[][..], &[42][..]]
        );
        for bad in [&[][..], &[0], &[0, 1, 42, 0], &[0, 2, 42], &[0; 132]] {
            assert!(packets(bad).is_err());
        }
    }
}
