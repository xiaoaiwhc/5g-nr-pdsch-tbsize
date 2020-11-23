//! PCAP file format
//!
//! See
//! [https://wiki.wireshark.org/Development/LibpcapFileFormat](https://wiki.wireshark.org/Development/LibpcapFileFormat)
//! for details.
//!
//! There are 2 main ways of parsing a PCAP file. The first method is to use
//! [`parse_pcap`](fn.parse_pcap.html). This method requires to load the entire
//! file to memory, and thus may not be good for large files.
//!
//! The [`PcapCapture`](struct.PcapCapture.html) implements the
//! [`Capture`](../trait.Capture.html) trait to provide generic methods. However,
//! this trait also reads the entire file.
//!
//! The second method is to first parse the PCAP header
//! using [`parse_pcap_header`](fn.parse_pcap_header.html), then
//! loop over [`parse_pcap_frame`](fn.parse_pcap_frame.html) to get the data.
//! This can be used in a streaming parser.

use crate::error::PcapError;
use crate::linktype::Linktype;
use nom::number::streaming::{be_i32, be_u16, be_u32, le_i32, le_u16, le_u32};
use nom::IResult;

/// PCAP global header
#[derive(Clone, Debug)]
pub struct PcapHeader {
    /// File format and byte ordering. If equal to `0xa1b2c3d4` then the rest of
    /// the file uses native byte ordering. If `0xd4c3b2a1` (swapped), then all
    /// following fields will have to be swapped too.
    pub magic_number: u32,
    /// Version major number (currently 2)
    pub version_major: u16,
    /// Version minor number (currently 4)
    pub version_minor: u16,
    /// The correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps
    pub thiszone: i32,
    /// In theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0
    pub sigfigs: u32,
    /// max len of captured packets, in octets
    pub snaplen: u32,
    /// Data link type
    pub network: Linktype,
}

impl PcapHeader {
    pub fn new() -> PcapHeader {
        PcapHeader {
            magic_number: 0xa1b2_c3d4, // native order
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 0,
            network: Linktype(1), // default: LINKTYPE_ETHERNET
        }
    }

    pub const fn size(&self) -> usize {
        24
    }

    pub fn is_bigendian(&self) -> bool {
        self.magic_number == 0xd4c3_b2a1
    }
}

impl Default for PcapHeader {
    fn default() -> Self {
        PcapHeader::new()
    }
}

/// Container for network data in legacy Pcap files
pub struct LegacyPcapBlock<'a> {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub caplen: u32,
    pub origlen: u32,
    pub data: &'a [u8],
}

/// Read a PCAP record header and data
///
/// Each PCAP record starts with a small header, and is followed by packet data.
/// The packet data format depends on the LinkType.
#[inline]
pub fn parse_pcap_frame(i: &[u8]) -> IResult<&[u8], LegacyPcapBlock, PcapError> {
    inner_parse_pcap_frame(i, false)
}

/// Read a PCAP record header and data (big-endian)
///
/// Each PCAP record starts with a small header, and is followed by packet data.
/// The packet data format depends on the LinkType.
#[inline]
pub fn parse_pcap_frame_be(i: &[u8]) -> IResult<&[u8], LegacyPcapBlock, PcapError> {
    inner_parse_pcap_frame(i, true)
}

fn inner_parse_pcap_frame(
    i: &[u8],
    big_endian: bool,
) -> IResult<&[u8], LegacyPcapBlock, PcapError> {
    let read_u32 = if big_endian { be_u32 } else { le_u32 };
    do_parse! {
        i,
        ts_sec: read_u32 >>
        ts_usec: read_u32 >>
        caplen: read_u32 >>
        origlen: read_u32 >>
        data: take!(caplen) >>
        (LegacyPcapBlock {
                ts_sec,
                ts_usec,
                caplen,
                origlen,
                data: data
            })
    }
}

/// Read the PCAP global header
///
/// The global header contains the PCAP description and options
pub fn parse_pcap_header(i: &[u8]) -> IResult<&[u8], PcapHeader, PcapError> {
    switch! {
        i,
        le_u32,
        0xa1b2_c3d4 => do_parse!(
            major:   le_u16 >>
            minor:   le_u16 >>
            zone:    le_i32 >>
            sigfigs: le_u32 >>
            snaplen: le_u32 >>
            network: le_i32 >>
            (
                PcapHeader {
                    magic_number: 0xa1b2_c3d4,
                    version_major: major,
                    version_minor: minor,
                    thiszone: zone,
                    sigfigs: sigfigs,
                    snaplen: snaplen,
                    network: Linktype(network)
                }
            )
        ) |
        0xd4c3_b2a1 => do_parse!(
            major:   be_u16 >>
            minor:   be_u16 >>
            zone:    be_i32 >>
            sigfigs: be_u32 >>
            snaplen: be_u32 >>
            network: be_i32 >>
            (
                PcapHeader {
                    magic_number: 0xd4c3_b2a1,
                    version_major: major,
                    version_minor: minor,
                    thiszone: zone,
                    sigfigs: sigfigs,
                    snaplen: snaplen,
                    network: Linktype(network)
                }
            )
        ) | 
        0xa1b2_3c4d => do_parse!(
            major:   le_u16 >>
            minor:   le_u16 >>
            zone:    le_i32 >>
            sigfigs: le_u32 >>
            snaplen: le_u32 >>
            network: le_i32 >>
            (
                PcapHeader {
                    magic_number: 0xa1b2_3c4d,
                    version_major: major,
                    version_minor: minor,
                    thiszone: zone,
                    sigfigs: sigfigs,
                    snaplen: snaplen,
                    network: Linktype(network)
                }
            )
        ) | 
        0x4d3c_b2a1 => do_parse!(
            major:   be_u16 >>
            minor:   be_u16 >>
            zone:    be_i32 >>
            sigfigs: be_u32 >>
            snaplen: be_u32 >>
            network: be_i32 >>
            (
                PcapHeader {
                    magic_number: 0x4d3c_b2a1,
                    version_major: major,
                    version_minor: minor,
                    thiszone: zone,
                    sigfigs: sigfigs,
                    snaplen: snaplen,
                    network: Linktype(network)
                }
            )
        )
    }
}

#[cfg(test)]
pub mod tests {
    use crate::pcap::{parse_pcap_frame, parse_pcap_header};
    use crate::traits::tests::FRAME_PCAP;
    // ntp.pcap header
    pub const PCAP_HDR: &[u8] = &hex!(
        "
D4 C3 B2 A1 02 00 04 00 00 00 00 00 00 00 00 00
00 00 04 00 01 00 00 00"
    );
    #[test]
    fn test_parse_pcap_header() {
        let (rem, hdr) = parse_pcap_header(PCAP_HDR).expect("header parsing failed");
        assert!(rem.is_empty());
        assert_eq!(hdr.magic_number, 0xa1b2_c3d4);
        assert_eq!(hdr.version_major, 2);
        assert_eq!(hdr.version_minor, 4);
        assert_eq!(hdr.snaplen, 262_144);
    }
    #[test]
    fn test_parse_pcap_frame() {
        let (rem, pkt) = parse_pcap_frame(FRAME_PCAP).expect("packet parsing failed");
        assert!(rem.is_empty());
        assert_eq!(pkt.origlen, 74);
        assert_eq!(pkt.ts_usec, 562_913);
        assert_eq!(pkt.ts_sec, 1_515_933_236);
    }
}
