use crate::blocks::PcapBlock;
use crate::capture_pcap::LegacyPcapReader;
use crate::capture_pcapng::PcapNGReader;
use crate::error::PcapError;
use crate::linktype::Linktype;
use crate::pcap::parse_pcap_header;
use crate::pcapng::parse_sectionheaderblock;
use crate::traits::PcapReaderIterator;
use circular::Buffer;
use std::io::Read;

/// Generic interface for PCAP or PCAPNG file access
pub trait Capture {
    fn get_datalink(&self) -> Linktype;

    fn get_snaplen(&self) -> u32;

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = PcapBlock> + 'a>;
}

/// Get a generic `PcapReaderIterator`, given a `Read` input. The input is probed for pcap-ng first,
/// then pcap.
///
/// ```rust
/// # extern crate nom;
/// # extern crate pcap_parser;
/// # use pcap_parser::*;
/// # use std::fs::File;
/// # use std::io::Read;
/// #
/// # fn main() {
/// # let path = "assets/ntp.pcap";
/// let mut file = File::open(path).expect("File open failed");
/// let mut reader = create_reader(65536, file).expect("LegacyPcapReader");
/// # }
/// ```
pub fn create_reader<'b, R>(
    capacity: usize,
    mut reader: R,
) -> Result<Box<dyn PcapReaderIterator<R> + 'b>, PcapError>
where
    R: Read + 'b,
{
    let mut buffer = Buffer::with_capacity(capacity);
    let sz = reader.read(buffer.space()).or(Err(PcapError::ReadError))?;
    buffer.fill(sz);
    // just check that first block is a valid one
    if parse_sectionheaderblock(buffer.data()).is_ok() {
        PcapNGReader::from_buffer(buffer, reader)
            .map(|r| Box::new(r) as Box<dyn PcapReaderIterator<R>>)
    } else if parse_pcap_header(buffer.data()).is_ok() {
        LegacyPcapReader::from_buffer(buffer, reader)
            .map(|r| Box::new(r) as Box<dyn PcapReaderIterator<R>>)
    } else {
        Err(PcapError::HeaderNotRecognized)
    }
}
