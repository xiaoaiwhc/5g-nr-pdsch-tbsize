extern crate ux;

use std::fmt;
use nom::number::streaming::{be_i32, be_u16, be_u32, le_i32, le_u16, le_u32};
use nom::{bytes::complete::take as nom_take, combinator::map as nom_map};
use nom::{error::ParseError, error::ErrorKind as NomErrorKind, IResult};
use nom::{sequence::tuple as nom_tuple};
use ux::*;
use std::mem;
use hex_literal;
use crate::protocols::types;


const BIP_MAGIC_NUMBER: u16 = 0x8951;

pub struct BIPHeader {
    pub msg_type: u8,   // Only last 4 bits were used
    pub stream_id: u16, // Only last 12 bits were used
    pub payload_size: u16,
    pub timestamp: u32,
}

impl BIPHeader {
    pub fn parse(i: types::Input) -> types::Result<Self> {
        let (_, msg_type) = be_u16::<()>(&i[..2]).expect("Can't parse the msg_type of BIPHeader.");
        let (_, payload_size) = be_u16::<()>(&i[2..4]).expect("Can't parse the payload_size of BIPHeader.");
        let (_, timestamp) = be_u32::<()>(&i[4..8]).expect("Can't parse the timestamp of BIPHeader");
        let stream_id = (msg_type & 0xFFFu16) as u16;
        let msg_type = (msg_type >> 12) as u8;

        Ok((
            &i[8..],
            Self{
            msg_type,
            stream_id,
            payload_size,
            timestamp}
        ))
    }

    pub fn is_bip_packet(i: types::Input) -> types::Result<u16> {
        let (remain_data, data_type) = be_u16::<()>(&i[..2]).expect("Can't parse the data_type from Ethernet package.");
        if data_type != BIP_MAGIC_NUMBER {
            let err_msg = types::ErrorKind::Context(format!("Unsupported data type: 0x{:02X}", data_type));
            let errors = vec![(remain_data, err_msg)];
            Err(nom::Err::Error(types::Error { errors }))
        } else {
            Ok((&i[2..], data_type))
        }
    }
}

impl fmt::Display for BIPHeader {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(
            w,
            "Type: {:01X}, Stream Id: {:01X}, Payload Size: {:02X}, Timestamp/Pointer: {:04X}",
            self.msg_type, self.stream_id, self.payload_size, self.timestamp
        )
    }
}

impl fmt::Debug for BIPHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub enum BIPType {
    ExtendedHeader = 0x0,
    Streaming_LTE_IQ = 0x1,
    EventChaining = 0x2,
    BICMP = 0x3,
    RMWA_22_bit = 0x4,
    RMWA_12_bit = 0x5,
    Reserved = 0x6 | 0x7
}

#[derive(Debug)]
pub enum ParseBIPError {
    NotBIPType(String),
    NotSupportType(String),
    UnknownError(String),
}

// For non-routable BIP type:
// For the type(4 bits): the first bit 0: 0 means BIP message, otherwise, RBIP
// the remaining 3 bits:
// BIP Type                Value
// Extended Header         0x0
// Streaming (LTE IQ)      0x1
// Event Chaining          0x2
// BICMP                   0x3
// RMWA 22-bit             0x4
// RMWA 12-bit             0x5
// Reserved                0x6 to 0x7
//
// Stream ID (12 bits):
// used to distingish between different streams/carriers/flows. The stream ID is unique per Type --
// Same ID can be used with different Type traffic flows. This field contains the DeviceID of the sender
// , which is composed of subset of the senders:
//     BIP Board ID: identify the board/unit/module types/indices
//     BIP Channel ID: identify the SoCs on boards/units/modules or core  clusters on SoCs. 
//
// Payload size (16 bits):
// provide the total size of the upper layer protocol message
//
// Timestamp/Pointer (32 bits):
// interpretation depends on the upper layer protocol type.
//////////////////////////////////////
//            |BIP Header (8 byte)|    Payload                             |
//            |-------------------|----------------------------------------
//           /                     \
//          /                        \\\\\\\\\\\\\\\\\\\\\                                                                        \
//        /                                               \\\\\\\\\\\
//       /                                                            \\\\\\\\\\\\\\\\\
//     |Type(4 bit)|StreamID(12 bit)|Payload size (16 bit)| Timestamp/Pointer (32 bit)|
//     |0         3|4             15|16                 31|32                       63|
//     |-----------|----------------|---------------------|---------------------------|
//     /           \
//    /             \
//   /               \
//  |0|SubType (3 bit)|

pub mod tests {
    use crate::protocols::bip::BIPHeader;
    pub const BIP_HDR: &[u8] = &hex_literal::hex!(
        "89 51 21 C5 02 3C"
    );

    #[test]
    fn parse_bip_header() {
        assert_eq!(BIPHeader::is_bip_packet(BIP_HDR).is_ok(), true);
    }
}
