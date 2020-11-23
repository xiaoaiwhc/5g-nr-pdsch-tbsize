use std::fmt;
use nom::number::complete::be_u16;
use nom::{bytes::complete::take as nom_take, combinator::map as nom_map};
use nom::{error::ParseError, IResult, error::context};
use nom::{sequence::tuple as nom_tuple};
use crate::protocols::types;
use std::convert::TryFrom;
use std::convert::From;


pub struct Ethernet {
    pub dst_mac_addr: MacAddr,
    pub src_mac_addr: MacAddr,
    pub ether_type: u16,
}

#[derive(Debug)]
pub enum PacketDataType {
    BIP = 0x8951,
    ECPRI = 0x8100,
    PTP = 0x88F7,
    UNKNOWN = 0x0
}

impl PacketDataType {
    pub fn value(&self) -> &'static str {
        match *self {
            PacketDataType::BIP => "BIP",
            PacketDataType::ECPRI => "eCPRI",
            PacketDataType::PTP => "PTPv2",
            PacketDataType::UNKNOWN => "Unknown"
        }
    }
}

impl From<u16> for PacketDataType {
    fn from(item: u16) -> Self {
        match item {
            _ if item == Self::BIP as u16 => Self::BIP,
            _ if item == Self::ECPRI as u16 => Self::ECPRI,
            _ if item == Self::PTP as u16 => Self::PTP,
            _ => Self::UNKNOWN,
        }
    }
}

// impl TryFrom<u16> for PacketDataType {
//     type Error = ();
//     fn try_from(v: u16) -> Result<Self, Self::Error> {
//         match v {
//             _ if v == Self::BIP as u16 => Ok(Self::BIP),
//             _ if v == Self::ECPRI as u16 => Ok(Self::ECPRI),
//             _ if v == Self::PTP as u16 => Ok(Self::PTP),
//             _ if v == Self::UNKNOWN as u16 => Ok(Self::UNKNOWN),
//             _ => Err(())
//         }
//     }
// }

impl Ethernet {
    pub fn parse(i: types::Input) -> types::Result<Self> {
        // let (_, dst_mac_addr) = MacAddr::parse(&i[0..]).expect("Can't parse the dst mac address.");
        // let (_, src_mac_addr) = MacAddr::parse(&i[6..]).expect("Can't parse the src mac address.");
        // let (_, ether_type) = be_u16::<()>(&i[12..14]).expect("Can't get the ehternet type.");

        // Self{
        //     dst_mac_addr,
        //     src_mac_addr,
        //     ether_type
        // }
        nom_map(
            nom_tuple((MacAddr::parse, MacAddr::parse, be_u16)),
            |(dst_mac_addr, src_mac_addr, ether_type)| Self {
                dst_mac_addr,
                src_mac_addr,
                ether_type
            }
        )(i)
    }
}

pub struct MacAddr([u8; 6]);

impl fmt::Display for MacAddr{
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        let [a1, b1, c1, d1, e1, f1] = self.0;
        write!(
            w,
            "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
            a1, b1, c1, d1, e1, f1
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl MacAddr {
    pub fn new(data: &[u8]) -> Self {
        let mut addr = Self([0u8; 6]);
        // the length of data have to be equal to/greater than 6.
        addr.0.copy_from_slice(&data[..6]);
        addr 
    }

    pub fn parse(i: types::Input) -> types::Result<Self> 
    {
        nom_map(nom_take(6_usize), Self::new)(i)
    }
}