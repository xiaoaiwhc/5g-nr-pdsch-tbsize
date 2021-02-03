use std::convert::From;
use std::fmt;
use nom::{
    number::complete::{be_u24, be_u16, be_u8},
    {bytes::complete::take as nom_take, combinator::map as nom_map},
    {error::ParseError as NomParseError, IResult, error::context},
    {error::ErrorKind},
    ErrorConvert,
    {sequence::tuple as nom_tuple},
    multi::count as nom_count,
    bits::{complete::take as nom_bit_take, bits as nom_bits},
};
use crate::protocols::types;

const ECPRI_MAGIC_NUM: u16 = 0xAEFE;

// Use for U-plane and C-Plane
// eCPRI transport header also has another name: eCPRI common header
// EcpriCommonHeader takes 4 bytes totally
pub struct CommonHeader {
                        // The attribute of revision, reserved and concatenation altogather occupy 1 byte.
    pub revision: u8,   // Only the first 4 bits were used within one byte.
    pub reserved: u8,   // The next 3 bits were used behind the "version" attribute.
    pub concatenation: u8, // The next 1 bit was used behind the "reserved" attribute.
                           // C=0, indicates the eCPRI message is the last one inside the eCPRI PDU.
                           // C=1, indicates another eCPRI message follows this one within the eCPRI PDU.
    pub message_type: u8, // the eCPRI message type, 1 byte
    pub payload_size: u16, // The size in bytes of payload part corresponding the eCPRI message, 2 bytes
    pub pcid: u16,         // 2 bytes
    pub seqid: u16,        // 2 bytes
}

impl CommonHeader {
    pub fn parse(data: types::Input) -> types::Result<Self> {
        nom_map(
            nom_tuple((be_u8, be_u8, be_u16, be_u16, be_u16)),
            |(byte_u8, message_type, payload_size, pcid, seqid)| Self {
                revision: byte_u8 >> 4,
                reserved: (byte_u8 & 0xE0) >> 1,
                concatenation: byte_u8 & 0x01,
                message_type,
                payload_size,
                pcid,
                seqid,
            }
        )(data)
    }

    // The eAxC comprises data of one carrier related to one specific antenna (array)
    // pub fn get_eaxc_id(&self) -> usize {
    //     // the first 8 bit of seqid is the eAxC id
    //     // SequenceID: wrap-around individual per c_eAxC
    //     // Ebit: last message in subseq, for Application layer fragm, Ebit=1, SubseqID = 0
    //     // SubSequenceID: value = 0
    //     (self.seqid >> 8) as usize
    // }
}

impl fmt::Display for CommonHeader {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(
            w,
            "{:02X}, {:02X}, {:02X}, {:02X}, {:04X}, {:04X}, {:04X}",
                self.revision,
                self.reserved,
                self.concatenation,
                self.message_type,
                self.payload_size,
                self.pcid,
                self.seqid,
        )
    }
}

impl fmt::Debug for CommonHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

//Timing header fields:
//   :D (1bit), data direction
//   :Ver (3bit), value 1 set to indicate 1st protocol version 
//   :Filter index (4bit). This parameter defines an index to the channel filter to be used between IQ data and air interface, both in DL and UL
//   :frameID (8bit). This parameter is a counter for 10ms frames
//   :subframeID (4bit). This parameter is a counter for 1ms sub-frames within 10ms frame.
//   :slotID (6bit). This parameter is the slot number within a 1ms sub-frame.
//   :symbolID (6bit). This parameter identifies the first symbol number with slot, for which the information of this message is applied to.
//
// Common to all sections in packet
pub struct TimingHeader {
    pub dir: DataDirection,    // 1 bit
    pub payload_ver: u8,       // 3 bits    
    pub filter_index: FilterIndex,  // 4 bits
    pub frame_id: u8,          // 1 byte
    pub subframe_id: u8,       // 4 bits
    pub slot_id: u8,           // 6 bits
    pub start_symbol_id: u8,   // 6 bits
    pub num_of_sections: u8,   // 1 byte
    pub section_type: u8,      // section type = 0 for SectionType 0, 1 byte
}

impl TimingHeader {
    pub fn parse(data: types::Input) -> types::Result<Self> {
        nom_map(
            nom_tuple((be_u8, be_u8, be_u16, be_u8, be_u8)),
            |(byte_u8, frame_id, byte_u16, num_of_sections, section_type)| {
                // println!("data:\n {:02X}, {:02X}, {:04X}, {:02X}, {:02X}, filter index: {:02X}",
                //         byte_u8, frame_id, byte_u16, num_of_sections, section_type, byte_u8 & 0xF
                // );
                Self {
                    dir: DataDirection::from(byte_u8 >> 7),
                    payload_ver: (byte_u8 >> 4) & 0x7,
                    filter_index: FilterIndex::from(byte_u8 & 0x0F),
                    frame_id,
                    subframe_id: (byte_u16 >> 12) as u8,
                    slot_id: ((byte_u16 & 0x0FC0) >> 6) as u8,
                    start_symbol_id: (byte_u16 & 0x003F) as u8,
                    num_of_sections,
                    section_type
                }
            }
        )(data)
    }
}

impl fmt::Display for TimingHeader {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(
            w,
            "{}, {:02X}, {}, {:02X}, {:02X}, {:02X}, {:02X}",
                DataDirection::from(self.dir),
                self.payload_ver,
                FilterIndex::from(self.filter_index),
                self.frame_id,
                self.subframe_id,
                self.slot_id,
                self.start_symbol_id,
        )
    }
}

impl fmt::Debug for TimingHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// Take just 1 bit
#[derive(Clone, Copy)]
pub enum DataDirection {
    UL = 0,  // Rx/Ul = 0
    DL = 1,  // Tx/Dl = 1
}

impl From<u8> for DataDirection {
    fn from(item: u8) -> Self {
        match item {
            _ if item == Self::UL as u8 => Self::UL,
            _ if item == Self::DL as u8 => Self::DL,
            item => { panic!("DataDirection: {}, Error: Shouldn't come here.", item); },
        }
    }
}

impl fmt::Display for DataDirection {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(w, "{:?}", self)
    }
}

impl fmt::Debug for DataDirection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// Take 4 bits
#[derive(Clone, Copy)]
pub enum FilterIndex {
    NO_FILTER = 0,  // no filter = 0
    NR_PRACH = 3,   // NR PRACH Format A1,A2,....,C2 
}

impl From<u8> for FilterIndex {
    fn from(item: u8) -> Self {
        match item {
            _ if item == Self::NO_FILTER as u8 => Self::NO_FILTER,
            _ if item == Self::NR_PRACH as u8 => Self::NR_PRACH,
            item => { panic!("FilterIndex: {}, Error: Shouldn't come here.", item); },
        }
    }
}

impl fmt::Display for FilterIndex {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(w, "{:?}", self)
    }
}

impl fmt::Debug for FilterIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
///////////////////////////////

// Unused resource blocks or symbols in UL and DL
// Idle/guard periods
pub struct FCPSectionType0 {
    // pub comm_ctrl_info: TimingHeader,
    pub time_offset: u16,        // 2 bytes
    pub frame_structure: FrameStructure,   // 1 byte
    pub cp_length: u16,           // 2 bytes
    pub reserved: u8,            // 1 byte
    pub sections: Vec<_SectionType0Data>  // number of sections
}   

impl FCPSectionType0 {
    fn parse_without_sections(data: types::Input) -> types::Result<Self> {
        nom_map(
            nom_tuple((
                // TimingHeader::parse,
                be_u16,
                be_u8,
                be_u16,
                be_u8,
            )),
            |(/* comm_ctrl_info, */ time_offset, 
                frame_struct, cp_length, reserved
            )| Self {
                // comm_ctrl_info: comm_ctrl_info,
                time_offset,
                frame_structure: FrameStructure::from(frame_struct),
                cp_length,
                reserved,
                sections: Vec::new(),
            }
        )(data)
    }

    pub fn parse(data: types::Input, num_of_sections: usize) -> types::Result<Self> {
        let (remaining, mut section_type0) = FCPSectionType0::parse_without_sections(data)?;
        match nom_count(_SectionType0Data::parse, num_of_sections)(remaining) {
            Ok((remain, sections)) => {
                section_type0.sections = sections;
                Ok((remain, section_type0))
            },
            Err(e) => { Err(e)},
        }
        
    }
}

impl fmt::Display for FCPSectionType0 {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(
            w,
            // "{}, {:04X}, {}, {:04X}, {:02X}, {:?}",
            "{:04X}, {}, {:04X}, {:02X}, {:?}",
            // self.comm_ctrl_info,
            self.time_offset,
            self.frame_structure,
            self.cp_length,
            self.reserved,
            self.sections,
        )
    }
}

impl fmt::Debug for FCPSectionType0 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

//Section header (4, 5 or 6 bytes) fields:
// • SectionID (12bit). This parameter enumerates the section IDs within the Fast C-Plane message. The purpose of section ID is mapping of U-Plane messages to the corresponding Fast C-Plane message (and Section Type) associated with the data.
// • Rb (1bit). Resource block indicator. Used to indicate that every second PRBu available in packet. Example:
//      o RB=0, numPRB = 3 and startPRB=10    PRB#10, PRB#11, PRB#12
//      o RB=1, numPRB = 3 and startPRB=10    PRB#10, PRB#12, PRB#14   
//      o RB=1, numPRB = 3 and startPRB=11    PRB#11, PRB#13, PRB#15   
// • symInc (1bit). Symbol number increment command. Use prohibited in the U-plane.
// • startPrbu (10bit). starting PRB of user plane section
// • numPrbu (8bit). number of contiguous PRBs per control section
// • udCompHdr (8bit). PRB compression used (available at 5 or 6 bytes section header)
//      o udIqWidth (4bit). 0’d = 16bit I and Q, 1’d = 1bit I and Q, …,15’d = 15bit I and Q
//      o udCompMeth (4bit) 0’d = no compression (no padding & exp), 1’d = block floating point (1-byte padding & exp), 2’d = block scaling (1-byte padding & exp), 3’d = -law (1-byte padding & exp), 4’d = modulation compression (no udCompParam), 5/6/9/A/D/E/F’d = Nokia modulation compression (udCompParam byte included). Others values are reserved.

// U-Plane Section header
// Take 4,5,6 bytes
pub struct SectionHeader {
    section_id: u16,   // 12 bits
    rb: u8,            // 1 bit
    si: u8,           // si = symInc (symbol increment), occupy 1 bit
    start_prbc: u16,  // 10 bits
    num_prbc: u8,     // 1 byte
    ud_comp_hdr: Option<u8>,   // Optional item, if exits, 8 bits, not use for now
    reserved: Option<u8>       // Optional item, if exits, 8 bits, not use for now
}

impl SectionHeader {
    pub fn parse(data: types::Input) -> types::Result<Self> {
        nom_map(
            nom_tuple((be_u24, be_u8)),
            |(byte_u24, num_prbc)| Self {
                section_id: (byte_u24 >> 12) as u16,
                rb: ((byte_u24 >> 11) & 0x1) as u8,
                si: ((byte_u24 >> 10) & 0x1) as u8,
                start_prbc: ((byte_u24) & 0x3FF) as u16,
                num_prbc,
                ud_comp_hdr: None,
                reserved: None
            }
        )(data)
    }
}

impl fmt::Display for SectionHeader {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(
            w,
            "{:04X}, {:02X}, {:02X}, {:04X}, {:02X}",
            self.section_id,
            self.rb,
            self.si,
            self.start_prbc,
            self.num_prbc,
        )
    }
}

impl fmt::Debug for SectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub struct FrameStructure {
    fft_size: FFTSize,    // 4 bits
    mu: MU                // 4 bits
}

impl From<u8> for FrameStructure {
    fn from(item: u8) -> Self {
        Self {
            fft_size: FFTSize::from(item & 0xF0),
            mu: MU::from(item & 0x0F),
        }
    }
}

impl FrameStructure {
    pub fn parse(data: types::Input) -> types::Result<Self> {
        nom_map(
            be_u8,
            |byte_u8| Self {
                fft_size: FFTSize::from(byte_u8 >> 4),
                mu: MU::from(byte_u8 & 0x0F)
            }
        )(data)
    }
}

impl fmt::Display for FrameStructure {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(w, "{:?}", self)
    }
}

impl fmt::Debug for FrameStructure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub enum FFTSize {
    I_NONE = 0,
    RESERVED1 = 1,  // 1..7 reserved1
    I_256 = 8,
    I_512 = 9,
    I_1024 = 10,
    I_2048 = 11,
    I_4096 = 12,
    RESERVED2 = 13,  // 13..15 reserved2
}

impl From<u8> for FFTSize {
    fn from(item: u8) -> Self {
        match item {
            _ if item == Self::I_NONE as u8 => Self::I_NONE,
            _ if item >=1 && item <= 7 => Self::RESERVED1,
            _ if item == Self::I_256 as u8 => Self::I_256,
            _ if item == Self::I_512 as u8 => Self::I_512,
            _ if item == Self::I_1024 as u8 => Self::I_1024,
            _ if item == Self::I_2048 as u8 => Self::I_2048,
            _ if item == Self::I_4096 as u8 => Self::I_4096,
            _ if item >=13 && item <= 15 => Self::RESERVED2,
            _ => { panic!("FFTSize error: Shouldn't come here."); },
        }
    }
}

pub enum MU {
    KHZ_15 = 0,     // 0 - 15KHz
    KHZ_30 = 1,     // 1 - 30KHz/500us
    KHZ_60 = 2,     // 2 - 60KHz/250us
    KHZ_120 = 3,    // 3 - 120KHz/125us
    KHZ_240 = 4,    // 4 - 240KHz/62.5us
    KHZ_480 = 5,    // 5 - 480KHz/31.25us
    Reserved = 6,   // 6-11 
    KHZ_1_25 = 12,  // 12 - 1.25KHz
    KHZ_3_75 = 13,  // 13 - 3.75KHz
    KHZ_5 = 14,     // 14 - 5KHz
    KHZ_7_5 = 15    // 15 - 7.5KHz
}

impl From<u8> for MU {
    fn from(item: u8) -> Self {
        match item {
            _ if item == Self::KHZ_15 as u8 => Self::KHZ_15,
            _ if item == Self::KHZ_30 as u8 => Self::KHZ_30,
            _ if item == Self::KHZ_60 as u8 => Self::KHZ_60,
            _ if item == Self::KHZ_120 as u8 => Self::KHZ_120,
            _ if item == Self::KHZ_240 as u8 => Self::KHZ_240,
            _ if item == Self::KHZ_480 as u8 => Self::KHZ_480,
            _ if item >= 6 && item <= 11 => Self::Reserved,
            _ if item == Self::KHZ_1_25 as u8 => Self::KHZ_1_25,
            _ if item == Self::KHZ_3_75 as u8 => Self::KHZ_3_75,
            _ if item == Self::KHZ_5 as u8 => Self::KHZ_5,
            _ if item == Self::KHZ_7_5 as u8 => Self::KHZ_7_5,
            _ => { panic!("MU error: Shouldn't come here."); },
        }
    }
}

pub struct _SectionType0Data {
    pub section_hdr: SectionHeader,
    pub re_mask: u16,     // 12 bits 
    pub num_symbol: u8,  // 4 bits
    pub ef: u8, // ef = extension flag, 1 bit
    //////// not sure the "reserved" item takes 1 byte or 2 bytes
    pub reserved: u16,    // 15 bits
}

impl _SectionType0Data {
    pub fn parse(data: types::Input) -> types::Result<Self> {
        nom_map(
            nom_tuple((SectionHeader::parse,
                be_u16,
                be_u16,
            )),
            |(section_hdr, byte_u16_1, byte_u16_2)| Self {
                section_hdr,
                re_mask: (byte_u16_1 >> 4) as u16,
                num_symbol: (byte_u16_1 & 0x000F) as u8,
                ef: (byte_u16_2 >> 15) as u8,
                reserved: (byte_u16_2 & 0x7FFF) as u16
            }
        )(data)
    }
}

impl fmt::Display for _SectionType0Data {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(
            w,
            "{}, {:04X}, {:02X}, {:02X}, {:04X}",
            self.section_hdr,
            self.re_mask,
            self.num_symbol,
            self.ef,
            self.reserved,
        )
    }
}

impl fmt::Debug for _SectionType0Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// Regular channels using common common resource grid
// UL/DL fast associated control message(beamforming control)
pub type FCPSectionType2 = FCPSectionType1;
pub struct FCPSectionType1 {
    // pub comm_ctrl_info: TimingHeader,
    pub ud_comp_hdr: u8,         // 1 byte
    pub reserved: u8,            // 1 byte
    pub sections: Vec<_SectionType1Data>  // number of sections
}

impl FCPSectionType1 {
    fn parse_without_sections(data: types::Input) -> types::Result<Self> {
        nom_map(
            nom_tuple((
                // TimingHeader::parse,
                be_u8,
                be_u8,
            )),
            |(/* comm_ctrl_info, */ ud_comp_hdr, reserved)| Self {
                // comm_ctrl_info,
                ud_comp_hdr,
                reserved,
                sections: Vec::new(),
            }
        )(data)
    }

    pub fn parse(data: types::Input, num_of_sections: usize) -> types::Result<Self> {
        let (remaining, mut section_type1) = FCPSectionType1::parse_without_sections(data)?;
        // match nom_count(_SectionType1Data::parse, section_type1.comm_ctrl_info.num_of_sections as usize)(remaining) {
        match nom_count(_SectionType1Data::parse, num_of_sections)(remaining) {
            Ok((remain, sections)) => {
                section_type1.sections = sections;
                Ok((remain, section_type1))
            },
            Err(e) => { Err(e)},
        }
    }

}

impl fmt::Display for FCPSectionType1 {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(
            w,
            // "{}, {:02X}, {:02X}, {:?}",
            "{:02X}, {:02X}, {:?}",
            // self.comm_ctrl_info,
            self.ud_comp_hdr,
            self.reserved,
            self.sections,
        )
    }
}

impl fmt::Debug for FCPSectionType1 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub struct _SectionType1Data {
    pub section_hdr: SectionHeader,
    pub re_mask: u16,      // 12 bits
    pub num_symbol: u8,   // 4 bits
    pub ef: u8,           // ef = extension flag, 1 bit
    pub beam_id: u16      // 15 bits 
}

impl _SectionType1Data {
    pub fn parse(data: types::Input) -> types::Result<Self> {
        nom_map(
            nom_tuple((SectionHeader::parse,
                be_u16,
                be_u16,
            )),
            |(section_hdr, byte_u16_1, byte_u16_2)| Self {
                section_hdr,
                re_mask: (byte_u16_1 >> 4) as u16,
                num_symbol: (byte_u16_1 & 0x000F) as u8,
                ef: (byte_u16_2 >> 15) as u8,
                beam_id: (byte_u16_2 & 0x7FFF) as u16
            }
        )(data)
    }
}

impl fmt::Display for _SectionType1Data {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(
            w,
            "{}, {:04X}, {:02X}, {:02X}, {:04X}",
            self.section_hdr,
            self.re_mask,
            self.num_symbol,
            self.ef,
            self.beam_id,
        )
    }
}

impl fmt::Debug for _SectionType1Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// Specific channels not fitting common resource grid
// control of PRACH and mixed numerology channels
pub struct FCPSectionType3 {
    // pub comm_ctrl_info: TimingHeader,
    pub num_of_sections: u8,  // 1 byte
    pub section_type: u8,        // section type = 2 for SectionType 3, 1 byte
    pub time_offset: u16,        // 2 bytes
    pub frame_structure: FrameStructure,      // 1 byte
    pub cp_length: u16,          // 2 bytes
    pub ud_comp_hdr: u8,         // 1 byte
    pub sections: Vec<_SectionType3Data>  // number of sections
}

impl FCPSectionType3 {
    fn parse_without_sections(data: types::Input) -> types::Result<Self> {
        nom_map(
            nom_tuple((
                // TimingHeader::parse,
                be_u8,
                be_u8,
                be_u16,
                be_u8,
                be_u16,
                be_u8,
            )),
            |(/* comm_ctrl_info, */ num_of_sections, section_type,
                time_offset, byte_one, cp_length, ud_comp_hdr 
            )| Self {
                // comm_ctrl_info,
                num_of_sections,
                section_type,
                time_offset,
                frame_structure: FrameStructure::from(byte_one),
                cp_length,
                ud_comp_hdr,
                sections: Vec::new(),
            }
        )(data)
    }

    pub fn parse(data: types::Input) -> types::Result<Self> {
        let (remaining, mut section_type3) = FCPSectionType3::parse_without_sections(data)?;
        match nom_count(_SectionType3Data::parse, section_type3.num_of_sections as usize)(remaining) {
            Ok((remain, sections)) => {
                section_type3.sections = sections;
                Ok((remain, section_type3))
            },
            Err(e) => { Err(e)},
        }
    }

}

impl fmt::Display for FCPSectionType3 {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(
            w,
            // "{}, {:02X}, {:02X}, {:04X}, {:?}, {:04X}, {:02X}, {:?}",
            "{:02X}, {:02X}, {:04X}, {:?}, {:04X}, {:02X}, {:?}",
            // self.comm_ctrl_info,
            self.num_of_sections,
            self.section_type,
            self.time_offset,
            self.frame_structure,
            self.cp_length,
            self.ud_comp_hdr,
            self.sections,
        )
    }
}

impl fmt::Debug for FCPSectionType3 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub struct _SectionType3Data {
    ////// number of sections ///////
    pub section_hdr: SectionHeader,
    pub re_mask: u16,       // 12 bits
    pub num_symbol: u8,     // 4 bits
    pub ef: u8, // ef = extension flag
    pub beam_id: u16,       // 15 bits
    ///// For the following 2 items, not sure if only frequency_offset take 2 bytes
    ////  or the frequency_offset take only 1 byte and reserved take another 1 byte
    pub freq_offset: u16,  // 2 bytes
    pub reserved: u8,  // 8 bits
}

impl _SectionType3Data {
    pub fn parse(data: types::Input) -> types::Result<Self> {
        nom_map(
            nom_tuple((SectionHeader::parse,
                be_u16,
                be_u16,
                be_u16,
                be_u8
            )),
            |(section_hdr, byte_u16_1, byte_u16_2, freq_offset, reserved)| Self {
                section_hdr,
                re_mask: (byte_u16_1 >> 4) as u16,
                num_symbol: (byte_u16_1 & 0x000F) as u8,
                ef: (byte_u16_2 >> 15) as u8,
                beam_id: (byte_u16_2 & 0x7FFF) as u16,
                freq_offset,
                reserved
            }
        )(data)
    }
}

impl fmt::Display for _SectionType3Data {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(
            w,
            "{}, {:04X}, {:02X}, {:02X}, {:04X}, {:04X}, {:02X}",
            self.section_hdr,
            self.re_mask,
            self.num_symbol,
            self.ef,
            self.beam_id,
            self.freq_offset,
            self.reserved,
        )
    }
}

impl fmt::Debug for _SectionType3Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// IQ transport
pub struct UPlaneIQData {
    pub dir: DataDirection,    // 1 bit
    pub payload_ver: u8,       // 3 bits    
    pub filter_index: FilterIndex,  // 4 bits
    pub frame_id: u8,          // 1 byte
    pub subframe_id: u8,       // 4 bits
    pub slot_id: u8,           // 6 bits
    pub start_symbol_id: u8,   // 6 bits
    ////// number of sections ///////
    Here maybe contain more than one section!!! We can move the SectionHeader into IQPrbuData !!!
    also, the number of section will represent at related C-Plane message
    pub section_hdr: SectionHeader,
    pub iq_prbu: Vec<IQPrbuData>, // The size of IQPrbuData should be variable because of different mantissa size.
}

impl UPlaneIQData {
    fn parse_without_sections(data: types::Input) -> types::Result<Self> {
        nom_map(
            nom_tuple((
                be_u8, be_u8, be_u16,
                SectionHeader::parse,
            )),
            |(byte_u8, frame_id, byte_u16, section_hdr)| Self {
                dir: DataDirection::from(byte_u8 >> 7),
                payload_ver: (byte_u8 & 0x70) >> 4,
                filter_index: FilterIndex::from(byte_u8 & 0x0F),
                frame_id,
                subframe_id: (byte_u16 >> 12) as u8,
                slot_id: ((byte_u16 & 0x0FC0) >> 6) as u8,
                start_symbol_id: (byte_u16 & 0x003F) as u8,
                section_hdr,
                iq_prbu: Vec::new(),
            }
        )(data)
    }

    pub fn parse(data: types::Input, mantissa: u16) -> types::Result<Self> {
        let (remaining, mut up_data) = UPlaneIQData::parse_without_sections(data)?;
        let iq_prbu_parse_with_mantissa = |data| IQPrbuData::parse(data, mantissa);
        match nom_count(iq_prbu_parse_with_mantissa, up_data.section_hdr.num_prbc as usize)(remaining) {
            Ok((remain, iq_data)) => {
                up_data.iq_prbu = iq_data;
                Ok((remain, up_data))
            },
            Err(e) => { 
                Err(e)
             },
        }
    }

}

impl fmt::Display for UPlaneIQData {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(
            w,
            // "{}, {:02X}, {}, {:02X}, {:02X}, {:02X}, {:02X}, {}, {:?}",
            "{}, {:02X}, {}, {:02X}, {:02X}, {:02X}, {:02X}, {}",
            DataDirection::from(self.dir),
            self.payload_ver,
            FilterIndex::from(self.filter_index),
            self.frame_id,
            self.subframe_id,
            self.slot_id,
            self.start_symbol_id,
            self.section_hdr ,
            // self.iq_prbu,
        )
    }
}

impl fmt::Debug for UPlaneIQData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// PRB fiedls when using block floating point:
//      •Reserved/padding (4bit). Used for scale control in some Nokia systems
//      •Exponent for I & Q samples (4bit).
//      •INbit / QNbit I & Q samples. Number of bits is stream specific control.
/////////
//
// ORAN-WG4.CUS.0-v02.00:
// 
// 6.3.3.16 iSample (in-phase sample)
// Description: This parameter is the In-phase sample value.
// Value range: {all zeros – all ones}.
// Type: signed integer.
// Field length: 1-16 bits.
// 
// 6.3.3.17 qSample (quadrature sample)
// Description: This parameter is the Quadrature sample value.
// Value range: {all zeros – all ones}.
// Type: signed integer.
// Field length: 1-16 bits

pub struct IQPrbuData {
    pub reserved: u8,        // 4 bits
    pub exponent: u8,        // 4 bits
    // pub iq_sample: Vec<(u16, u16)>,  // the I/Q samples, 9b case, size: [(u16, u16); 12], 9 bits
    pub iq_sample: Vec<u8>,  // total 27 bytes, the I/Q samples, 9b case, size: [(u16, u16); 12], 9 bits
}

impl IQPrbuData {
    // For mantissa = 9, take total 27 bytes for IQ data:  (9 bits I + 9 bits Q) * 12
    fn _get_iq_samples(data: (&[u8], usize), mantissa: u16) -> IResult<(&[u8], usize), Vec<(i16, i16)>> {
        const RE_NUM: usize = 12;
        let mut iq_data = Vec::<(i16, i16)>::new();
        let mut remain = data;

        let modulo: i16 = 1 << mantissa;
        let max_value: i16 = (1 << (mantissa-1)) -1;

        for _ in 0..RE_NUM {
            let (other, i_real) = nom_bit_take(mantissa)(remain)?;
            let (other, q_imag) = nom_bit_take(mantissa)(other)?;
            let fix_two_complement = | i: i16 | {
                // The RE binary representation is 2's complement.
                if i < max_value { i } else { i - modulo }
            };
            iq_data.push((
                fix_two_complement(i_real), 
                fix_two_complement(q_imag)
            ));
            remain = other;
        }

        Ok((remain, iq_data))
    }

    pub fn get_iq_data<'a>(&'a self, mantissa: u16) -> IResult<&'a [u8], Vec<(i16, i16)>> {
        let parser = |data: (&'a [u8], usize)| { IQPrbuData::_get_iq_samples(data, mantissa) };
        nom_bits(parser)(&self.iq_sample[..])
    }

    pub fn parse(data: types::Input, mantissa: u16) -> types::Result<Self> {
        let iq_data_size = mantissa * 2 * 12 / 8;  // (I + Q) * mantissa * re_count / byte_len
        nom_map(
            nom_tuple((
                be_u8,
                // IQPrbuData::take_27_count,
                // IQPrbuData::take_1_prbu_data,
                nom_take(iq_data_size),
            )),
            |(byte_u8, iq_sample)| Self {
                reserved: (byte_u8 >> 4) as u8,
                exponent: (byte_u8 & 0x0F) as u8,
                iq_sample: iq_sample.to_vec(),
            }
        )(data)
    }
}

impl fmt::Display for IQPrbuData {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(
            w,
            "{:02X}, {:02X}, {:?}",
            self.reserved,
            self.exponent,
            self.iq_sample,
        )
    }
}

impl fmt::Debug for IQPrbuData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub enum MessageType {
    IQData = 0,
    BitSequence = 1,
    RealTimeControlData = 2,
    GenericDataTransfer = 3,
    RemoteMemoryAccess = 4,
    OneWayDelayMeasurement = 5,
    RemoteReset = 6,
    EventIndication = 7,
    IWFStartUp = 8,
    IWFOperation = 9,
    IWFMapping = 10,
    Reserved = 12,    // 12..63 reserved
    VendorSpecific = 64   // 64..225 vendor specific
}


impl From<u16> for MessageType {
    fn from(item: u16) -> Self {
        match item {
            _ if item == Self::IQData as u16 => Self::IQData,
            _ if item == Self::BitSequence as u16 => Self::BitSequence,
            _ if item == Self::RealTimeControlData as u16 => Self::RealTimeControlData,
            _ if item == Self::GenericDataTransfer as u16 => Self::GenericDataTransfer,
            _ if item == Self::RemoteMemoryAccess as u16 => Self::RemoteMemoryAccess,
            _ if item == Self::OneWayDelayMeasurement as u16 => Self::OneWayDelayMeasurement,
            _ if item == Self::RemoteReset as u16 => Self::RemoteReset,
            _ if item == Self::EventIndication as u16 => Self::EventIndication,
            _ if item == Self::IWFStartUp as u16 => Self::IWFStartUp,
            _ if item == Self::IWFOperation as u16 => Self::IWFOperation,
            _ if item == Self::IWFMapping as u16 => Self::IWFMapping,
            _ if item >= 12 && item <= 63 => Self::Reserved,
            _ if item >= 64 && item <= 225 => Self::VendorSpecific,
            _ => { panic!("MessageType error: Shouldn't come here."); },
        }
    }
}

//  | Preamble | Destination MAC Addr | Source MAC Addr |  VLAN Tag | Type/Length(EtherType) |        Payload        |    FCS    |    IFG     |
//  |(8 bytes) |      (6 bytes)       |     (6 bytes    | (4 bytes) |        (2 bytes)       |  (42 .. 1500 bytes)   | (4 bytes) | (12 bytes) |
//                                                                                          /                         \
//                                                                                      /                                \
//                                                                                 /                                        \
//                                                                             /                                                \
//                        | eCPRI Transport Header | eCPRI application header(s) | eCPRI application payload |
// The "eCPRI application header(s)" and "eCPRI application payload" depend on the message type                                                                     

#[derive(Debug)]
pub enum EcpriType {
    IQData(Box<UPlaneIQData>),
    FCPType0(Box<FCPSectionType0>),
    FCPType1(Box<FCPSectionType1>),
    // FCPType2(FCPSectionType2),
    FCPType3(Box<FCPSectionType3>),
}

pub fn is_ecpri_data(data: &[u8]) -> types::Result<bool> {
    nom_map(
        nom_tuple((
            be_u16,
            be_u16,
        )),
        |(_, magic_num)| magic_num == ECPRI_MAGIC_NUM,
    )(data)
}

// pub fn ecpri_parse(data: types::Input) -> types::Result<Self> {
pub fn ecpri_parse(data: &[u8], mantissa: u16) -> EcpriType {
    let msg_type: EcpriType;

    // check if the data is ecpri data
    let (remain, is_ecpri) = is_ecpri_data(&data).expect("Can't parse the ECPRI header.");
    if !is_ecpri {
        panic!("This is not a ecpri package.");
    }

    let (remain, header) = CommonHeader::parse(&remain).expect("Can't parse the ECPRI header.");
    match &header.message_type {
        0 => {  // U-Plane IQ data
            println!("U-Plane IQ data.");
            let (remain, iq_data) = UPlaneIQData::parse(&remain, mantissa).expect("Can't parse U-Plane IQ data.");
            // use hex_slice::AsHex;
            println!("IQ Prbu length: {}", iq_data.iq_prbu.len());
            // for prbu in iq_data.iq_prbu.iter() {
            //     println!("IQ data: {:?}", prbu);
            // }
            // println!("iq data: {:0X}", iq_data.as_hex());
            msg_type = EcpriType::IQData(Box::new(iq_data));
            // use std::mem;
            // println!("IQ data len: {}", mem::size_of::<UPlaneIQData>());
        },
        2 => {  // Fast-Control Plane
            let (remain, timing_header) = TimingHeader::parse(&remain).expect("Can't parse timing header of ECPRI.");
            match &timing_header.section_type {
                0 => {
                    println!("Idle/Guard periods.");
                    let (remain, fcp_sect_type0) = FCPSectionType0::parse(&remain, timing_header.num_of_sections as usize).expect("Can't parse FCP section type 0 data.");
                    msg_type = EcpriType::FCPType0(Box::new(fcp_sect_type0));
                },
                1 => {
                    println!("UL/DL channel.");
                    let (remain, fcp_sect_type1) = FCPSectionType1::parse(&remain, timing_header.num_of_sections as usize).expect("Can't parse FCP section type 1 data.");
                    msg_type = EcpriType::FCPType1(Box::new(fcp_sect_type1));
                },
                3 => {
                    println!("PRACH/mixed numerology channel.");
                    let (remain, fcp_sect_type3) = FCPSectionType3::parse(&remain).expect("Can't parse FCP section type 3 data.");
                    msg_type = EcpriType::FCPType3(Box::new(fcp_sect_type3));
                },
                item => { panic!("eCpri parse: timing header: section type: {} Shouldn't come here.", item); }
            }
        },
        _ => { panic!("eCpri parse: common header: Shouldn't come here."); }
    }

    msg_type
}