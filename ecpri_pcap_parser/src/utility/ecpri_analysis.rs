use std::collections::BTreeMap;
use crate::protocols::{EcpriType, IQPrbuData};
use chrono::{DateTime, TimeZone, NaiveDateTime, Utc};
use ecpri_pcap_parser::{SectionHeader, CommonHeader};
use std::cmp;

#[derive(Debug)]
pub struct EcpriData {
    pub timestamp: DateTime<Utc>,    
    pub header: CommonHeader,
    pub data: EcpriType,
}

#[derive(Debug)]
pub struct Frame {
    pub pcid: u16,              // ecpriPCID
    pub frame_id: u8,
    pub subframe_id: u8,
    pub slot_id: u8,           // slot id
    pub slot_dir: u8,          // direction: UL/DL
    pub symb_id: u8,           // symbol id
    pub iq: Vec<(i32, i32)>,   // (i_data, q_data)
}

#[derive(Debug)]
pub struct EcpriDataVec (pub Vec<EcpriData>);

impl Default for EcpriDataVec {
    fn default() -> Self {
        let v = Vec::new();
        Self(v)
    }
}

impl EcpriDataVec {
    pub fn new() -> Self {
        EcpriDataVec::default()
    }

    pub fn append(&mut self, data: EcpriData) {
        self.0.push(data);
    }

    pub fn parse_iq_data(self, mantissa: u16) -> BTreeMap<(u16, u8, u8, u8, u8), Frame> {
        let mut frame_data = BTreeMap::new();
        for v in self.0.iter() {
            if let EcpriType::IQData(iq_data) = &v.data {
                let pcid = v.header.pcid;
                let frame_id = iq_data.frame_id;
                let subframe_id = iq_data.subframe_id;
                let slot_id = iq_data.slot_id;
                let symb_id = iq_data.start_symbol_id;
                let mut iq = EcpriDataVec::get_prbu_data(&iq_data.iq_prbu, mantissa);

                // frame_data.entry((frame_id, subframe_id, slot_id))
                //             .or_insert(Frame {
                //                 frame_id,
                //                 subframe_id,
                //                 slot_id,
                //                 slot_dir: iq_data.dir as u8,
                //                 iq: iq,
                //             });
                
                if !frame_data.contains_key(&(pcid, frame_id, subframe_id, slot_id, symb_id)) {
                    frame_data.insert((pcid, frame_id, subframe_id, slot_id, symb_id), 
                                    Frame {
                                                pcid,
                                                frame_id,
                                                subframe_id,
                                                slot_id,
                                                slot_dir: iq_data.dir as u8,
                                                symb_id,
                                                iq: iq,
                    });
                    println!("frame id: {}, subframe id: {}, slot id: {}, slot dir: {}, symb id: {}, one frame data len: {}", 
                              frame_id, subframe_id, slot_id, iq_data.dir as u8, symb_id, iq_data.iq_prbu.len());
                } else if let Some(frame) = frame_data.get_mut(&(pcid, frame_id, subframe_id, slot_id, symb_id)) {
                    frame.iq.append(&mut iq);
                    println!("frame id: {}, subframe id: {}, slot id: {}, slot dir: {}, symb id: {}, one frame data len: {}, (append)", 
                              frame_id, subframe_id, slot_id, iq_data.dir as u8, symb_id, iq_data.iq_prbu.len());
                }
            }
        }
        frame_data
    }

    fn get_prbu_data(prbu: &Vec<IQPrbuData>, mantissa: u16) -> Vec<(i32, i32)> {
        use std::cmp;
        let mut iq_data = Vec::with_capacity(50);  // Should not exceed 50 in one eth packet.
        for iq in prbu.iter() {
            // let exp = 2i16.pow(iq.exponent as u32) - 1;
            // let scale_exp = cmp::max((iq.exponent as i16) - mantissa as i16 + 1, 0_i16);
            let scale_exp = iq.exponent;
            let scaler = 2i16.pow(scale_exp as u32) - 1;
            let (_, _iq) = iq.get_iq_data(mantissa).expect("Failed to get prbu data.");
            // println!("exp: {}, IQ len: {}", scaler, _iq.len());
            let real_iq = _iq.iter()
                                               .map(|&d| ((d.0 * scaler) as i32, (d.1 * scaler) as i32))
                                               .collect::<Vec<_>>();
            iq_data.extend(real_iq.iter());
        }
        println!("prbu data len: {}", iq_data.len());
        iq_data
    }
}