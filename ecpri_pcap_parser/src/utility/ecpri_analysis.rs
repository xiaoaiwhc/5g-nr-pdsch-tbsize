use std::collections::BTreeMap;
use crate::protocols::{SupportedType, IQPrbuData};
use chrono::{DateTime, TimeZone, NaiveDateTime, Utc};
use std::cmp;

#[derive(Debug)]
pub struct EcpriData {
    pub timestamp: DateTime<Utc>,    
    pub data: SupportedType,
}

#[derive(Debug)]
pub struct Frame {
    pub frame_id: u8,
    pub subframe_id: u8,
    pub slot_id: u8,           // slot id
    pub slot_dir: u8,          // direction: UL/DL
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

    pub fn parse_iq_data(self) -> BTreeMap<(u8, u8, u8), Frame> {
        let mut frame_data = BTreeMap::new();
        for v in self.0.iter() {
            if let SupportedType::IQData(iq_data) = &v.data {
                let frame_id = iq_data.frame_id;
                let subframe_id = iq_data.subframe_id;
                let slot_id = iq_data.slot_id;
                let mut iq = EcpriDataVec::get_prbu_data(&iq_data.iq_prbu);

                // frame_data.entry((frame_id, subframe_id, slot_id))
                //             .or_insert(Frame {
                //                 frame_id,
                //                 subframe_id,
                //                 slot_id,
                //                 slot_dir: iq_data.dir as u8,
                //                 iq: iq,
                //             });
                
                if !frame_data.contains_key(&(frame_id, subframe_id, slot_id)) {
                    frame_data.insert((frame_id, subframe_id, slot_id), 
                                    Frame {
                                                frame_id,
                                                subframe_id,
                                                slot_id,
                                                slot_dir: iq_data.dir as u8,
                                                iq: iq,
                    });
                } else if let Some(frame) = frame_data.get_mut(&(frame_id, subframe_id, slot_id)) {
                    frame.iq.append(&mut iq);
                }
            }
        }
        frame_data
    }

    fn get_prbu_data(prbu: &Vec<IQPrbuData>) -> Vec<(i32, i32)> {
        let mut iq_data = Vec::new();
        for iq in prbu.iter() {
            let exp = 2i16.pow(iq.exponent as u32) - 1;
            let (_, _iq) = IQPrbuData::take_prbu_data(&iq.iq_sample).expect("Failed to get prbu data.");
            let real_iq = _iq.iter()
                                               .map(|&d| ((d.0 * exp) as i32, (d.1 * exp) as i32))
                                               .collect::<Vec<_>>();
            iq_data.extend(real_iq.iter());
        }
        iq_data
    }
}