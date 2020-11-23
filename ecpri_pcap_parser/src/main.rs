use std::env;
use std::fs::File;
use std::io::{BufWriter, prelude::*};
use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
mod protocols;
use crate::protocols::{ethernet::Ethernet, ethernet::PacketDataType, bip::BIPHeader};
use crate::protocols::{ecpri::ecpri_parse, SupportedType};
use chrono::{DateTime, TimeZone, NaiveDateTime, Utc};
mod utility;
use utility::ecpri_analysis::{EcpriDataVec, EcpriData};

fn main() ->std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        println!("Pcap file name: {}", &args[1]);
    } else {
        println!("Please input the pcap file.");
        return Ok(());
    }

    let cur_dir = env::current_dir().expect("Can't get current path.");
    let path = cur_dir.join(&args[1]);
    let file = File::open(path).unwrap();
    let mut num_blocks = 0;
    let meta = file.metadata()?;
    let size = meta.len() as usize;

    let mut num_blocks = 0;
    let mut reader = LegacyPcapReader::new(size, file).expect("LegacyPcapReader failed.");

    // initial file to save iq data
    let iq_file = File::create("iq_data.txt")?;
    let mut buf_writer = BufWriter::new(iq_file);

    let mut ecpri_data = EcpriDataVec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(_) => (),
                    PcapBlockOwned::Legacy(b) => {
                        let date_time = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(b.ts_sec as i64, b.ts_usec), Utc);
                        println!("date time: {}, caplen: {}, origlen: {}",
                        date_time, b.caplen, b.origlen);
                        let (ether_data, ether_header)= Ethernet::parse(&b.data).expect("Can't parse the ethernet package.");
                        println!(
                            "dst: {}, src: {}, ether type: 0x{:02X}", 
                            ether_header.dst_mac_addr, ether_header.src_mac_addr, ether_header.ether_type
                        );
                        match PacketDataType::from(ether_header.ether_type) {
                            PacketDataType::BIP => {
                                let (bip_data, bip_header) = BIPHeader::parse(&ether_data).expect("Can't parse the BIP package.");
                                use hex_slice::AsHex;
                                println!(
                                    "msg_type: 0x{:01X}, stream_id: {}, payload_size: {}, timpstamp/pointer: 0x{:X}",
                                    bip_header.msg_type, bip_header.stream_id, bip_header.payload_size, bip_header.timestamp
                                );
                                println!("data:\n {:02X}", bip_data.as_hex());

                            },
                            PacketDataType::PTP => {
                                unimplemented!()
                            },
                            PacketDataType::ECPRI => {
                                let (_, data) = ecpri_parse(&ether_data).expect("Can't parse the ECPRI package.");
                                // use hex_slice::AsHex;
                                //println!("msg_type: {:?}", data);
                                // println!("data:\n {:02X}", remain.as_hex());
                                ecpri_data.append(EcpriData {
                                    timestamp: date_time,
                                    data,
                                });
                            },
                            unknown_type => println!("Unknown data type: {:?}", unknown_type),
                        }
                        println!("\n");
                    },
                    PcapBlockOwned::NG(_) => panic!("unexpected NG data.")
                }
                num_blocks += 1;
                reader.consume(offset);
            },
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            },
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    println!("num_blocks: {}", num_blocks);

    // save iq data to file
    let frame_data = ecpri_data.parse_iq_data();
    for (info, frame) in &frame_data {
        buf_writer.write_fmt(format_args!(
            "frame_id: {}, subframe_id: {}, slot_id: {}, slot_dir: {}, iq: \n",
            info.0, info.1, info.2, frame.slot_dir
        )).expect("Failed to write iq head info to file.");
        for iq in frame.iq.iter() {
            buf_writer.write_fmt(format_args!(
                "{}, {}", 
                iq.0, iq.1
            )).expect("Failed to write iq data to file.");
        }
    }
    buf_writer.flush().expect("Flush error.");

    Ok(())
}
