extern crate byteorder;
extern crate itertools;

use std::fmt;

use byteorder::{BigEndian, LittleEndian, ByteOrder};
use itertools::Itertools;

use Packet::*;

pub struct HexData(pub Vec<u8>);

#[derive(Debug)]
pub enum Packet {
    Header,
    IfaceDescr {
        link_type: u16,
        snap_num: u32,
        options: HexData,
    },
    Packet,
    SimplePacket,
    NameResolution,
    IfaceStatistics,
    EnhancedBlock {
        iface_id: u32,
        timestamp: u64,
        orig_len: u32,
        cap_len: u32,
        content: HexData,
    },
}

#[derive(Debug)]
#[repr(u8)]
pub enum OptionType {
    EndOfOpts = 0,
    Name = 2,
    Descr = 3,
    Ip4Addr = 4,
    Ip6Addr = 5,
    Unknown = ::std::u8::MAX,
}

pub fn parse_file(buf: &[u8]) -> Vec<Packet>{
    let mut packets = Vec::new();
    let mut begin = 0_usize;
    loop {
        let len = LittleEndian::read_u32(&buf[begin + 4..begin + 8]);
        let len = len +
                  match len % 4 {
                      0 => 0,
                      1 => 3,
                      2 => 2,
                      3 => 1,
                      _ => unreachable!(),
                  };
        packets.push(parse_block(&buf[begin.. begin + len as usize - 4]));

        begin += len as usize;
        if begin >= buf.len() {
            return packets;
        }
    }
}

fn parse_block(buf: &[u8]) -> Packet {
    let read_u16 = LittleEndian::read_u16;
    let read_u32 = LittleEndian::read_u32;
    let read_u64 = LittleEndian::read_u64;

    let type_id = LittleEndian::read_u32(&buf[0..4]);
    match type_id {
        0x0A0D0D0A => Header,
        0x1 => IfaceDescr {
            link_type: read_u16(&buf[4..6]),
            snap_num: read_u32(&buf[8..12]),
            options: HexData(buf[12..].to_vec()),
        },
        0x2 => Packet::Packet,
        0x3 => SimplePacket,
        0x4 => NameResolution,
        0x5 => IfaceStatistics,
        0x6 => EnhancedBlock {
            iface_id: read_u32(&buf[8..12]),
            timestamp: read_u64(&buf[12..20]),
            cap_len: read_u32(&buf[20..24]),
            orig_len: read_u32(&buf[24..28]),
            content: HexData(buf[28..].to_vec()),
        },
        _ => panic!(),
    }
    /*
    match type_id {
        0x1 => {
            builder.set_color(Green);
            builder.line(2, Ty::LeNum, "link type");
            builder.line(2, Ty::Binary, "reserved");
            builder.line(4, Ty::LeNum, "snap num");
            builder.set_color(Yellow);

            let mut offset = 16 as usize;
            for i in 0.. {
                let opt1_type_num = LittleEndian::read_u16(&buf[offset..offset + 2]);
                let opt1_type = match opt1_type_num {
                    0 => "end of opts",
                    2 => "name",
                    3 => "descr",
                    4 => "ipv4 addr",
                    5 => "ipv6 addr",
                    9 => "tmstamp res",
                    12 => "OS",
                    _ => {
                        builder.set_color(Red);
                        "<unknown>"
                    },
                };
                builder.line(2, Ty::custom(opt1_type), format!("opt{} type", i));
                builder.set_color(Yellow);

                let opt1_len = LittleEndian::read_u16(&buf[offset + 2..offset + 4]) as usize;
                let opt1_len = opt1_len +
                               match opt1_len % 4 {
                                   0 => 0,
                                   1 => 3,
                                   2 => 2,
                                   3 => 1,
                                   9 => 1,
                                   _ => unreachable!(),
                               };
                let opt1_len_adapted = match opt1_type_num {
                    0 => 0, // end of opts
                    4 => 8,
                    5 => 17,
                    6 => 6,
                    7 => 8,
                    _ => opt1_len,
                };
                assert_eq!(opt1_len, opt1_len_adapted, "Opt len is wrong");
                builder.line(2, Ty::LeNum, format!("opt{}  len", i));
                builder.line(opt1_len, Ty::Ascii, format!("opt{} data", i));
                offset += 4 + opt1_len;
                if offset >= buf.len() - 4 {
                    break;
                }
                //break;
            }
            builder.line_until(buf.len() - 4, Ty::Ascii, "options");
        }
        0x6 => {
        }
        _ => builder.line_until(buf.len() - 4, Ty::Ascii, "content"),
    }

    builder.line(4, Ty::LeNum, "size");*/
}

fn make_ascii(c: char) -> char {
    match c {
        // _ if c.is_ascii_alphanumeric() || c.is_ascii_punctuation() => c,
        'a'...'z' | 'A'...'Z' | '0'...'9' | ':' | ';' | '@' | '/' | '\\' | '|' | '?' | '!' |
        '+' | '*' | '.' | ',' | ' ' | '-' | '_' | '\'' | '"' | '=' | '(' | ')' | '{' | '}' |
        '[' | ']' | '&' | '>' | '<' => c,
        '\n' => '␊',
        '\r' => '␍',
        '\0' => '␀',
        //c => c,
        _ => '�',
    }
}

impl fmt::Debug for HexData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\n")?;
        for chunk in self.0.iter().chunks(32).into_iter() {
            let chunk = chunk.collect::<Vec<_>>();
            for b in chunk.iter().map(|b|format!("{:02X}", b)).pad_using(32, |_|"..".to_string()).into_iter() {
                write!(f, "{} ", b)?;
            }
            write!(f, " |{}|\n", chunk.into_iter().map(|&b|make_ascii(b as char)).collect::<String>())?;
        }
        Ok(())
    }
}

