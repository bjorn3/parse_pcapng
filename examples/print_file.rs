extern crate pcapng_parse;

fn main() {
    use std::io::prelude::*;
    use std::fs::File;

    let mut buf = Vec::new();
    let mut file = File::open(std::env::args()
                                  .skip(1)
                                  .next()
                                  .expect("No file to view"))
            .expect("File not found");
    file.read_to_end(&mut buf).unwrap();

    let packets = pcapng_parse::parse_file(&*buf);
    for packet in packets {
        println!("{:#?}", packet);
    }
}

