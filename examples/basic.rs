use std::fs::OpenOptions;
use warcio::{WarcRecordBuilder, WarcRecordType, WarcWriter};

fn main() {
    let f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open("basic.warc")
        .expect("opening basic.warc for writing");
    let mut warc_writer = WarcWriter::from(f);
    println!("opened basic.warc for writing");

    let payload = b"howdy doody!";
    let record = WarcRecordBuilder::new()
        .warc_type(WarcRecordType::Warcinfo)
        .content_length(payload.len() as u64)
        .body(Box::new(&payload[..]))
        .build();
    warc_writer
        .write_record(record)
        .expect("warc_writer.warc_record");
}
