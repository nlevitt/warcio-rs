use std::fs::OpenOptions;
use warcio_rs::{WarcRecordBuilder, WarcWriter};

fn main() {
    let f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open("basic.warc")
        .expect("opening basic.warc for writing");
    println!("opened basic.warc for writing");

    let mut warc_writer = WarcWriter::from(f);
    let record = WarcRecordBuilder::new()
        .body(Box::new(&b"howdy doody!"[..]))
        .build();
    warc_writer
        .write_record(record)
        .expect("warc_writer.warc_record");
}
