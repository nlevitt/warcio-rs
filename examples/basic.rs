use chrono::Utc;
use std::fs::OpenOptions;
use warcio::{WarcRecord, WarcRecordType, WarcWriter};

fn main() {
    let f = OpenOptions::new()
        .create(true) // .create_new(true)
        .append(true) // .write(true)
        .open("basic.warc")
        .expect("opening basic.warc for writing");
    let mut warc_writer = WarcWriter::new(f, false);
    println!("opened basic.warc for writing");

    let payload = b"howdy doody!";
    let record = WarcRecord::builder().warc_type(WarcRecordType::Warcinfo).warc_date(Utc::now()).warc_filename(b"basic.warc").content_type(b"application/warc-fields").content_length(payload.len() as u64).body(Box::new(&payload[..])).build();
    warc_writer
        .write_record(record)
        .expect("warc_writer.warc_record");
}
