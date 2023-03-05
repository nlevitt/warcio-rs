use chrono::Utc;
use std::fs::OpenOptions;
use std::io::BufWriter;
use warcio::{WarcRecord, WarcRecordType, WarcRecordWrite as _, WarcWriter};

fn main() -> Result<(), std::io::Error> {
    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .open("example.warc.gz")
        .expect("opening example.warc.gz for writing");
    let mut warc_writer = WarcWriter::new(BufWriter::new(f), true);

    let payload = b"format: WARC File Format 1.1\r\n";
    let record: WarcRecord<&[u8]> = WarcRecord::builder()
        .generate_record_id()
        .warc_type(WarcRecordType::Warcinfo)
        .warc_date(Utc::now())
        .warc_filename(b"example.warc.gz")
        .content_type(b"text/plain")
        .content_length(payload.len() as u64)
        .body(&payload[..])
        .build();
    warc_writer.write_record(record, Some(&Vec::<u8>::from("example.warc.gz")))?;

    let payload = b"howdy doody!";
    let record: WarcRecord<&[u8]> = WarcRecord::builder()
        .generate_record_id()
        .warc_type(WarcRecordType::Resource)
        .warc_date(Utc::now())
        .warc_filename(b"example.warc.gz")
        .content_type(b"text/plain")
        .content_length(payload.len() as u64)
        .body(&payload[..])
        .build();
    warc_writer.write_record(record, Some(&Vec::<u8>::from("example.warc.gz")))?;

    println!("wrote 2 warc records to example.warc.gz");

    Ok(())
}
