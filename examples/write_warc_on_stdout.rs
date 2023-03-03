use chrono::Utc;
use std::io::{stdout, BufWriter};
use warcio::{WarcRecord, WarcRecordType, WarcRecordWrite as _, WarcWriter};

fn main() -> Result<(), std::io::Error> {
    let mut warc_writer = WarcWriter::new(BufWriter::new(stdout()), false);

    let payload = b"format: WARC File Format 1.1\r\n";
    let body = &payload[..];
    let mut record: WarcRecord<&[u8]> = WarcRecord::builder()
        .generate_record_id()
        .warc_type(WarcRecordType::Warcinfo)
        .warc_date(Utc::now())
        .content_type(b"text/plain")
        .content_length(payload.len() as u64)
        .body(body)
        .build();
    warc_writer.write_record(&mut record)?;

    let payload = b"howdy doody!";
    let body = &payload[..];
    let mut record: WarcRecord<&[u8]> = WarcRecord::builder()
        .generate_record_id()
        .warc_type(WarcRecordType::Resource)
        .warc_date(Utc::now())
        .content_type(b"text/plain")
        .content_length(payload.len() as u64)
        .body(body)
        .build();
    warc_writer.write_record(&mut record)?;

    Ok(())
}
