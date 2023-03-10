use std::fs::File;
use std::io::{BufRead, Read};
use std::str::from_utf8;
use warcio::{LendingIterator as _, WarcReader, WarcRecordHeaderName};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let f = File::open("example.warc.gz")
        .expect("\n  Error opening example.warc.gz for writing, does it exist?\n  Try running `cargo run --example write_warc_gz` first.\n");
    let mut warc_reader = WarcReader::<Box<dyn BufRead>>::try_from(f)?;

    while let Some(record) = warc_reader.next()? {
        let mut content_type: Option<&[u8]> = None;
        let mut content_length: Option<&[u8]> = None;
        let mut warc_type: Option<&[u8]> = None;
        let mut warc_date: Option<&[u8]> = None;

        for header in &record.headers {
            match header.name {
                WarcRecordHeaderName::ContentLength => content_length = Some(&header.value),
                WarcRecordHeaderName::WARCDate => warc_date = Some(&header.value),
                WarcRecordHeaderName::WARCType => warc_type = Some(&header.value),
                WarcRecordHeaderName::ContentType => content_type = Some(&header.value),
                _ => {}
            }
        }

        let mut buf: [u8; 20] = [0; 20];
        let n = record.payload.read(&mut buf)?;

        println!(
            "warc_date={:?} warc_type={:?} content_type={:?} content_length={:?} start of body: {:?}",
            from_utf8(warc_date.unwrap_or(b"<n/a>"))?,
            from_utf8(warc_type.unwrap_or(b"<n/a>"))?,
            from_utf8(content_type.unwrap_or(b"<n/a>"))?,
            from_utf8(content_length.unwrap_or(b"<n/a>"))?,
            &buf[0..n]
        );
    }

    Ok(())
}
