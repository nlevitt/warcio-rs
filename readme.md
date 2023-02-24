[![tests](https://github.com/nlevitt/warcio-rs/actions/workflows/tests.yml/badge.svg)](https://github.com/nlevitt/warcio-rs/actions)

# warcio-rs

## WARC library for rust

Warcio-rs is a rust library for reading and writing [WARC 1.1][1] files. Input and output are streamed: the WARC record
body is a [`Read`][2], both when reading and writing WARCs.

## Sample code

See [examples][3] for more.

### Read a WARC

```rust
use std::fs::File;
use std::io::{BufRead, Read};
use std::str::from_utf8;
use warcio::{LendingIterator as _, WarcReader, WarcRecordHeaderName};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let f = File::open("example.warc.gz")?;
    let mut warc_reader = WarcReader::<Box<dyn BufRead>>::try_from(f)?;
    while let Some(record) = warc_reader.next()? {

        // more convenient api to come
        let mut content_type: Option<&[u8]> = None;
        for header in &record.headers {
            match header.name {
                WarcRecordHeaderName::ContentType => content_type = Some(&header.value),
                _ => {}
            }
        }

        let mut buf: [u8; 20] = [0; 20];
        let n = record.body.read(&mut buf)?;

        println!(
            "content_type={:?} start of body: {:?}",
            from_utf8(content_type.unwrap_or(b"<n/a>"))?,
            &buf[0..n]
        );
    }

    Ok(())
}
```

### Write a WARC

```rust
use chrono::Utc;
use std::fs::File;
use std::io::BufWriter;
use warcio::{WarcRecord, WarcRecordType, WarcWriter};

fn main() -> Result<(), std::io::Error> {
    let f = File::create("example.warc.gz")?;
    let mut warc_writer = WarcWriter::new(BufWriter::new(f), true);

    let payload = b"format: WARC File Format 1.1\r\n";
    let record: WarcRecord<&[u8]> = WarcRecord::builder()
        .generate_record_id()
        .warc_type(WarcRecordType::Warcinfo)
        .warc_date(Utc::now())
        .content_type(b"text/plain")
        .content_length(payload.len())
        .body(&payload[..])
        .build();
    warc_writer.write_record(record)?;

    Ok(())
}
```

[1]: https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/
[2]: https://doc.rust-lang.org/std/io/trait.Read.html
[3]: https://github.com/nlevitt/warcio-rs/tree/master/examples
