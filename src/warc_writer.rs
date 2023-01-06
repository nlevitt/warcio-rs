use crate::{WarcRecord, WarcRecordHeader};
use std::io::{Error, Read, Write};

pub struct WarcWriter<W: Write> {
    writer: W,
}

const CRLF: &[u8; 2] = b"\r\n";
const CRLFCRLF: &[u8; 4] = b"\r\n\r\n";

impl<W: Write> WarcWriter<W> {
    fn write_headers(&mut self, headers: Vec<WarcRecordHeader>) -> Result<(), Error> {
        for header in headers.into_iter() {
            self.writer.write_all(header.name.as_bytes())?;
            self.writer.write_all(b": ")?;
            self.writer.write_all(header.value.as_slice())?;
            self.writer.write_all(CRLF)?;
        }
        Ok(())
    }

    fn write_body<R: Read>(&mut self, mut body: R) -> Result<(), Error> {
        let mut buf: [u8; 65536] = [0; 65536];

        loop {
            let n = body.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.writer.write_all(&buf[0..n])?;
        }

        Ok(())
    }

    pub fn write_record(&mut self, record: WarcRecord) -> Result<(), Error> {
        let (headers, body) = record.into_parts();
        self.writer.write_all(b"WARC/1.1\r\n")?; // FIXME un-hardcode in some fashion
        self.write_headers(headers)?;
        self.writer.write_all(CRLF)?;
        self.write_body(body)?;
        self.writer.write_all(CRLFCRLF)?;
        Ok(())
    }
}

impl<W: Write> From<W> for WarcWriter<W> {
    fn from(writer: W) -> Self {
        Self { writer }
    }
}
