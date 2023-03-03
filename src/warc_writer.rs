use crate::{WarcRecord, WarcRecordHeader, WarcRecordType};
use chrono::{DateTime, Utc};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Error, Read, Write};

const WARC_1_1: &[u8; 10] = b"WARC/1.1\r\n";
const CRLF: &[u8; 2] = b"\r\n";
const CRLFCRLF: &[u8; 4] = b"\r\n\r\n";

struct ByteCountingWriter<W> {
    inner: W,
    count: u64,
}

impl<W> ByteCountingWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, count: 0 }
    }
}

impl<W: Write> Write for ByteCountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.inner.flush()
    }
}

/*
#[derive(Debug)]
pub(crate) struct RecordedUrl {
    pub(crate) timestamp: DateTime<Utc>,

    pub(crate) uri: String,
    pub(crate) status: u16,
    pub(crate) method: String,
    pub(crate) mimetype: Option<String>,

    pub(crate) request_line: Vec<u8>,
    pub(crate) request_headers: Vec<u8>,
    pub(crate) request_payload: Payload,
    pub(crate) response_status_line: Vec<u8>,
    pub(crate) response_headers: Vec<u8>,
    pub(crate) response_payload: Payload,
}
 */

pub struct WarcRecordInfo {
    offset: u64,
    record_id: Vec<u8>,
    warc_type: WarcRecordType,
    content_length: u64,
    warc_date: DateTime<Utc>,
    warc_target_uri: Vec<u8>,
    warc_payload_digest: Vec<u8>,
    warc_filename: Vec<u8>,

    status: u16,
    method: String,
    mimetype: Option<String>,
}

pub trait WarcRecordWrite {
    fn write_record<R: Read>(&mut self, record: &mut WarcRecord<R>) -> Result<(), Error>;
}

pub struct WarcWriter<W: Write> {
    writer: ByteCountingWriter<W>,
    gzip: bool,
}

impl<W: Write> WarcWriter<W> {
    pub fn new(writer: W, gzip: bool) -> Self {
        Self {
            writer: ByteCountingWriter::new(writer),
            gzip,
        }
    }

    pub fn tell(&mut self) -> u64 {
        self.writer.count
    }

    pub fn into_inner(self) -> W {
        self.writer.inner
    }
}

impl<W: Write> WarcRecordWrite for WarcWriter<W> {
    fn write_record<R: Read>(&mut self, record: &mut WarcRecord<R>) -> Result<(), Error> {
        if self.gzip {
            GzipRecordWriter::new(&mut self.writer).write_record(record)
        } else {
            UncompressedRecordWriter::new(&mut self.writer).write_record(record)
        }
    }
}

pub struct GzipRecordWriter<W: Write> {
    writer: W,
}

pub struct UncompressedRecordWriter<W: Write> {
    writer: W,
}

impl<W: Write> UncompressedRecordWriter<W> {
    fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: Write> WarcRecordWrite for UncompressedRecordWriter<W> {
    fn write_record<R: Read>(&mut self, record: &mut WarcRecord<R>) -> Result<(), Error> {
        // let (headers, body) = record.into_parts();
        self.writer.write_all(WARC_1_1)?;
        write_headers(&mut self.writer, &record.headers)?;
        self.writer.write_all(CRLF)?;
        write_body(&mut self.writer, &mut record.payload)?;
        self.writer.write_all(CRLFCRLF)?;
        Ok(())
    }
}

impl<W: Write> GzipRecordWriter<W> {
    fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: Write> WarcRecordWrite for GzipRecordWriter<W> {
    fn write_record<R: Read>(&mut self, record: &mut WarcRecord<R>) -> Result<(), Error> {
        let mut w = GzEncoder::new(&mut self.writer, Compression::default());
        w.write_all(WARC_1_1)?;
        write_headers(&mut w, &record.headers)?;
        w.write_all(CRLF)?;
        write_body(&mut w, &mut record.payload)?;
        w.write_all(CRLFCRLF)?;
        let inner = w.finish()?;
        inner.flush()?;
        Ok(())
    }
}

fn write_headers<W: Write>(w: &mut W, headers: &Vec<WarcRecordHeader>) -> Result<(), Error> {
    for header in headers.into_iter() {
        w.write_all(header.name.as_bytes())?;
        w.write_all(b": ")?;
        w.write_all(header.value.as_slice())?;
        w.write_all(CRLF)?;
    }
    Ok(())
}

fn write_body<W: Write, R: Read>(w: &mut W, body: &mut R) -> Result<(), Error> {
    let mut buf: [u8; 65536] = [0; 65536];

    loop {
        let n = body.read(&mut buf)?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[0..n])?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{WarcRecord, WarcRecordType, WarcRecordWrite as _, WarcWriter};
    use chrono::{TimeZone, Utc};
    use flate2::read::GzDecoder;
    use std::io::{Cursor, Read, Seek, SeekFrom};
    use std::str::from_utf8;

    fn build_record() -> (WarcRecord<Box<dyn Read>>, String) {
        let body: Box<dyn Read> = Box::new(Cursor::new(b"I'm the body".to_vec()));
        let record = WarcRecord::builder()
            .generate_record_id()
            .warc_type(WarcRecordType::Resource)
            .content_length(100)
            .warc_date(Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap())
            .content_type(b"text/plain; charset=utf-8")
            .warc_filename(b"test.warc")
            .warc_target_uri(b"https://example.com/foo.txt")
            .warc_payload_digest(
                b"sha256:0b0edecafc0ffeec0c0acafef00ddeadface0ffaccededd00dadeffacedd00d9",
            )
            .body(body)
            .build();
        let record_str = format!(
            concat!(
            "WARC/1.1\r\n",
            "WARC-Record-ID: <{}>\r\n",
            "WARC-Type: resource\r\n",
            "Content-Length: 100\r\n",
            "WARC-Date: 2023-01-01T00:00:00.000000Z\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "WARC-Filename: test.warc\r\n",
            "WARC-Target-URI: https://example.com/foo.txt\r\n",
            "WARC-Payload-Digest: sha256:0b0edecafc0ffeec0c0acafef00ddeadface0ffaccededd00dadeffacedd00d9\r\n",
            "\r\n",
            "I'm the body",
            "\r\n\r\n"),
            record.record_id,
        );
        (record, record_str)
    }

    /*
    #[test]
    fn test_write_record_uncompressed() {
        let (record, record_str) = build_record();
        let buf = Cursor::new(Vec::<u8>::new());
        let mut w = WarcWriter::new(buf, false);
        w.write_record(record).unwrap();
        let buf = w.into_inner().into_inner();
        // print!("{}", from_utf8(&buf).unwrap());
        assert_eq!(from_utf8(&buf).unwrap(), record_str);
    }

    #[test]
    fn test_write_record_gzip() {
        let (record, expected) = build_record();
        let buf = Cursor::new(Vec::<u8>::new());
        let mut w = WarcWriter::new(buf, true);
        w.write_record(record).unwrap();
        let mut gzipped_buf = w.into_inner();
        gzipped_buf.seek(SeekFrom::Start(0)).unwrap();
        let mut gunzipped_buf = Vec::<u8>::new();
        GzDecoder::new(gzipped_buf)
            .read_to_end(&mut gunzipped_buf)
            .unwrap();
        print!("{}", from_utf8(&gunzipped_buf).unwrap());
        assert_eq!(gunzipped_buf, expected.as_bytes());
    }
     */
}
