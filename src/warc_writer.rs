use crate::{WarcRecord, WarcRecordHeader};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Error, Read, Seek, SeekFrom, Write};

const WARC_1_1: &[u8; 10] = b"WARC/1.1\r\n";
const CRLF: &[u8; 2] = b"\r\n";
const CRLFCRLF: &[u8; 4] = b"\r\n\r\n";

// TODO Seek is only used to get current offset, but we could keep track of that by counting bytes
pub struct WarcWriter<W: Write + Seek> {
    writer: W,
    gzip: bool,
}

impl<W: Write + Seek> WarcWriter<W> {
    pub fn new(writer: W, gzip: bool) -> Self {
        Self { writer, gzip }
    }

    pub fn write_record(&mut self, record: WarcRecord) -> Result<(), Error> {
        if self.gzip {
            GzipRecordWriter::new(&mut self.writer).write_record(record)
        } else {
            UncompressedRecordWriter::new(&mut self.writer).write_record(record)
        }
    }

    pub fn tell(&mut self) -> u64 {
        self.writer.seek(SeekFrom::Current(0)).unwrap()
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

    pub fn write_record(&mut self, record: WarcRecord) -> Result<(), Error> {
        let (headers, body) = record.into_parts();
        self.writer.write_all(WARC_1_1)?;
        write_headers(&mut self.writer, headers)?;
        self.writer.write_all(CRLF)?;
        write_body(&mut self.writer, body)?;
        self.writer.write_all(CRLFCRLF)?;
        Ok(())
    }
}

impl<W: Write> GzipRecordWriter<W> {
    fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn write_record(&mut self, record: WarcRecord) -> Result<(), Error> {
        let (headers, body) = record.into_parts();
        let mut w = GzEncoder::new(&mut self.writer, Compression::default());
        w.write_all(WARC_1_1)?;
        write_headers(&mut w, headers)?;
        w.write_all(CRLF)?;
        write_body(&mut w, body)?;
        w.write_all(CRLFCRLF)?;
        w.finish()?;
        Ok(())
    }
}

fn write_headers<W: Write>(w: &mut W, headers: Vec<WarcRecordHeader>) -> Result<(), Error> {
    for header in headers.into_iter() {
        w.write_all(header.name.as_bytes())?;
        w.write_all(b": ")?;
        w.write_all(header.value.as_slice())?;
        w.write_all(CRLF)?;
    }
    Ok(())
}

fn write_body<W: Write, R: Read>(w: &mut W, mut body: R) -> Result<(), Error> {
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
