use crate::{WarcRecord, WarcRecordHeader, WarcVersion};
use std::io::{BufRead, Read};
/*
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::io::{BufRead as _, Read as _};
use std::str::from_utf8;

fn main() -> Result<(), Box<dyn Error>> {
    let reader = BufReader::new(File::open("/etc/passwd")?);
    let mut buf = Vec::<u8>::new();

    let mut limited_reader = reader.take(65536);
    limited_reader.read_until(b'\n', &mut buf)?;
    print!("{}", from_utf8(&buf)?);
    let mut reader = limited_reader.into_inner();

    let mut limited_reader = reader.take(65536);
    limited_reader.read_until(b'\n', &mut buf)?;
    print!("{}", from_utf8(&buf)?);
    let mut reader = limited_reader.into_inner();

    Ok(())
}
 */

pub struct WarcReader<R: BufRead> {
    reader: R,
    gzip: bool,
}

fn read_line<R: BufRead>(reader: &mut R) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = Vec::<u8>::new();
    let mut limited_reader = reader.by_ref().take(65536);
    limited_reader.read_until(b'\n', &mut buf)?;
    Ok(buf)
}

fn trim_newline(buf: &Vec<u8>) -> &[u8] {
    let len = buf.len();
    if &buf[len - 2..] == b"\r\n" {
        &buf[..len - 2]
    } else if buf[len - 1] == b'\n' {
        &buf[..len - 1]
    } else {
        &buf
    }
}

fn read_version_line<R: BufRead>(reader: &mut R) -> Result<WarcVersion, std::io::Error> {
    let buf = read_line(reader)?;
    let buf = trim_newline(&buf);

    if buf == b"WARC/1.1" {
        Ok(WarcVersion::WARC_1_1)
    } else {
        Ok(WarcVersion::Custom(Vec::from(buf)))
    }
}

fn read_header<R: BufRead>(
    reader: &mut R,
) -> Result<Option<WarcRecordHeader>, Box<dyn std::error::Error>> {
    let buf = read_line(reader)?;
    let buf = trim_newline(&buf);
    if buf.len() == 0 {
        return Ok(None);
    };
    let header = WarcRecordHeader::try_from(buf)?;
    Ok(Some(header))
}

impl<R: BufRead> WarcReader<R> {
    pub fn new(reader: R, gzip: bool) -> Self {
        Self { reader, gzip }
    }

    // Returns Ok(None) at EOF
    pub fn read_record(&mut self) -> Result<Option<WarcRecord>, Box<dyn std::error::Error>> {
        let builder = WarcRecord::builder();
        let version = read_version_line(&mut self.reader)?;
        let mut builder = builder.version(version);
        loop {
            match read_header(&mut self.reader)? {
                None => break,
                Some(header) => {
                    builder = builder.add_header(header);
                }
            }
        }

        Ok(Some(builder.build()))
    }
}

#[cfg(test)]
mod tests {
    use crate::WarcReader;
    use std::io::Cursor;

    #[test]
    fn test_read_warc() {
        let warc = concat!(
            "WARC/1.1\r\n",
            "WARC-Record-ID: <urn:uuid:cae45b6d-9ba0-42c4-9d06-3c3b9bb61e5f>\r\n",
            "WARC-Type: response\r\n",
            "WARC-Date: 2023-01-15T22:32:46.308080Z\r\n",
            "WARC-Target-URI: https://httpbin.org/get\r\n",
            "WARC-Payload-Digest: sha256:04b4d2a634fe38b41c1e9d15987f19560b85ff332e0205b2d9e2db44a43fbc6d\r\n",
            "Content-Type: application/http;msgtype=response\r\n",
            "Content-Length: 485\r\n",
            "\r\n",
            "HTTP/1.1 200 OK\r\n",
            "date: Sun, 15 Jan 2023 22:32:46 GMT\r\n",
            "content-type: application/json\r\n",
            "content-length: 255\r\n",
            "connection: keep-alive\r\n",
            "server: gunicorn/19.9.0\r\n",
            "access-control-allow-origin: *\r\n",
            "access-control-allow-credentials: true\r\n",
            "\r\n",
            "{\n",
            "  \"args\": {}, \n",
            "  \"headers\": {\n",
            "    \"Accept\": \"*/*\", \n",
            "    \"Host\": \"httpbin.org\", \n",
            "    \"User-Agent\": \"curl/7.79.1\", \n",
            "    \"X-Amzn-Trace-Id\": \"Root=1-63c47f0e-54ee71763aff92de7cc01c7c\"\n",
            "  }, \n",
            "  \"origin\": \"52.119.127.81\", \n",
            "  \"url\": \"https://httpbin.org/get\"\n",
            "}\n",
            "\r\n",
            "\r\n",
            "WARC/1.1\r\n",
            "WARC-Record-ID: <urn:uuid:33f0ed45-5b1f-4bae-8759-ecb4844e2997>\r\n",
            "WARC-Type: request\r\n",
            "WARC-Date: 2023-01-15T22:32:46.308080Z\r\n",
            "WARC-Target-URI: https://httpbin.org/get\r\n",
            "WARC-Payload-Digest: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\r\n",
            "Content-Type: application/http;msgtype=request\r\n",
            "Content-Length: 78\r\n",
            "\r\n",
            "GET /get HTTP/1.1\r\n",
            "host: httpbin.org\r\n",
            "user-agent: curl/7.79.1\r\n",
            "accept: */*\r\n",
            "\r\n",
            "\r\n"
        );
        let mut warc_reader = WarcReader::new(Cursor::new(Vec::from(warc.as_bytes())), false);
        loop {
            match warc_reader.read_record() {
                Ok(Some(record)) => {
                    let (headers, _body) = record.into_parts();
                    assert_eq!(headers.len(), 7);
                }
                Ok(None) => {}
                Err(_e) => {}
            }
        }
    }
}
