use crate::{WarcRecord, WarcRecordHeader, WarcRecordHeaderName, WarcVersion};
use httparse::{parse_headers, Header, Status};
use std::io::{BufRead, Read};
use std::str::from_utf8;
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

/*
 * Tested parse_headers() in rust playground:
 *
 *     use std::str::from_utf8;
 *     use httparse::parse_headers;
 *
 *     fn main() -> Result<(), Box<dyn std::error::Error>> {
 *         let test_bufs: [&[u8]; 15] = [
 *             b"",
 *             b"\n",
 *             b"\r\n",
 *             b"\n\n",
 *             b"\r\n\n",
 *             b"\n\r\n",
 *             b"\r\n\r\n",
 *             b"foo:bar\n",
 *             b"foo:bar\r\n",
 *             b"foo:  bar  \n",
 *             b"foo:  bar  baz  \n",
 *             b"foo : bar\n",
 *             b"foo  bar  :  baz  quux  \r\n",
 *             b"  foo  :  baz  quux  \r\n",
 *             b"  foo  bar  :  baz  quux  \r\n",
 *         ];
 *         for i in 0..test_bufs.len() {
 *             println!("\n{:?}", from_utf8(test_bufs[i])?);
 *             let mut headers = [httparse::EMPTY_HEADER; 2];
 *             let rv = parse_headers(test_bufs[i], &mut headers);
 *             match rv {
 *                 Ok(status) => {
 *                     println!("status={:?}", status);
 *                     println!("headers={:?}", headers);
 *                 }
 *                 Err(e) => {
 *                     println!("e={:?}", e);
 *                 }
 *             }
 *         }
 *
 *         Ok(())
 *     }
 *
 * Output:
 *
 *     ""
 *     status=Partial
 *     headers=[Header { name: "", value: "" }, Header { name: "", value: "" }]
 *
 *     "\n"
 *     status=Complete((1, []))
 *     headers=[Header { name: "", value: "" }, Header { name: "", value: "" }]
 *
 *     "\r\n"
 *     status=Complete((2, []))
 *     headers=[Header { name: "", value: "" }, Header { name: "", value: "" }]
 *
 *     "\n\n"
 *     status=Complete((1, []))
 *     headers=[Header { name: "", value: "" }, Header { name: "", value: "" }]
 *
 *     "\r\n\n"
 *     status=Complete((2, []))
 *     headers=[Header { name: "", value: "" }, Header { name: "", value: "" }]
 *
 *     "\n\r\n"
 *     status=Complete((1, []))
 *     headers=[Header { name: "", value: "" }, Header { name: "", value: "" }]
 *
 *     "\r\n\r\n"
 *     status=Complete((2, []))
 *     headers=[Header { name: "", value: "" }, Header { name: "", value: "" }]
 *
 *     "foo:bar\n"
 *     status=Partial
 *     headers=[Header { name: "foo", value: "bar" }, Header { name: "", value: "" }]
 *
 *     "foo:bar\r\n"
 *     status=Partial
 *     headers=[Header { name: "foo", value: "bar" }, Header { name: "", value: "" }]
 *
 *     "foo:  bar  \n"
 *     status=Partial
 *     headers=[Header { name: "foo", value: "bar" }, Header { name: "", value: "" }]
 *
 *     "foo:  bar  baz  \n"
 *     status=Partial
 *     headers=[Header { name: "foo", value: "bar  baz" }, Header { name: "", value: "" }]
 *
 *     "foo : bar\n"
 *     e=HeaderName
 *
 *     "foo  bar  :  baz  quux  \r\n"
 *     e=HeaderName
 *
 *     "  foo  :  baz  quux  \r\n"
 *     e=HeaderName
 *
 *     "  foo  bar  :  baz  quux  \r\n"
 *     e=HeaderName
 */

fn read_header<R: BufRead>(
    reader: &mut R,
) -> Result<Option<WarcRecordHeader>, Box<dyn std::error::Error>> {
    let buf = read_line(reader)?;
    let mut headers = [httparse::EMPTY_HEADER; 1];
    match httparse::parse_headers(&buf, &mut headers)? {
        Status::Partial => Ok(Some(WarcRecordHeader::from(headers[0]))),
        Status::Complete(_) => Ok(None),
    }
}

impl<R: BufRead> WarcReader<R> {
    pub fn new(reader: R, gzip: bool) -> Self {
        Self { reader, gzip }
    }

    // Returns Ok(None) at EOF
    pub fn read_record(&'static mut self) -> Result<Option<WarcRecord>, Box<dyn std::error::Error>> {
        let mut builder = WarcRecord::builder();
        let version = read_version_line(&mut self.reader)?;
        builder = builder.version(version);
        let mut content_length: u64 = 0;
        loop {
            match read_header(&mut self.reader)? {
                None => break,
                Some(header) => {
                    if header.name == WarcRecordHeaderName::ContentLength {
                        content_length = from_utf8(&header.value)?.parse()?;
                    }
                    builder = builder.add_header(header);
                }
            }
        }
        read_line(&mut self.reader)?; // discard empty line
        builder = builder.body(Box::new(self.reader.by_ref().take(content_length)));

        Ok(Some(builder.build()))
    }
}

#[cfg(test)]
mod tests {
    use crate::{WarcReader, WarcRecordHeaderName};
    use std::io::Cursor;
    use std::str::from_utf8;

    #[test]
    fn test_read_warc() -> Result<(), Box<dyn std::error::Error>> {
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

        let record = warc_reader.read_record()?.unwrap();
        let (headers, _body) = record.into_parts();
        assert_eq!(headers.len(), 7);
        assert!(headers[0].name == WarcRecordHeaderName::WARCRecordID);
        assert_eq!(
            from_utf8(&headers[0].value)?,
            "<urn:uuid:cae45b6d-9ba0-42c4-9d06-3c3b9bb61e5f>",
        );
        assert!(headers[1].name == WarcRecordHeaderName::WARCType);
        assert_eq!(from_utf8(&headers[1].value)?, "response",);
        assert!(headers[2].name == WarcRecordHeaderName::WARCDate);
        assert_eq!(from_utf8(&headers[2].value)?, "2023-01-15T22:32:46.308080Z",);
        assert!(headers[3].name == WarcRecordHeaderName::WARCTargetURI);
        assert_eq!(from_utf8(&headers[3].value)?, "https://httpbin.org/get",);
        assert!(headers[4].name == WarcRecordHeaderName::WARCPayloadDigest);
        assert_eq!(
            from_utf8(&headers[4].value)?,
            "sha256:04b4d2a634fe38b41c1e9d15987f19560b85ff332e0205b2d9e2db44a43fbc6d"
        );
        assert!(headers[5].name == WarcRecordHeaderName::ContentType);
        assert_eq!(
            from_utf8(&headers[5].value)?,
            "application/http;msgtype=response",
        );
        assert!(headers[6].name == WarcRecordHeaderName::ContentLength);
        assert_eq!(from_utf8(&headers[6].value)?, "485",);

        Ok(())
    }
}
