use crate::{WarcRecord, WarcRecordHeader, WarcRecordHeaderName, WarcVersion};
use httparse::Status;
use std::io::{BufRead, Read, Take};
use std::str::from_utf8;

// https://blog.rust-lang.org/2022/10/28/gats-stabilization.html
// Simpler proof of concept:
// https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&gist=955cb06a498c29433ee2ccea162f091e
trait LendingIterator {
    type Item<'a>
    where
        Self: 'a;

    fn next(&mut self) -> Self::Item<'_>;
}

/**
 * WARC reader. Initial implementation is brittle, will probably fail poorly attempting to read
 * invalid warcs.
 */
pub struct WarcReader<R: BufRead> {
    reader: Option<R>,
    current_record: Option<WarcRecord<Take<R>>>,
    gzip: bool,
}

// Read line, with limit
fn read_line<R: BufRead>(reader: &mut R) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = Vec::<u8>::new();
    let mut limited_reader = reader.by_ref().take(65536);
    limited_reader.read_until(b'\n', &mut buf)?;
    Ok(buf)
}

// No copy, returns subslice of slice
fn trim_newline(buf: &[u8]) -> &[u8] {
    let len = buf.len();
    if len >= 2 && &buf[len - 2..] == b"\r\n" {
        &buf[..len - 2]
    } else if len >= 1 && buf[len - 1] == b'\n' {
        &buf[..len - 1]
    } else {
        &buf
    }
}

fn read_version_line<R: BufRead>(reader: &mut R) -> Result<WarcVersion, std::io::Error> {
    let buf = read_line(reader)?;
    let buf = trim_newline(&buf);

    if buf == b"WARC/1.1" {
        Ok(WarcVersion::Warc1_1)
    } else {
        Ok(WarcVersion::Custom(Vec::from(buf)))
    }
}

fn read_header<R: BufRead>(
    reader: &mut R,
) -> Result<Option<WarcRecordHeader>, Box<dyn std::error::Error>> {
    let buf = read_line(reader)?;
    let mut headers = [httparse::EMPTY_HEADER; 1];

    // Explored parse_headers behavior:
    // https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&gist=3d6dabb8f61be46ad4166ab83c973165
    match httparse::parse_headers(&buf, &mut headers)? {
        Status::Partial => Ok(Some(WarcRecordHeader::from(headers[0]))),
        Status::Complete(_) => Ok(None),
    }
}

impl<R: BufRead> WarcReader<R> {
    pub fn new(reader: R, gzip: bool) -> Self {
        Self {
            reader: Some(reader),
            current_record: None,
            gzip,
        }
    }
}

impl<R: BufRead> LendingIterator for WarcReader<R> {
    type Item<'a> = Result<Option<&'a mut WarcRecord<Take<R>>>, Box<dyn std::error::Error>> where Self: 'a;

    fn next(&mut self) -> Result<Option<&mut WarcRecord<Take<R>>>, Box<dyn std::error::Error>> {
        let mut reader = if self.current_record.is_some() {
            let (_, last_body) = self.current_record.take().unwrap().into_parts();
            let mut reader = last_body.into_inner();
            read_line(&mut reader)?; // discard empty line
            read_line(&mut reader)?; // discard empty line
            reader
        } else {
            self.reader.take().unwrap()
        };

        // Check for end of warc. XXX Handle EOF at any point somehow
        if reader.fill_buf()?.len() == 0 {
            return Ok(None);
        }

        let version = read_version_line(&mut reader)?;
        let mut builder = WarcRecord::builder();
        builder = builder.version(version);
        let mut content_length: u64 = 0;
        loop {
            match read_header(&mut reader)? {
                None => break,
                Some(header) => {
                    if header.name == WarcRecordHeaderName::ContentLength {
                        content_length = from_utf8(&header.value)?.parse()?;
                    }
                    builder = builder.add_header(header);
                }
            }
        }
        builder = builder.body(reader.take(content_length));

        self.current_record = Some(builder.build());
        Ok(self.current_record.as_mut())
    }
}

#[cfg(test)]
mod tests {
    use crate::warc_reader::LendingIterator;
    use crate::{WarcReader, WarcRecordHeaderName, WarcVersion};
    use std::io::{Cursor, Read};
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

        let record = warc_reader.next()?;
        assert!(record.is_some());
        let record = record.unwrap();
        assert_eq!(record.version, WarcVersion::Warc1_1);
        assert_eq!(record.headers.len(), 7);
        assert!(record.headers[0].name == WarcRecordHeaderName::WARCRecordID);
        assert_eq!(
            from_utf8(&record.headers[0].value)?,
            "<urn:uuid:cae45b6d-9ba0-42c4-9d06-3c3b9bb61e5f>",
        );
        assert!(record.headers[1].name == WarcRecordHeaderName::WARCType);
        assert_eq!(from_utf8(&record.headers[1].value)?, "response",);
        assert!(record.headers[2].name == WarcRecordHeaderName::WARCDate);
        assert_eq!(
            from_utf8(&record.headers[2].value)?,
            "2023-01-15T22:32:46.308080Z",
        );
        assert!(record.headers[3].name == WarcRecordHeaderName::WARCTargetURI);
        assert_eq!(
            from_utf8(&record.headers[3].value)?,
            "https://httpbin.org/get",
        );
        assert!(record.headers[4].name == WarcRecordHeaderName::WARCPayloadDigest);
        assert_eq!(
            from_utf8(&record.headers[4].value)?,
            "sha256:04b4d2a634fe38b41c1e9d15987f19560b85ff332e0205b2d9e2db44a43fbc6d",
        );
        assert!(record.headers[5].name == WarcRecordHeaderName::ContentType);
        assert_eq!(
            from_utf8(&record.headers[5].value)?,
            "application/http;msgtype=response",
        );
        assert!(record.headers[6].name == WarcRecordHeaderName::ContentLength);
        assert_eq!(from_utf8(&record.headers[6].value)?, "485");
        let mut buf: Vec<u8> = Vec::new();
        record.body.read_to_end(&mut buf)?;
        assert_eq!(
            from_utf8(&buf)?,
            concat!(
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
            )
        );

        let record = warc_reader.next()?;
        assert!(record.is_some());
        let record = record.unwrap();
        assert_eq!(record.version, WarcVersion::Warc1_1);
        assert_eq!(record.headers.len(), 7);
        assert!(record.headers[0].name == WarcRecordHeaderName::WARCRecordID);
        assert_eq!(
            from_utf8(&record.headers[0].value)?,
            "<urn:uuid:33f0ed45-5b1f-4bae-8759-ecb4844e2997>",
        );
        assert!(record.headers[1].name == WarcRecordHeaderName::WARCType);
        assert_eq!(from_utf8(&record.headers[1].value)?, "request",);
        assert!(record.headers[2].name == WarcRecordHeaderName::WARCDate);
        assert_eq!(
            from_utf8(&record.headers[2].value)?,
            "2023-01-15T22:32:46.308080Z",
        );
        assert!(record.headers[3].name == WarcRecordHeaderName::WARCTargetURI);
        assert_eq!(
            from_utf8(&record.headers[3].value)?,
            "https://httpbin.org/get",
        );
        assert!(record.headers[4].name == WarcRecordHeaderName::WARCPayloadDigest);
        assert_eq!(
            from_utf8(&record.headers[4].value)?,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert!(record.headers[5].name == WarcRecordHeaderName::ContentType);
        assert_eq!(
            from_utf8(&record.headers[5].value)?,
            "application/http;msgtype=request",
        );
        assert!(record.headers[6].name == WarcRecordHeaderName::ContentLength);
        assert_eq!(from_utf8(&record.headers[6].value)?, "78");
        let mut buf: Vec<u8> = Vec::new();
        record.body.read_to_end(&mut buf)?;
        assert_eq!(
            from_utf8(&buf)?,
            concat!(
                "GET /get HTTP/1.1\r\n",
                "host: httpbin.org\r\n",
                "user-agent: curl/7.79.1\r\n",
                "accept: */*\r\n",
                "\r\n",
            )
        );

        assert!(warc_reader.next()?.is_none());

        Ok(())
    }
}
