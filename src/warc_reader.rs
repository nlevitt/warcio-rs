use crate::{WarcRecord, WarcRecordHeader, WarcRecordHeaderName, WarcVersion};
use httparse::Status;
use std::io::{BufRead, Read, Take};
use std::str::from_utf8;

fn read_line<R: BufRead>(reader: &mut R) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = Vec::<u8>::new();
    let mut limited_reader = reader.by_ref().take(65536);
    limited_reader.read_until(b'\n', &mut buf)?;
    Ok(buf)
}

fn trim_newline(buf: &Vec<u8>) -> &[u8] {
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

// https://blog.rust-lang.org/2022/10/28/gats-stabilization.html
// Simpler proof of concept:
// https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&gist=955cb06a498c29433ee2ccea162f091e
trait LendingIterator {
    type Item<'a>
    where
        Self: 'a;

    fn next(&mut self) -> Self::Item<'_>;
}

pub struct WarcReader<R: BufRead> {
    reader: Option<R>,
    current_record: Option<WarcRecord<Take<R>>>,
}

impl<R: BufRead> WarcReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: Some(reader),
            current_record: None,
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
            // TODO cap number of headers we store
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

    static WARC_RECORDS: [&str; 2] = [
        concat!(
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
        ),
        concat!(
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
        ),
    ];
    use crate::{WarcReader, WarcRecord};
    use flate2::read::MultiGzDecoder;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::{BufReader, Cursor, Read, Seek, SeekFrom, Write};
    use std::str::from_utf8;

    fn check_first_record<R: Read>(
        record: Option<&mut WarcRecord<R>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(record.is_some());
        let record = record.unwrap();
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

        Ok(())
    }

    fn check_second_record<R: Read>(
        record: Option<&mut WarcRecord<R>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(record.is_some());
        let record = record.unwrap();
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

        Ok(())
    }

    #[test]
    fn test_read_uncompressed_warc() -> Result<(), Box<dyn std::error::Error>> {
        let mut warc_reader = WarcReader::new(Cursor::new(Vec::from(WARC_RECORDS.concat())));

        // We have this check_first_record / check_second_record code because (I think) it's not
        // easy/possible to write a function that takes either a WarcReader or GzipWarcReader.
        // See https://blog.rust-lang.org/2022/10/28/gats-stabilization.html#implied-static-requirement-from-higher-ranked-trait-bounds
        let record = warc_reader.next()?;
        check_first_record(record)?;
        let record = warc_reader.next()?;
        check_second_record(record)?;
        assert!(warc_reader.next()?.is_none());

        Ok(())
    }

    #[test]
    fn test_read_gzipped_warc() -> Result<(), Box<dyn std::error::Error>> {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        for record_str in WARC_RECORDS {
            let mut w = GzEncoder::new(&mut cursor, Compression::default());
            w.write_all(record_str.as_bytes())?;
            w.finish()?;
        }
        cursor.seek(SeekFrom::Start(0))?;

        let mut warc_reader = WarcReader::new(BufReader::new(MultiGzDecoder::new(cursor)));

        // We have this check_first_record / check_second_record code because (I think) it's not
        // easy/possible to write a function that takes either a WarcReader or GzipWarcReader.
        // See https://blog.rust-lang.org/2022/10/28/gats-stabilization.html#implied-static-requirement-from-higher-ranked-trait-bounds
        let record = warc_reader.next()?;
        check_first_record(record)?;
        let record = warc_reader.next()?;
        check_second_record(record)?;
        assert!(warc_reader.next()?.is_none());

        Ok(())
    }
}
