use chrono::{DateTime, SecondsFormat, Utc};
use http::{HeaderMap, HeaderValue, StatusCode, Version};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{BufRead, BufReader, Chain, Cursor, Read, Take};
use uuid::fmt::Urn;
use uuid::Uuid;

// https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/#named-fields
#[derive(PartialEq, Eq, Debug)]
pub enum WarcRecordHeaderName {
    WARCRecordID,
    ContentLength,
    WARCDate,
    WARCType,
    ContentType,
    WARCConcurrentTo,
    WARCBlockDigest,
    WARCPayloadDigest,
    WARCIPAddress,
    WARCRefersTo,
    WARCRefersToTargetURI,
    WARCRefersToDate,
    WARCTargetURI,
    WARCTruncated,
    WARCWarcinfoID,
    WARCFilename,
    WARCProfile,
    WARCIdentifiedPayloadType,
    WARCSegmentNumber,
    WARCSegmentOriginID,
    WARCSegmentTotalLength,
    Custom(Vec<u8>),
}

impl WarcRecordHeaderName {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            WarcRecordHeaderName::WARCRecordID => b"WARC-Record-ID",
            WarcRecordHeaderName::ContentLength => b"Content-Length",
            WarcRecordHeaderName::WARCDate => b"WARC-Date",
            WarcRecordHeaderName::WARCType => b"WARC-Type",
            WarcRecordHeaderName::ContentType => b"Content-Type",
            WarcRecordHeaderName::WARCConcurrentTo => b"WARC-Concurrent-To",
            WarcRecordHeaderName::WARCBlockDigest => b"WARC-Block-Digest",
            WarcRecordHeaderName::WARCPayloadDigest => b"WARC-Payload-Digest",
            WarcRecordHeaderName::WARCIPAddress => b"WARC-IP-Address",
            WarcRecordHeaderName::WARCRefersTo => b"WARC-Refers-To",
            WarcRecordHeaderName::WARCRefersToTargetURI => b"WARC-Refers-To-Target-URI",
            WarcRecordHeaderName::WARCRefersToDate => b"WARC-Refers-To-Date",
            WarcRecordHeaderName::WARCTargetURI => b"WARC-Target-URI",
            WarcRecordHeaderName::WARCTruncated => b"WARC-Truncated",
            WarcRecordHeaderName::WARCWarcinfoID => b"WARC-Warcinfo-ID",
            WarcRecordHeaderName::WARCFilename => b"WARC-Filename",
            WarcRecordHeaderName::WARCProfile => b"WARC-Profile",
            WarcRecordHeaderName::WARCIdentifiedPayloadType => b"WARC-Identified-Payload-Type",
            WarcRecordHeaderName::WARCSegmentNumber => b"WARC-Segment-Number",
            WarcRecordHeaderName::WARCSegmentOriginID => b"WARC-Segment-Origin-ID",
            WarcRecordHeaderName::WARCSegmentTotalLength => b"WARC-Segment-Total-Length",
            WarcRecordHeaderName::Custom(name) => name.as_slice(),
        }
    }
}

impl From<&[u8]> for WarcRecordHeaderName {
    fn from(name: &[u8]) -> Self {
        if name.eq_ignore_ascii_case(b"WARC-Record-ID") {
            WarcRecordHeaderName::WARCRecordID
        } else if name.eq_ignore_ascii_case(b"Content-Length") {
            WarcRecordHeaderName::ContentLength
        } else if name.eq_ignore_ascii_case(b"WARC-Date") {
            WarcRecordHeaderName::WARCDate
        } else if name.eq_ignore_ascii_case(b"WARC-Type") {
            WarcRecordHeaderName::WARCType
        } else if name.eq_ignore_ascii_case(b"Content-Type") {
            WarcRecordHeaderName::ContentType
        } else if name.eq_ignore_ascii_case(b"WARC-Concurrent-To") {
            WarcRecordHeaderName::WARCConcurrentTo
        } else if name.eq_ignore_ascii_case(b"WARC-Block-Digest") {
            WarcRecordHeaderName::WARCBlockDigest
        } else if name.eq_ignore_ascii_case(b"WARC-Payload-Digest") {
            WarcRecordHeaderName::WARCPayloadDigest
        } else if name.eq_ignore_ascii_case(b"WARC-IP-Address") {
            WarcRecordHeaderName::WARCIPAddress
        } else if name.eq_ignore_ascii_case(b"WARC-Refers-To") {
            WarcRecordHeaderName::WARCRefersTo
        } else if name.eq_ignore_ascii_case(b"WARC-Refers-To-Target-URI") {
            WarcRecordHeaderName::WARCRefersToTargetURI
        } else if name.eq_ignore_ascii_case(b"WARC-Refers-To-Date") {
            WarcRecordHeaderName::WARCRefersToDate
        } else if name.eq_ignore_ascii_case(b"WARC-Target-URI") {
            WarcRecordHeaderName::WARCTargetURI
        } else if name.eq_ignore_ascii_case(b"WARC-Truncated") {
            WarcRecordHeaderName::WARCTruncated
        } else if name.eq_ignore_ascii_case(b"WARC-Warcinfo-ID") {
            WarcRecordHeaderName::WARCWarcinfoID
        } else if name.eq_ignore_ascii_case(b"WARC-Filename") {
            WarcRecordHeaderName::WARCFilename
        } else if name.eq_ignore_ascii_case(b"WARC-Profile") {
            WarcRecordHeaderName::WARCProfile
        } else if name.eq_ignore_ascii_case(b"WARC-Identified-Payload-Type") {
            WarcRecordHeaderName::WARCIdentifiedPayloadType
        } else if name.eq_ignore_ascii_case(b"WARC-Segment-Number") {
            WarcRecordHeaderName::WARCSegmentNumber
        } else if name.eq_ignore_ascii_case(b"WARC-Segment-Origin-ID") {
            WarcRecordHeaderName::WARCSegmentOriginID
        } else if name.eq_ignore_ascii_case(b"WARC-Segment-Total-Length") {
            WarcRecordHeaderName::WARCSegmentTotalLength
        } else {
            WarcRecordHeaderName::Custom(name.to_vec())
        }
    }
}

#[derive(Debug)]
pub struct WarcRecordHeader {
    pub name: WarcRecordHeaderName,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub enum WarcRecordHeaderError {
    NoKey,
    NoValue,
}

impl Display for WarcRecordHeaderError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            WarcRecordHeaderError::NoKey => {
                write!(f, "NoKey")
            }
            WarcRecordHeaderError::NoValue => {
                write!(f, "NoValue")
            }
        }
    }
}

impl Error for WarcRecordHeaderError {}

impl From<httparse::Header<'_>> for WarcRecordHeader {
    fn from(value: httparse::Header) -> Self {
        Self {
            name: WarcRecordHeaderName::from(value.name.as_bytes()),
            value: value.value.to_vec(),
        }
    }
}

pub enum WarcRecordType {
    Warcinfo,
    Response,
    Resource,
    Request,
    Metadata,
    Revisit,
    Conversion,
    Continuation,
    Custom(Vec<u8>),
}

impl WarcRecordType {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            WarcRecordType::Warcinfo => b"warcinfo",
            WarcRecordType::Response => b"response",
            WarcRecordType::Resource => b"resource",
            WarcRecordType::Request => b"request",
            WarcRecordType::Metadata => b"metadata",
            WarcRecordType::Revisit => b"revisit",
            WarcRecordType::Conversion => b"conversion",
            WarcRecordType::Continuation => b"continuation",
            WarcRecordType::Custom(record_type) => record_type.as_slice(),
        }
    }
}

#[derive(Debug)]
pub enum WarcVersion {
    Warc1_1,
    Custom(Vec<u8>),
}

impl WarcVersion {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            WarcVersion::Warc1_1 => b"WARC/1.1",
            WarcVersion::Custom(warc_version) => warc_version,
        }
    }
}

fn response_status_line_as_bytes(version: Version, status: StatusCode) -> Vec<u8> {
    Vec::from(
        format!(
            "{:?} {} {}\r\n",
            version,
            status.as_u16(),
            status
                .canonical_reason()
                .or(Some("No Known Reason"))
                .unwrap()
        )
        .as_bytes(),
    )
}

trait AsBytes {
    fn as_bytes(self: &Self) -> Vec<u8>;
}

impl AsBytes for HeaderMap {
    fn as_bytes(self: &Self) -> Vec<u8> {
        let mut buf = Vec::new();
        for (name, value) in self {
            buf.extend_from_slice(name.as_str().as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        buf
    }
}

pub struct HttpResponse<R: Read> {
    pub version: Version,
    pub status: StatusCode,
    pub headers: HeaderMap<HeaderValue>,

    full_http_response: Chain<Chain<Chain<Cursor<Vec<u8>>, Cursor<Vec<u8>>>, &'static [u8]>, R>,
}

impl<R: Read> HttpResponse<R> {
    fn new(version: Version, status: StatusCode, headers: HeaderMap<HeaderValue>, body: R) -> Self {
        let full_http_response = Cursor::new(response_status_line_as_bytes(version, status))
            .chain(Cursor::new(headers.as_bytes()))
            .chain(&b"\r\n"[..])
            .chain(body);
        Self {
            version,
            status,
            headers,
            full_http_response,
        }
    }

    pub(crate) fn into_body(self) -> R {
        let (_, body) = self.full_http_response.into_inner();
        body
    }
}

impl<R: Read> Read for HttpResponse<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.full_http_response.read(buf)
    }
}

// Just call this `Payload`? WE have a different `Payload` over in warcprox-rs but so what?
pub enum WarcRecordPayload<R: Read> {
    Empty,
    Raw(R),
    HttpResponse(HttpResponse<R>),
    // HttpRequest(HttpRequest<R>),
}

#[derive(Debug, Clone)]
struct MissingInnerRead;

impl Display for MissingInnerRead {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WarcRecordPayload has no inner read because it is a WarcRecordPayload::Empty"
        )
    }
}

impl Error for MissingInnerRead {}

impl<R: Read> WarcRecordPayload<Take<R>> {
    /// Consume payload and return inner reader. Advances reader to end of payload before returning
    /// it. Returns error if payload is WarcRecordPayload::Empty since there is no inner reader.
    pub(crate) fn try_into_inner(self) -> Result<R, Box<dyn Error>> {
        // extract bounded body reader
        let maybe_body_reader: Result<Take<R>, Box<dyn Error>> = match self {
            WarcRecordPayload::Empty => Err(Box::new(MissingInnerRead)),
            WarcRecordPayload::Raw(take) => Ok(take),
            WarcRecordPayload::HttpResponse(http_response) => Ok(http_response.into_body()),
        };

        match maybe_body_reader {
            Ok(body_reader) => {
                let mut bufread = BufReader::new(body_reader);
                loop {
                    let n = bufread.fill_buf()?.len();
                    if n == 0 {
                        break;
                    }
                    bufread.consume(n);
                }
                Ok(bufread.into_inner().into_inner())
            }
            Err(e) => Err(e),
        }
    }
}

impl<R: Read> Read for WarcRecordPayload<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            WarcRecordPayload::Empty => Ok(0),
            WarcRecordPayload::Raw(body) => body.read(buf),
            WarcRecordPayload::HttpResponse(payload) => payload.read(buf),
        }
    }
}

pub struct WarcRecord<R: Read> {
    pub headers: Vec<WarcRecordHeader>,
    pub payload: WarcRecordPayload<R>,
    pub record_id: Urn,
}

impl<R: Read> WarcRecord<R> {
    pub fn into_parts(self) -> (Vec<WarcRecordHeader>, WarcRecordPayload<R>) {
        (self.headers, self.payload)
    }

    pub fn builder() -> WarcRecordBuilder<R> {
        // This record id is a placeholder so that `WarcRecord::record_id` doesn't have to be an
        // `Option`. Slyly named `WarcRecordBuilder::generate_record_id()` adds the
        // WARC-Record-ID header using the already computed value. `record_id()` can be used to
        // set the record ID to an arbitrary value.
        let record_id = Uuid::new_v4().urn();
        WarcRecordBuilder {
            version: WarcVersion::Warc1_1,
            headers: Some(Vec::new()),
            payload: WarcRecordPayload::Empty,
            record_id,
        }
    }
}

/// Doesn't block duplicate headers, though the standard disallows this, except for
/// warc-concurrent-to.
pub struct WarcRecordBuilder<R: Read> {
    version: WarcVersion,
    headers: Option<Vec<WarcRecordHeader>>,
    payload: WarcRecordPayload<R>,
    record_id: Urn,
}

impl<R: Read> WarcRecordBuilder<R> {
    pub fn body(mut self, body: R) -> Self {
        self.payload = WarcRecordPayload::Raw(body);
        self
    }

    pub fn http_response(
        mut self,
        version: Version,
        status: StatusCode,
        headers: HeaderMap<HeaderValue>,
        body: R,
    ) -> Self {
        self.payload =
            WarcRecordPayload::HttpResponse(HttpResponse::new(version, status, headers, body));
        self
    }

    pub fn version(mut self, version: WarcVersion) -> Self {
        self.version = version;
        self
    }

    pub fn add_header(mut self, header: WarcRecordHeader) -> Self {
        self.headers.as_mut().unwrap().push(header);
        self
    }

    pub fn add_header_name_value(self, name: WarcRecordHeaderName, value: &[u8]) -> Self {
        self.add_header(WarcRecordHeader {
            name,
            value: Vec::from(value),
        })
    }

    pub fn generate_record_id(self) -> Self {
        let value = &format!("<{}>", self.record_id).into_bytes();
        self.add_header_name_value(WarcRecordHeaderName::WARCRecordID, value)
    }

    pub fn record_id(self, record_id: &[u8]) -> Self {
        self.add_header_name_value(WarcRecordHeaderName::WARCRecordID, record_id)
    }

    pub fn warc_type(self, warc_type: WarcRecordType) -> Self {
        self.add_header_name_value(WarcRecordHeaderName::WARCType, warc_type.as_bytes())
    }

    /// Doesn't enforce that this matches actual length of body.
    pub fn content_length(self, content_length: u64) -> Self {
        self.add_header_name_value(
            WarcRecordHeaderName::ContentLength,
            content_length.to_string().as_bytes(),
        )
    }

    pub fn warc_date(self, warc_date: DateTime<Utc>) -> Self {
        self.add_header_name_value(
            WarcRecordHeaderName::WARCDate,
            warc_date
                .to_rfc3339_opts(SecondsFormat::Micros, true)
                .as_bytes(),
        )
    }

    pub fn content_type(self, content_type: &[u8]) -> Self {
        self.add_header_name_value(WarcRecordHeaderName::ContentType, content_type)
    }

    pub fn warc_filename(self, filename: &[u8]) -> Self {
        self.add_header_name_value(WarcRecordHeaderName::WARCFilename, filename)
    }

    pub fn warc_target_uri(self, uri: &[u8]) -> Self {
        self.add_header_name_value(WarcRecordHeaderName::WARCTargetURI, uri)
    }

    pub fn warc_payload_digest(self, digest: &[u8]) -> Self {
        self.add_header_name_value(WarcRecordHeaderName::WARCPayloadDigest, digest)
    }

    pub fn build(mut self) -> WarcRecord<R> {
        WarcRecord {
            headers: self.headers.take().unwrap(),
            payload: self.payload,
            record_id: self.record_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{WarcRecord, WarcRecordHeaderName, WarcRecordType};
    use chrono::{TimeZone, Utc};
    use regex::bytes::Regex;
    use std::error::Error;
    use std::io::{empty, Read};
    use std::str::from_utf8;

    #[test]
    fn test_minimal_record() -> Result<(), Box<dyn Error>> {
        let body: Box<dyn Read> = Box::new(empty());
        let record: WarcRecord<Box<dyn Read>> = WarcRecord::builder()
            .generate_record_id()
            .body(body)
            .build();
        let (headers, mut payload) = record.into_parts();

        assert_eq!(headers.len(), 1);
        assert_eq!(&headers[0].name.as_bytes(), b"WARC-Record-ID");
        let re = Regex::new(
            r"^<urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}>$",
        )?;
        assert!(
            re.is_match(&headers[0].value),
            "warc-record-id {} does not match regex {}",
            from_utf8(&headers[0].value)?,
            re
        );

        let mut buf = Vec::new();
        payload.read_to_end(&mut buf)?;
        assert_eq!(buf, b"");
        Ok(())
    }

    #[test]
    fn test_all_the_headers() {
        let body: Box<dyn Read> = Box::new(empty());
        let record: WarcRecord<Box<dyn Read>> = WarcRecord::builder()
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

        let (headers, _) = record.into_parts();

        assert_eq!(headers.len(), 8);
        assert_eq!(&headers[0].name.as_bytes(), b"WARC-Record-ID");
        assert_eq!(&headers[1].name.as_bytes(), b"WARC-Type");
        assert_eq!(&headers[1].value, b"resource");
        assert_eq!(&headers[2].name.as_bytes(), b"Content-Length");
        assert_eq!(&headers[2].value, b"100");
        assert_eq!(&headers[3].name.as_bytes(), b"WARC-Date");
        assert_eq!(&headers[3].value, b"2023-01-01T00:00:00.000000Z");
        assert_eq!(&headers[4].name.as_bytes(), b"Content-Type");
        assert_eq!(&headers[4].value, b"text/plain; charset=utf-8");
        assert_eq!(&headers[5].name.as_bytes(), b"WARC-Filename");
        assert_eq!(&headers[5].value, b"test.warc");
        assert_eq!(&headers[6].name.as_bytes(), b"WARC-Target-URI");
        assert_eq!(&headers[6].value, b"https://example.com/foo.txt");
        assert_eq!(&headers[7].name.as_bytes(), b"WARC-Payload-Digest");
        assert_eq!(
            &headers[7].value,
            b"sha256:0b0edecafc0ffeec0c0acafef00ddeadface0ffaccededd00dadeffacedd00d9"
        );
    }

    #[test]
    fn test_custom_header() {
        let body: Box<dyn Read> = Box::new(empty());
        let record: WarcRecord<Box<dyn Read>> = WarcRecord::builder()
            .generate_record_id()
            .add_header_name_value(
                WarcRecordHeaderName::Custom(b"custom-warc-header".to_vec()),
                b"toot",
            )
            .body(body)
            .build();
        let (headers, _) = record.into_parts();
        assert_eq!(headers.len(), 2);
        assert_eq!(&headers[0].name.as_bytes(), b"WARC-Record-ID");
        assert_eq!(&headers[1].name.as_bytes(), b"custom-warc-header");
        assert_eq!(&headers[1].value, b"toot");
    }

    #[test]
    fn test_custom_warc_type() {
        let body: Box<dyn Read> = Box::new(empty());
        let record: WarcRecord<Box<dyn Read>> = WarcRecord::builder()
            .generate_record_id()
            .warc_type(WarcRecordType::Custom(b"special".to_vec()))
            .body(body)
            .build();
        let (headers, _) = record.into_parts();
        assert_eq!(headers.len(), 2);
        assert_eq!(&headers[0].name.as_bytes(), b"WARC-Record-ID");
        assert_eq!(&headers[1].name.as_bytes(), b"WARC-Type");
        assert_eq!(&headers[1].value, b"special");
    }

    #[test]
    fn test_header_name_from() {
        for orig_header_name in [
            WarcRecordHeaderName::WARCRecordID,
            WarcRecordHeaderName::ContentLength,
            WarcRecordHeaderName::WARCDate,
            WarcRecordHeaderName::WARCType,
            WarcRecordHeaderName::ContentType,
            WarcRecordHeaderName::WARCConcurrentTo,
            WarcRecordHeaderName::WARCBlockDigest,
            WarcRecordHeaderName::WARCPayloadDigest,
            WarcRecordHeaderName::WARCIPAddress,
            WarcRecordHeaderName::WARCRefersTo,
            WarcRecordHeaderName::WARCRefersToTargetURI,
            WarcRecordHeaderName::WARCRefersToDate,
            WarcRecordHeaderName::WARCTargetURI,
            WarcRecordHeaderName::WARCTruncated,
            WarcRecordHeaderName::WARCWarcinfoID,
            WarcRecordHeaderName::WARCFilename,
            WarcRecordHeaderName::WARCProfile,
            WarcRecordHeaderName::WARCIdentifiedPayloadType,
            WarcRecordHeaderName::WARCSegmentNumber,
            WarcRecordHeaderName::WARCSegmentOriginID,
            WarcRecordHeaderName::WARCSegmentTotalLength,
        ] {
            assert_eq!(
                WarcRecordHeaderName::from(&*orig_header_name.as_bytes().to_ascii_lowercase()),
                orig_header_name
            );
            assert_eq!(
                WarcRecordHeaderName::from(&*orig_header_name.as_bytes().to_ascii_lowercase()),
                orig_header_name
            );
        }
    }

    #[test]
    fn test_header_name_from_custom() {
        let custom_value = b"something-else";
        let header_name = WarcRecordHeaderName::from(&custom_value[..]);
        match header_name {
            WarcRecordHeaderName::Custom(value) => {
                assert_eq!(value, custom_value);
            }
            _ => {
                assert!(false);
            }
        }
    }
}
