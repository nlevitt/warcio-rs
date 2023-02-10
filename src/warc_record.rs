use chrono::{DateTime, SecondsFormat, Utc};
use std::fmt::{Display, Formatter};
use std::io::{empty, Read};
use uuid::fmt::Urn;
use uuid::Uuid;

// https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/#named-fields
#[derive(PartialEq, Eq)]
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

impl std::error::Error for WarcRecordHeaderError {}

// impl TryFrom<&[u8]> for WarcRecordHeader {
//     type Error = WarcRecordHeaderError;
//
//     fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
//         // value.split()
//         let mut key_and_value = value.splitn(2, |b| b == &b':');
//         let key = key_and_value.next().ok_or(WarcRecordHeaderError::NoKey)?;
//         let value = key_and_value.next().ok_or(WarcRecordHeaderError::NoValue)?;
//         let header_name = WarcRecordHeaderName::from(key);
//         Ok(Self {
//             name: header_name,
//             value: value.to_vec(),
//         })
//     }
// }
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

pub enum WarcVersion {
    WARC_1_1,
    Custom(Vec<u8>),
}

impl WarcVersion {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            WarcVersion::WARC_1_1 => b"WARC/1.1",
            WarcVersion::Custom(warc_version) => warc_version,
        }
    }
}

pub struct WarcRecord {
    headers: Vec<WarcRecordHeader>,
    body: Box<dyn Read>,
    pub record_id: Urn,
}

impl WarcRecord {
    pub(crate) fn into_parts(self) -> (Vec<WarcRecordHeader>, Box<dyn Read>) {
        (self.headers, self.body)
    }

    pub fn builder() -> WarcRecordBuilder {
        let record_id = Uuid::new_v4().urn();
        WarcRecordBuilder {
            version: WarcVersion::WARC_1_1,
            headers: Some(Vec::new()),
            body: Some(Box::new(empty())),
            record_id,
        }
    }
}

/// Doesn't block duplicate headers, though the standard disallows this, except for
/// warc-concurrent-to.
pub struct WarcRecordBuilder {
    version: WarcVersion,
    headers: Option<Vec<WarcRecordHeader>>,
    body: Option<Box<dyn Read>>,
    record_id: Urn,
}

impl WarcRecordBuilder {
    pub fn body(mut self, body: Box<dyn Read>) -> Self {
        self.body = Some(body);
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

    pub fn add_header_name_value(mut self, name: WarcRecordHeaderName, value: &[u8]) -> Self {
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

    pub fn build(mut self) -> WarcRecord {
        WarcRecord {
            headers: self.headers.take().unwrap(),
            body: self.body.take().unwrap(),
            record_id: self.record_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{WarcRecord, WarcRecordHeaderName, WarcRecordType};
    use chrono::{TimeZone, Utc};
    use regex::bytes::Regex;
    use std::io::Read;
    use std::str::from_utf8;

    #[test]
    fn test_minimal_record() {
        let record = WarcRecord::builder().generate_record_id().build();
        let (headers, mut body) = record.into_parts();

        assert_eq!(headers.len(), 1);
        assert_eq!(&headers[0].name.as_bytes(), b"WARC-Record-ID");
        let re = Regex::new(
            r"^<urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}>$",
        )
        .unwrap();
        assert!(
            re.is_match(&headers[0].value),
            "warc-record-id {} does not match regex {}",
            from_utf8(&headers[0].value).unwrap(),
            re
        );

        let mut buf = Vec::new();
        body.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"");
    }

    #[test]
    fn test_all_the_headers() {
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
        let record = WarcRecord::builder()
            .generate_record_id()
            .add_header_name_value(
                WarcRecordHeaderName::Custom(b"custom-warc-header".to_vec()),
                b"toot",
            )
            .build();
        let (headers, _) = record.into_parts();
        assert_eq!(headers.len(), 2);
        assert_eq!(&headers[0].name.as_bytes(), b"WARC-Record-ID");
        assert_eq!(&headers[1].name.as_bytes(), b"custom-warc-header");
        assert_eq!(&headers[1].value, b"toot");
    }

    #[test]
    fn test_custom_warc_type() {
        let record = WarcRecord::builder()
            .generate_record_id()
            .warc_type(WarcRecordType::Custom(b"special".to_vec()))
            .build();
        let (headers, _) = record.into_parts();
        assert_eq!(headers.len(), 2);
        assert_eq!(&headers[0].name.as_bytes(), b"WARC-Record-ID");
        assert_eq!(&headers[1].name.as_bytes(), b"WARC-Type");
        assert_eq!(&headers[1].value, b"special");
    }
}
