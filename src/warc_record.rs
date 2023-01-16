use chrono::{DateTime, SecondsFormat, Utc};
use std::io::{empty, Read};
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

pub struct WarcRecordHeader {
    pub name: WarcRecordHeaderName,
    pub value: Vec<u8>,
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

pub struct WarcRecord {
    headers: Vec<WarcRecordHeader>,
    body: Box<dyn Read>,
}

impl WarcRecord {
    pub(crate) fn into_parts(self) -> (Vec<WarcRecordHeader>, Box<dyn Read>) {
        (self.headers, self.body)
    }

    pub fn builder() -> WarcRecordBuilder {
        WarcRecordBuilder {
            headers: Some(vec![WarcRecordHeader {
                name: WarcRecordHeaderName::WARCRecordID,
                value: format!("<{}>", Uuid::new_v4().urn()).into_bytes(),
            }]),
            body: Some(Box::new(empty())),
        }
    }
}

/// Doesn't block duplicate headers, though the standard disallows this, except for
/// warc-concurrent-to.
pub struct WarcRecordBuilder {
    headers: Option<Vec<WarcRecordHeader>>,
    body: Option<Box<dyn Read>>,
}

impl WarcRecordBuilder {
    pub fn body(mut self, body: Box<dyn Read>) -> Self {
        self.body = Some(body);
        self
    }

    pub fn add_header(mut self, name: WarcRecordHeaderName, value: &[u8]) -> Self {
        self.headers.as_mut().unwrap().push(WarcRecordHeader {
            name,
            value: Vec::from(value),
        });
        self
    }

    pub fn warc_type(self, warc_type: WarcRecordType) -> Self {
        self.add_header(WarcRecordHeaderName::WARCType, warc_type.as_bytes())
    }

    /// Doesn't enforce that this matches actual length of body.
    pub fn content_length(self, content_length: u64) -> Self {
        self.add_header(
            WarcRecordHeaderName::ContentLength,
            content_length.to_string().as_bytes(),
        )
    }

    pub fn warc_date(self, warc_date: DateTime<Utc>) -> Self {
        self.add_header(
            WarcRecordHeaderName::WARCDate,
            warc_date
                .to_rfc3339_opts(SecondsFormat::Micros, true)
                .as_bytes(),
        )
    }

    pub fn content_type(self, content_type: &[u8]) -> Self {
        self.add_header(WarcRecordHeaderName::ContentType, content_type)
    }

    pub fn warc_filename(self, filename: &[u8]) -> Self {
        self.add_header(WarcRecordHeaderName::WARCFilename, filename)
    }

    pub fn warc_target_uri(self, uri: &[u8]) -> Self {
        self.add_header(WarcRecordHeaderName::WARCTargetURI, uri)
    }

    pub fn warc_payload_digest(self, digest: &[u8]) -> Self {
        self.add_header(WarcRecordHeaderName::WARCPayloadDigest, digest)
    }

    pub fn build(mut self) -> WarcRecord {
        WarcRecord {
            headers: self.headers.take().unwrap(),
            body: self.body.take().unwrap(),
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
        let record = WarcRecord::builder().build();
        let (headers, mut body) = record.into_parts();

        assert_eq!(headers.len(), 1);
        assert!(&headers[0].name == &WarcRecordHeaderName::WARCRecordID);
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
        assert!(&headers[0].name == &WarcRecordHeaderName::WARCRecordID);
        assert!(&headers[1].name == &WarcRecordHeaderName::WARCType);
        assert_eq!(&headers[1].value, b"resource");
        assert!(&headers[2].name == &WarcRecordHeaderName::ContentLength);
        assert_eq!(&headers[2].value, b"100");
        assert!(&headers[3].name == &WarcRecordHeaderName::WARCDate);
        assert_eq!(&headers[3].value, b"2023-01-01T00:00:00.000000Z");
        assert!(&headers[4].name == &WarcRecordHeaderName::ContentType);
        assert_eq!(&headers[4].value, b"text/plain; charset=utf-8");
        assert!(&headers[5].name == &WarcRecordHeaderName::WARCFilename);
        assert_eq!(&headers[5].value, b"test.warc");
        assert!(&headers[6].name == &WarcRecordHeaderName::WARCTargetURI);
        assert_eq!(&headers[6].value, b"https://example.com/foo.txt");
        assert!(&headers[7].name == &WarcRecordHeaderName::WARCPayloadDigest);
        assert_eq!(
            &headers[7].value,
            b"sha256:0b0edecafc0ffeec0c0acafef00ddeadface0ffaccededd00dadeffacedd00d9"
        );
    }

    #[test]
    fn test_custom_header() {
        let record = WarcRecord::builder()
            .add_header(
                WarcRecordHeaderName::Custom(b"custom-warc-header".to_vec()),
                b"toot",
            )
            .build();
        let (headers, _) = record.into_parts();
        assert_eq!(headers.len(), 2);
        assert!(&headers[0].name == &WarcRecordHeaderName::WARCRecordID);
        assert!(&headers[1].name == &WarcRecordHeaderName::Custom(b"custom-warc-header".to_vec()));
        assert!(&headers[1].value == b"toot");
    }

    #[test]
    fn test_custom_warc_type() {
        let record = WarcRecord::builder()
            .warc_type(WarcRecordType::Custom(b"special".to_vec()))
            .build();
        let (headers, _) = record.into_parts();
        assert_eq!(headers.len(), 2);
        assert!(&headers[0].name == &WarcRecordHeaderName::WARCRecordID);
        assert!(&headers[1].name == &WarcRecordHeaderName::WARCType);
        assert_eq!(&headers[1].value, b"special");
    }
}
