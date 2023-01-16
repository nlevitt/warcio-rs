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

pub struct WarcRecordBuilder {
    headers: Option<Vec<WarcRecordHeader>>,
    body: Option<Box<dyn Read>>,
}

impl WarcRecordBuilder {
    pub fn body(mut self, body: Box<dyn Read>) -> Self {
        self.body = Some(body);
        self
    }

    pub fn warc_type(mut self, warc_type: WarcRecordType) -> Self {
        self.headers.as_mut().unwrap().push(WarcRecordHeader {
            name: WarcRecordHeaderName::WARCType,
            value: Vec::from(warc_type.as_bytes()),
        });
        self
    }

    pub fn content_length(mut self, content_length: u64) -> Self {
        self.headers.as_mut().unwrap().push(WarcRecordHeader {
            name: WarcRecordHeaderName::ContentLength,
            value: content_length.to_string().into_bytes(),
        });
        self
    }

    pub fn warc_date(mut self, warc_date: DateTime<Utc>) -> Self {
        self.headers.as_mut().unwrap().push(WarcRecordHeader {
            name: WarcRecordHeaderName::WARCDate,
            value: warc_date
                .to_rfc3339_opts(SecondsFormat::Micros, true)
                .into_bytes(),
        });
        self
    }

    pub fn content_type(mut self, content_type: &[u8]) -> Self {
        self.headers.as_mut().unwrap().push(WarcRecordHeader {
            name: WarcRecordHeaderName::ContentType,
            value: Vec::from(content_type),
        });
        self
    }

    pub fn warc_filename(mut self, filename: &[u8]) -> Self {
        self.headers.as_mut().unwrap().push(WarcRecordHeader {
            name: WarcRecordHeaderName::WARCFilename,
            value: Vec::from(filename),
        });
        self
    }

    pub fn warc_target_uri(mut self, uri: &[u8]) -> Self {
        self.headers.as_mut().unwrap().push(WarcRecordHeader {
            name: WarcRecordHeaderName::WARCTargetURI,
            value: Vec::from(uri),
        });
        self
    }

    pub fn warc_payload_digest(mut self, digest: &[u8]) -> Self {
        self.headers.as_mut().unwrap().push(WarcRecordHeader {
            name: WarcRecordHeaderName::WARCPayloadDigest,
            value: Vec::from(digest),
        });
        self
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
    use crate::{WarcRecord, WarcRecordHeaderName};
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
}
