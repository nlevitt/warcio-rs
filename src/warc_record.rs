use std::io::{empty, Read, Write};
use uuid::Uuid;
use crate::WarcStandardRecordHeaderName::WARCRecordID;

// https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/#named-fields
pub enum WarcStandardRecordHeaderName {
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
    WARCWARCinfoID,
    WARCFilename,
    WARCProfile,
    WARCIDentifiedPayloadType,
    WARCSegmentNumber,
    WARCSegmentOriginID,
    WARCSegmentTotalLength,
}

impl WarcStandardRecordHeaderName {
    pub fn value(&self) -> &'static [u8] {
        match self {
            WarcStandardRecordHeaderName::WARCRecordID => b"WARC-Record-ID",
            WarcStandardRecordHeaderName::ContentLength => b"Content-Length",
            WarcStandardRecordHeaderName::WARCDate => b"WARC-Date",
            WarcStandardRecordHeaderName::WARCType => b"WARC-Type",
            WarcStandardRecordHeaderName::ContentType => b"Content-Type",
            WarcStandardRecordHeaderName::WARCConcurrentTo => b"WARC-Concurrent-To",
            WarcStandardRecordHeaderName::WARCBlockDigest => b"WARC-Block-Digest",
            WarcStandardRecordHeaderName::WARCPayloadDigest => b"WARC-Payload-Digest",
            WarcStandardRecordHeaderName::WARCIPAddress => b"WARC-IP-Address",
            WarcStandardRecordHeaderName::WARCRefersTo => b"WARC-Refers-To",
            WarcStandardRecordHeaderName::WARCRefersToTargetURI => b"WARC-Refers-To-Target-URI",
            WarcStandardRecordHeaderName::WARCRefersToDate => b"WARC-Refers-To-Date",
            WarcStandardRecordHeaderName::WARCTargetURI => b"WARC-Target-URI",
            WarcStandardRecordHeaderName::WARCTruncated => b"WARC-Truncated",
            WarcStandardRecordHeaderName::WARCWARCinfoID => b"WARC-Warcinfo-ID",
            WarcStandardRecordHeaderName::WARCFilename => b"WARC-Filename",
            WarcStandardRecordHeaderName::WARCProfile => b"WARC-Profile",
            WarcStandardRecordHeaderName::WARCIDentifiedPayloadType => {
                b"WARC-Identified-Payload-Type"
            }
            WarcStandardRecordHeaderName::WARCSegmentNumber => b"WARC-Segment-Number",
            WarcStandardRecordHeaderName::WARCSegmentOriginID => b"WARC-Segment-Origin-ID",
            WarcStandardRecordHeaderName::WARCSegmentTotalLength => b"WARC-Segment-Total-Length",
        }
    }
}

pub enum WarcRecordHeaderName {
    Standard(WarcStandardRecordHeaderName),
    Custom(Vec<u8>),
}

impl WarcRecordHeaderName {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            WarcRecordHeaderName::Standard(name) => name.value(),
            WarcRecordHeaderName::Custom(name) => name.as_slice(),
        }
    }
}

pub struct WarcRecordHeader {
    name: WarcRecordHeaderName,
    value: Vec<u8>,
}

pub struct WarcRecord<R: Read> {
    headers: Vec<WarcRecordHeader>,
    body: R,
}

impl<R: Read> WarcRecord<R> {
    pub fn into_parts(self) -> (Vec<WarcRecordHeader>, R) {
        (self.headers, self.body)
    }
}

pub struct WarcRecordBuilder<R: Read> {
    headers: Option<Vec<WarcRecordHeader>>,
    body: Option<R>,
}

impl<R: Read> WarcRecordBuilder<R> {
    pub fn new() -> Self {
        WarcRecordBuilder {
            headers: Some(vec![
                WarcRecordHeader {
                    name: WarcRecordHeaderName::Standard(WARCRecordID),
                    value: format!("<{}>", Uuid::new_v4().urn()).into_bytes();
                }
            ]),
            body: Some(empty())
        }
    }

    pub fn body(mut self, body: R) -> Self {
        self.body = Some(body);
        self
    }

    pub fn build(mut self) -> WarcRecord<R> {
        WarcRecord {
            headers: self.headers.take().unwrap(),
            body: self.body.take().unwrap(),
        }
    }
}