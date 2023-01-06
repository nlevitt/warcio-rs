use crate::WarcRecordHeaderName::*;
use crate::WarcStandardRecordHeaderName::*;
use std::io::{empty, Read};
use uuid::Uuid;

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
            WARCRecordID => b"WARC-Record-ID",
            ContentLength => b"Content-Length",
            WARCDate => b"WARC-Date",
            WARCType => b"WARC-Type",
            ContentType => b"Content-Type",
            WARCConcurrentTo => b"WARC-Concurrent-To",
            WARCBlockDigest => b"WARC-Block-Digest",
            WARCPayloadDigest => b"WARC-Payload-Digest",
            WARCIPAddress => b"WARC-IP-Address",
            WARCRefersTo => b"WARC-Refers-To",
            WARCRefersToTargetURI => b"WARC-Refers-To-Target-URI",
            WARCRefersToDate => b"WARC-Refers-To-Date",
            WARCTargetURI => b"WARC-Target-URI",
            WARCTruncated => b"WARC-Truncated",
            WARCWARCinfoID => b"WARC-Warcinfo-ID",
            WARCFilename => b"WARC-Filename",
            WARCProfile => b"WARC-Profile",
            WARCIDentifiedPayloadType => b"WARC-Identified-Payload-Type",
            WARCSegmentNumber => b"WARC-Segment-Number",
            WARCSegmentOriginID => b"WARC-Segment-Origin-ID",
            WARCSegmentTotalLength => b"WARC-Segment-Total-Length",
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
            Standard(name) => name.value(),
            Custom(name) => name.as_slice(),
        }
    }
}

pub struct WarcRecordHeader {
    pub name: WarcRecordHeaderName,
    pub value: Vec<u8>,
}

pub struct WarcRecord {
    headers: Vec<WarcRecordHeader>,
    body: Box<dyn Read>,
}

impl WarcRecord {
    pub fn into_parts(self) -> (Vec<WarcRecordHeader>, Box<dyn Read>) {
        (self.headers, self.body)
    }
}

pub struct WarcRecordBuilder {
    headers: Option<Vec<WarcRecordHeader>>,
    body: Option<Box<dyn Read>>,
}

impl WarcRecordBuilder {
    pub fn new() -> Self {
        WarcRecordBuilder {
            headers: Some(vec![WarcRecordHeader {
                name: Standard(WARCRecordID),
                value: format!("<{}>", Uuid::new_v4().urn()).into_bytes(),
            }]),
            body: Some(Box::new(empty())),
        }
    }

    pub fn body(mut self, body: Box<dyn Read>) -> Self {
        self.body = Some(body);
        self
    }

    pub fn build(mut self) -> WarcRecord {
        WarcRecord {
            headers: self.headers.take().unwrap(),
            body: self.body.take().unwrap(),
        }
    }
}
