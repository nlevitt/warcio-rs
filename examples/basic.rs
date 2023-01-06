use std::fs::{File, OpenOptions};
use warcio_rs::{WarcRecord, WarcWriter};

fn main() {
   let mut f = OpenOptions::new().create_new(true).write(true).open("basic.warc")?;
   let warc_writer = WarcWriter::from(f);

   // let record = WarcRecord {
   // }
}