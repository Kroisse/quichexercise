use std::fmt;

use anyhow::anyhow;
use ring::rand::*;

use crate::Error;

pub type Scid = [u8; quiche::MAX_CONN_ID_LEN];

pub fn new_scid() -> Result<Scid, Error> {
    let mut scid = Scid::default();
    SystemRandom::new()
        .fill(&mut scid[..])
        .map_err(|_| anyhow!("crypto error"))?;
    Ok(scid)
}

pub struct HexDump<'a>(&'a [u8]);

impl<'a> From<&'a [u8]> for HexDump<'a> {
    fn from(buf: &'a [u8]) -> Self {
        Self(buf)
    }
}

impl fmt::Display for HexDump<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}
