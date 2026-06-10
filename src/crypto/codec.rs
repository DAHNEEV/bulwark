use std::io::{self, BufReader, Read, Write};

pub enum Encoder<W: Write> {
    Zstd(zstd::Encoder<'static, W>),
    None(W),
}

impl<W: Write> Write for Encoder<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Zstd(e) => e.write(buf),
            Self::None(e) => e.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Zstd(e) => e.flush(),
            Self::None(e) => e.flush(),
        }
    }
}

impl<W: Write> Encoder<W> {
    pub fn finish(self) -> io::Result<W> {
        match self {
            Self::Zstd(e) => e.finish(),
            Self::None(e) => Ok(e),
        }
    }
}

pub enum Decoder<R: Read> {
    Zstd(zstd::Decoder<'static, BufReader<R>>),
    None(R),
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Zstd(d) => d.read(buf),
            Self::None(d) => d.read(buf),
        }
    }
}
