use std::os::unix::io::AsRawFd;
use gbm::{BufferObject as GbmBuffer, Device as GbmDevice, BufferObjectFlags};
use super::{Allocator, Buffer, Format, Fourcc, Modifier, dmabuf::Dmabuf};

impl<A: AsRawFd + 'static, T> Allocator<GbmBuffer<T>> for GbmDevice<A> {
    type Error = std::io::Error;

    fn create_buffer(&mut self, width: u32, height: u32, format: Format) -> std::io::Result<GbmBuffer<T>> {
        if format.modifier == Modifier::Invalid || format.modifier == Modifier::Linear {
            let mut usage = BufferObjectFlags::SCANOUT | BufferObjectFlags::RENDERING;
            if format.modifier == Modifier::Linear {
                usage |= BufferObjectFlags::LINEAR;
            }
            self.create_buffer_object(width, height, format.code, usage)
        } else {
            self.create_buffer_object_with_modifiers(width, height, format.code, Some(format.modifier).into_iter())
        }
    }
}

impl<T> Buffer for GbmBuffer<T> {
    fn width(&self) -> u32 {
        self.width().unwrap_or(0)
    }

    fn height(&self) -> u32 {
        self.height().unwrap_or(0)
    }

    fn format(&self) -> Format {
        Format {
            code: self.format().unwrap_or(Fourcc::Argb8888), // we got to return something, but this should never happen anyway
            modifier: self.modifier().unwrap_or(Modifier::Invalid),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum GbmConvertError {
    #[error("The gbm device was destroyed")]
    DeviceDestroyed(#[from] gbm::DeviceDestroyedError),
    #[error("Buffer consists out of multiple file descriptors, which is currently unsupported")]
    UnsupportedBuffer,
    #[error("Buffer returned invalid file descriptor")]
    InvalidFD,
}

impl<T> std::convert::TryFrom<GbmBuffer<T>> for Dmabuf {
    type Error = GbmConvertError;

    fn try_from(buf: GbmBuffer<T>) -> Result<Self, GbmConvertError> {
        let planes = buf.plane_count()? as i32;

        //TODO switch to gbm_bo_get_plane_fd when it lands
        let mut iter = (0i32..planes).map(|i| buf.handle_for_plane(i));
        let first = iter.next().expect("Encountered a buffer with zero planes");
        if iter.try_fold(first, |first, next| {
            if let (Ok(next), Ok(first)) = (next, first) {
                if unsafe { next.u64_ == first.u64_ } {
                    return Some(Ok(first));
                }
            }
            None
        }).is_none() {
            // GBM is lacking a function to get a FD for a given plane. Instead,
            // check all planes have the same handle. We can't use
            // drmPrimeHandleToFD because that messes up handle ref'counting in
            // the user-space driver.
            return Err(GbmConvertError::UnsupportedBuffer); //TODO
        }

        let fds = [buf.fd()?, 0, 0, 0];
        //if fds.iter().any(|fd| fd == 0) {
        if fds[0] < 0 {
            return Err(GbmConvertError::InvalidFD);
        }

        let offsets = (0i32..planes).map(|i| buf.offset(i)).collect::<Result<Vec<u32>, gbm::DeviceDestroyedError>>()?;
        let strides = (0i32..planes).map(|i| buf.stride_for_plane(i)).collect::<Result<Vec<u32>, gbm::DeviceDestroyedError>>()?;

        Ok(Dmabuf::new(buf, planes as usize, &offsets, &strides, &fds).unwrap())
    }
}