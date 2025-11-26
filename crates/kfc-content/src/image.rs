mod decode;
mod encode;
mod format;
mod wrapper;

pub use decode::*;
pub use encode::*;
pub use format::*;
pub use wrapper::*;

pub fn size_of_format(
    format: PixelFormat,
    width: usize,
    height: usize,
) -> usize {
    let (block_width, block_height) = format.block_extent();
    let width = width.div_ceil(block_width);
    let height = height.div_ceil(block_height);

    width * height * format.block_size()
}
