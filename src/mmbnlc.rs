/*

MIT License

Copyright (c) 2023 Prof. 9

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


*/

pub enum LCnbExe {}
pub enum LCOverlayUnk {}
pub enum LCOverlayPicture {}
pub enum LCObjUnk {}

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug)]
    pub struct CPUFlags: u32 {
        const NONE = 0x0;
        const N = 0x1;
        const C = 0x2;
        const Z = 0x4;
        const V = 0x8;
        const UPDATE_N = 0x10;
        const UPDATE_C = 0x20;
        const UPDATE_Z = 0x40;
        const UPDATE_V = 0x80;
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct GBAFuncID(u32);

#[derive(Copy, Clone, Debug)]
#[repr(C, align(64))]
pub struct GBAState {
    pub r0: u32,
    pub r1: u32,
    pub r2: u32,
    pub r3: u32,
    pub r4: u32,
    pub r5: u32,
    pub r6: u32,
    pub r7: u32,
    pub r8: u32,
    pub r9: u32,
    pub r10: u32,
    pub r11: u32,
    pub r12: u32,
    pub sp: u32,
    pub lr: GBAFuncID,
    pub pc: GBAFuncID,
    pub flags: CPUFlags,
    pub flags_implicit_update: CPUFlags,
    pub memory: *mut u8,
    pub stack_bottom: *mut u8,
    pub owner: *const LCnbExe,
    pub addr_ldmia_stmia: u32,
    pub stack_count: u32,
    pub call_depth: u32,
    pub always1: u32,
    pub is_alt_entry: bool,
    pub overlay_unk: *const LCOverlayUnk,
    pub overlay_bg: *const LCOverlayPicture,
    pub overlay_obj: *const LCOverlayPicture,
    pub obj_unk: *const LCObjUnk,
}

impl GBAState {
    pub fn read_u8(&self, addr: u32) -> u8 {
        unsafe { *(self.memory.offset(addr.try_into().unwrap()) as *const u8) }
    }
    pub fn read_u16(&self, addr: u32) -> u16 {
        unsafe { *(self.memory.offset(addr.try_into().unwrap()) as *const u16) }
    }
    pub fn read_u32(&self, addr: u32) -> u32 {
        unsafe { *(self.memory.offset(addr.try_into().unwrap()) as *const u32) }
    }
    pub fn write_u8(&self, addr: u32, val: u8) {
        unsafe { *(self.memory.offset(addr.try_into().unwrap()) as *mut u8) = val }
    }
    pub fn write_u16(&self, addr: u32, val: u16) {
        unsafe { *(self.memory.offset(addr.try_into().unwrap()) as *mut u16) = val }
    }
    pub fn write_u32(&self, addr: u32, val: u32) {
        unsafe { *(self.memory.offset(addr.try_into().unwrap()) as *mut u32) = val }
    }

    pub unsafe fn from_addr<'a>(addr: u64) -> &'a mut Self {
        &mut *(addr as *mut Self)
    }
}

pub type GBAFunc = extern "C" fn(*mut GBAState) -> GBAFuncID;
