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

pub mod memsearch;
pub mod mmbnlc;
pub mod RSFACE;
pub mod BMFACE;
use crate::mmbnlc::*;
use mlua::prelude::*;

static mut HOOKS: Vec<ilhook::x64::HookPoint> = Vec::new();

static mut gamever: u8=0;
static mut FACELOC: u32=0;
static mut FACEPALLOC: u32=0;
static mut currSoul: u8=0;
static mut total: u32=0;
static mut total2: u32=0;

#[allow(non_upper_case_globals)]
//static EXE4_SceFlagsOn2: std::sync::OnceLock<GBAFunc> = std::sync::OnceLock::new();


fn hook_direct(addr: usize, func: ilhook::x64::JmpToRetRoutine, user_data: usize) {
    let hooker = ilhook::x64::Hooker::new(
        addr,
        ilhook::x64::HookType::JmpToRet(func),
        ilhook::x64::CallbackOption::None,
        user_data,
        ilhook::x64::HookFlags::empty(),
    );
    let hook = unsafe { hooker.hook() };
    let hook = hook.expect(format!("Failed to hook {addr:#X}!").as_str());

    unsafe { &mut HOOKS }.push(hook);
}



fn hook_direct2(addr: usize, func: ilhook::x64::JmpBackRoutine, user_data: usize) {
    let hooker = ilhook::x64::Hooker::new(
        addr,
        ilhook::x64::HookType::JmpBack(func),
        ilhook::x64::CallbackOption::None,
        user_data,
        ilhook::x64::HookFlags::empty(),
    );
    let hook = unsafe { hooker.hook() };
    let hook = hook.expect(format!("Failed to hook {addr:#X}!").as_str());

    unsafe { &mut HOOKS }.push(hook);
}

fn FakeMemCopy(LCRAM:*mut u8,off: u32, WhatToCOPY: &[u8],Leng:u16) {

    for n in 0..Leng {
        unsafe { *(LCRAM.offset((off+(n as u32) ).try_into().unwrap()) as *mut u8) = WhatToCOPY[n as usize] }    ;

    }

}
fn comp(LCRAM:*mut u8,off: u32, head: &[u8],Leng:u16)  ->bool {
for n in 0..Leng {
let x= unsafe { *(LCRAM.offset((off+(n as u32) ).try_into().unwrap()) as *const u8)};
if x!=head[n as usize] {
return false;
}
}



return true;

}


#[mlua::lua_module]
fn hello(lua: &Lua) -> LuaResult<LuaValue> {
    let text_section = lua
        .globals()
        .get::<_, LuaTable>("chaudloader")?
        .get::<_, LuaTable>("GAME_ENV")?
        .get::<_, LuaTable>("sections")?
        .get::<_, LuaTable>("text")?;
    let text_address = text_section.get::<_, LuaInteger>("address")? as usize;
    let text_size = text_section.get::<_, LuaInteger>("size")? as usize;

  
  


   // println!("Hook...");
    let ptrs_life = memsearch::find_n_in(
        "e8 f1 41 9c ff 8b 43 40 c1 e8 02 a8 01 0f 85 eb 00 00 00 48 8d 53 0c 48 8b cb e8 b7 42 9c ff 48 8b d3 48 8b cb e8 dc 3d 9c ff 48 8b cb c7 43 38 54 05 00 00 e8 cd 39 ad ff 3d 54 05 00 00 0f 85 4d 01 00 00 48 8d 53 0c 48 8b cb e8 e6 42 9c ff 8b 43 40 c1 e8 02 a8 01 0f 85 a0 00 00 00 ba 01 00 00 00 48 8b cb e8 1b f8 9b ff 44 8b 0b 45",
        text_address,
        text_size,
        1,
    );
    if ptrs_life.is_err() || ptrs_life.as_ref().unwrap().len() != 1 {
        panic!("Cannot find Life!");
    }

    // Install hooks
    for addr in ptrs_life.unwrap().iter() {
     
    
    //    println!("Hooking Version @ {addr:#X}");
        hook_direct2(*addr, on_hook, *addr);
 }



//println!("Hook...");
let ptrs_secure = memsearch::find_n_in(
    "8b 43 40 c1 e8 02 a8 01 0f 84 22 01 00 00 8b 4b 10 8d 91 01 ff ff ff 44 8d 81 01 ff ff ff 8b c2 44 33 c1 c1 e8 03 44 23 c1 41 81 e0 ff ff ff 8f 44 0b c0 8b c1 41 c1 e8 1c b9 01 ff ff ff 48 03 c1 48 c1 e8 1f 83 e0 02 44 0b c0 b8 04 00 00 00 85 d2 0f 44 e8 44 0b c5 44 89 43 40 41 c1 e8 02 41 f6 c0 01 0f 85 c2 00 00 00 48 8d 53 1c 48 8b cb e8 63 4d 70 ff 48 8b cb c7 43 38 ad 11 00 00 e8 24 9a aa ff 3d ad 11 00 00 0f 85 0d 01 00 00 8b 13 48 8d 4b 0c e8 de 63 70 ff 4c 8d 43 10 48 8b cb 48 8d 53 0c e8 5e a6 70 ff 8b 43 40 c1 e8 02 a8 01 75 77 8b 13 48 8d 4b 0c ff c2 e8 b7 63 70 ff 4c 8d 43 10 48 8b cb 48 8d 53 0c e8 37 a6 70 ff 8b 43",
    text_address,
    text_size,
    1,
);
if ptrs_secure.is_err() || ptrs_secure.as_ref().unwrap().len() != 1 {
    panic!("Cannot find Secure");
}

// Install hooks
for addr in ptrs_secure.unwrap().iter() {
 

  //  println!("Hooking Version @ {addr:#X}");
    hook_direct(*addr, on_hook2, *addr);


} 
//println!("Hook...");
let ptrs_secure2 = memsearch::find_n_in(
    "8b 43 40 c1 e8 02 a8 01 0f 84 22 01 00 00 8b 4b 10 8d 91 01 ff ff ff 44 8d 81 01 ff ff ff 8b c2 44 33 c1 c1 e8 03 44 23 c1 41 81 e0 ff ff ff 8f 44 0b c0 8b c1 41 c1 e8 1c b9 01 ff ff ff 48 03 c1 48 c1 e8 1f 83 e0 02 44 0b c0 b8 04 00 00 00 85 d2 0f 44 e8 44 0b c5 44 89 43 40 41 c1 e8 02 41 f6 c0 01 0f 85 c2 00 00 00 48 8d 53 1c 48 8b cb e8 d3 7e ab ff 48 8b cb c7 43 38 ad 11 00 00 e8 94 cb e5 ff 3d ad 11 00 00 0f 85 0d 01 00 00 8b 13 48 8d 4b 0c e8 4e 95 ab ff 4c 8d 43 10 48 8b cb 48 8d 53 0c e8 ce d7 ab ff 8b 43 40 c1 e8 02 a8 01 75 77 8b 13 48 8d 4b 0c ff c2 e8 27 95 ab ff 4c 8d 43 10 48 8b cb 48 8d 53 0c e8 a7 d7 ab ff 8b 43 40 c1 e8 02 a8 01 75 50 8b 13 48",

    text_address,
    text_size,
    1,
);
if ptrs_secure2.is_err() || ptrs_secure2.as_ref().unwrap().len() != 1 {
    panic!("Cannot find Secure");
}

// Install hooks
for addr in ptrs_secure2.unwrap().iter() {
 

  //  println!("Hooking Version @ {addr:#X}");
    hook_direct(*addr, on_hook2, *addr);


} 

//println!("Hook...");

let ptrs_face = memsearch::find_n_in(
    "40 55 56 57 48 81 ec d0 00 00 00 48 c7 44 24 40 fe ff ff ff 48 89 9c 24 00 01 00 00 48 8b 05 b5 b6 9d 00 48 33 c4 48 89 84 24 c8 00 00 00 48 8b da 48 8b f9 48 8d 0d fe a6 c1 07 e8 e8 1a 06 00 33 ed 48 89 af 08 01 00 00 41 b0 01 33 d2 48 8b cb e8 2a 0b 00 00 48 89 87 08 01 00 00 48 89 ac 24 c0 00 00 00 48 85 c0 0f 85 0f 01 00 00 4c 8d 05 cb 56 bd 00 48 8b d3 48 8d 4c 24 50 e8 1e 53 ea fc 48 8b 08 48 83 e1 fe 48 89 6c 24 30 c7 44 24 28 80 00 00 00 c7 44 24 20 03 00 00 00 45 33 c9 ba 00 00 00 80 44 8d 45 01 ff 15 a8 3a 07 00 48 8b d8 48 89 84 24 b8 00 00 00 89 6c 24 5c 48 8b 54 24 50 48 83 e2 fe 74 14 f6 44 24 50 01 75 0d 48 8d 0d 48 50 bd 00 e8 93 6c ea fc 90 48 83 fb ff 0f 84 06 01 00 00 48 89 ac",
    text_address,
    text_size,
    1,
);
if ptrs_face.is_err() || ptrs_face.as_ref().unwrap().len() != 1 {
    panic!("Cannot find Secure");
}

// Install hooks
for addr in ptrs_face.unwrap().iter() {
 

//    println!("Hooking Version @ {addr:#X}");
    hook_direct2(*addr, on_hook3, *addr);


} 

let ptrs_koko =memsearch::find_n_in(
"e8 18 9b 6a ff 8b d5 48 8b cb e8 ae 9b 6a ff ba 06 00 00 00 48 8b cb e8 81 9c 6a ff eb 99 cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc 40 53 48 83 ec 20 48 8b d9 48 8d 0d f9 b9 3f 0a e8 e3 2d 84 02 48 8d 05 c4 31 d6 ff 48 89 83 e8 f0 02 00 48 8d 05 c6 32 d6 ff 48 89 83 a8 f1 02 00 48 8d",
text_address,
text_size,
1
);
if ptrs_koko.is_err() || ptrs_koko.as_ref().unwrap().len() != 1 {
    panic!("Cannot find Secure");
}

// Install hooks
for addr in ptrs_koko.unwrap().iter() {
 

    //println!("Hooking Version @ {addr:#X}");
    hook_direct2(*addr, on_hook4, *addr);


} 
let ptrs_setface =memsearch::find_n_in(
"e8 d0 f7 77 ff 48 8b 43 08 8b 88 f0 eb 02 00 48 8d 47 48 89 0e 48 83 e0 c0 48 8b 40 08 8b 88 f8 eb 02 00 89 4f 08 48 8b cf c7 47 38 3e 04 00 00 e8 a0 5e c4 ff 3d 3e 04 00 00 0f 85 62 03 00 00 8b 4f 14 ba 02 00 00 00 48 8b 43 08 83 c1 02 0f b6 0c 01 89 0e 48 8d 4f 08 e8 57 b1 77 ff 8b 57 1c 48 8d 4f 08 e8 ab 70 78 ff 8b 47 40 c1 e8 02",
text_address,
text_size,
1
);
if ptrs_setface.is_err() || ptrs_setface.as_ref().unwrap().len() != 1{
    panic!("CANNOT FIND FACE");
}

for addr in ptrs_setface.unwrap().iter() {
    //println!("Hooking Version @ {addr:#X}");
  hook_direct2(*addr,on_hook5,*addr);


}

let ptrs_setfaceadd =memsearch::find_n_in (
"48 8b 40 08 8b 88 f8 eb 02 00 89 4f 08 48 8b cf c7 47 38 3e 04 00 00 e8 a0 5e c4 ff 3d 3e 04 00 00 0f 85 62 03 00 00 8b 4f 14 ba 02 00 00 00 48 8b 43 08 83 c1 02 0f b6 0c 01 89 0e 48 8d 4f 08 e8 57 b1 77 ff 8b 57 1c 48 8d 4f 08 e8 ab 70 78 ff 8b 47 40 c1 e8 02 a8 01 75 0d 8b 57 14 48 8b ce ff c2 e8 54 0d 78 ff ba 05 00 00 00 48 8b cf e8 27",
 text_address,
text_size,
1

);
if ptrs_setfaceadd.is_err() || ptrs_setfaceadd.as_ref().unwrap().len() != 1{
    panic!("CANNOT FIND FACE");
}

for addr in ptrs_setfaceadd.unwrap().iter() {
    //println!("Hooking Version @ {addr:#X}");
  hook_direct2(*addr,on_hook6,*addr);


}
let ptrs_setPALadd =memsearch::find_n_in (
"48 8b 43 08 8b 90 fc eb 02 00 89 16 e8 86 f4 77 ff 48 8b 43 08 48 8d 4f 08 8b 90 00 ec 02 00 89 16 ba 20 00 00 00 e8 4c ae 77 ff 48 8b cf c7 47 38 3e 04",
text_address,
text_size,
1

);
if ptrs_setPALadd.is_err() || ptrs_setPALadd.as_ref().unwrap().len() != 1{
    panic!("CANNOT FIND FACE");
}

for addr in ptrs_setPALadd.unwrap().iter() {
    //println!("Hooking Version @ {addr:#X}");
  hook_direct(*addr,on_hook7,*addr);


}

let ptrs_rsKokocalc=memsearch::find_n_in (
"48 8b cb e8 e8 88 93 ff 8b d5 48 8b cb e8 7e 89 93 ff eb a6 cc cc cc cc cc cc cc cc cc cc cc cc 40 53 48 83 ec 20 48 8b d9 48 8d 0d d9 a7 68 0a e8 c3 1b ad 02 83 43 34 fc 4c 8d 4b 38 44 8b 43 34 48 8b 53 48 c7 43",
text_address,
text_size,
1


);
if ptrs_rsKokocalc.is_err() || ptrs_rsKokocalc.as_ref().unwrap().len() != 1{
    panic!("CANNOT FIND FACE");
}

for addr in ptrs_rsKokocalc.unwrap().iter() {
   // println!("Hooking Version @ {addr:#X}");
  hook_direct2(*addr,on_hook9,*addr);


}

let ptrs_rsfaceaddbefore=memsearch::find_n_in (
    "e8 dc 4c cd ff 48 8b 43 08 8b 88 f0 eb 02 00 48 8d 47 48 89 0e 48 83 e0 c0 48 8b 40 08 8b 88 f8 eb 02 00 89 4f 08 48 8b cf c7 47 38 3e 04 00 00 e8 ac b3 19 00 3d 3e 04",
    text_address,
    text_size,
    1
    
    
    );
    if ptrs_rsfaceaddbefore.is_err() || ptrs_rsfaceaddbefore.as_ref().unwrap().len() != 1{
        panic!("CANNOT FIND FACE");
    }
    
    for addr in ptrs_rsfaceaddbefore.unwrap().iter() {
      //  println!("Hooking Version @ {addr:#X}");
      hook_direct2(*addr,on_hook10,*addr);
    
    
    }
let ptrs_rsfaceaddafter=memsearch::find_n_in (
 "e8 ac b3 19 00 3d 3e 04 00 00 0f 85 5e 03 00 00 8b 4f 14 ba 02 00 00 00 48 8b 43 08 83 c1 02 0f b6 0c 01 89 0e 48 8d 4f 08 e8 63 06 cd ff 8b 57 1c 48 8d 4f 08 e8 b7 c5 cd ff 8b",
 text_address,
 text_size,
 1
);

if ptrs_rsfaceaddafter.is_err() || ptrs_rsfaceaddafter.as_ref().unwrap().len() != 1{
    panic!("CANNOT FIND FACE");
}

for addr in ptrs_rsfaceaddafter.unwrap().iter() {
    //println!("Hooking Version @ {addr:#X}");
  hook_direct2(*addr,on_hook6,*addr);


}

let ptrs_rspaladdbefore=memsearch::find_n_in (
    "48 8b 43 08 8b 90 fc eb 02 00 89 16 e8 96 49 cd ff 48 8b 43 08 48 8d 4f 08 8b 90 00 ec 02 00 89 16 ba 20 00 00 00 e8 5c 03 cd ff 48 8b cf c7 47 38 3e 04 00 00 e8 6d b0 19 00 3d 3e 04 00 00 75 23",
    text_address,
    text_size,
    1
   );
   
   if ptrs_rspaladdbefore.is_err() || ptrs_rspaladdbefore.as_ref().unwrap().len() != 1{
       panic!("CANNOT FIND FACE");
   }
   
   for addr in ptrs_rspaladdbefore.unwrap().iter() {
  //     println!("Hooking Version @ {addr:#X}");
     hook_direct(*addr,on_hook11,*addr);
   
   
   }



    


  
 Ok(LuaValue::Nil)
}


/*unsafe extern "win64" fn on_hook(
    reg: *mut ilhook::x64::Registers,
    _return_addr: usize,
    from_addr: usize,
) -> usize {
    
    from_addr + 0x51
} */

unsafe extern "win64" fn on_hook(
    reg: *mut ilhook::x64::Registers,
    _return_addr: usize

) {
   
    let gba = unsafe { GBAState::from_addr((*reg).rbx) };
    let battlesettings = gba.read_u32(gba.r10 + 0x18);
    let pvpornot = gba.read_u8(battlesettings+0xF);
  
   if pvpornot<0x46 {
  let bytes: [u32; 12] = [0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22];
 //let bytes: [u32; 12] = [0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22];
   gba.r0=bytes[gba.r3 as usize];
   }
}



unsafe extern "win64" fn on_hook2(
    reg: *mut ilhook::x64::Registers,
    _return_addr: usize,
    from_addr: usize,
) -> usize {
    
    from_addr + 0xE
}

unsafe extern "win64" fn on_hook3(
    reg: *mut ilhook::x64::Registers,
    _return_addr: usize

) {
    let LCMEM=(*reg).rsi as *mut u8;
   let headeradr=0x80000A0 as u32;
    if comp(LCMEM,headeradr,RSFACE::BMHEADER,RSFACE::lengthHeader )==true {
    let romadr= 0x87de310 as u32;
    FACELOC=romadr;
     FakeMemCopy(LCMEM,romadr,RSFACE::RSFACE,RSFACE::LENGTHRSFACE);
     FACEPALLOC=romadr+(RSFACE::LENGTHRSFACE as u32);
     FakeMemCopy(LCMEM,romadr+(RSFACE::LENGTHRSFACE as u32),RSFACE::RSPallete,RSFACE::lengthRSPallete);
    
gamever=0;
}
if comp(LCMEM,headeradr,BMFACE::RSHEADER,BMFACE::lengthHeader2)==true {

    let romadr= 0x87de310 as u32;
    FACELOC=romadr;
     FakeMemCopy(LCMEM,romadr,BMFACE::BMFACE,BMFACE::LENGTHBMFACE);
     FACEPALLOC=romadr+(BMFACE::LENGTHBMFACE as u32);
     FakeMemCopy(LCMEM,romadr+(BMFACE::LENGTHBMFACE as u32),BMFACE::BMPAL,BMFACE::LENGTHBMPAL);

gamever=1;

}
    
    
}

unsafe extern "win64" fn on_hook4(
    reg: *mut ilhook::x64::Registers,
    _return_addr: usize

) {
    let gba = unsafe { GBAState::from_addr((*reg).rbx) };
currSoul=gba.r4 as u8;
if currSoul>0 && currSoul<7 {
gba.r4=(currSoul+0xA-0x4 ) as u32;

}
    
}

unsafe extern "win64" fn on_hook5(
    reg: *mut ilhook::x64::Registers,
    _return_addr: usize

) {
   
    let gba = unsafe { GBAState::from_addr((*reg).rcx) };

if currSoul>0 && currSoul<7 {
    total=FACELOC+gba.r0;

}
else {
    total=gba.r0+gba.r1;
}


    
}
unsafe extern "win64" fn on_hook6(
    reg: *mut ilhook::x64::Registers,
    _return_addr: usize

) {
   
    let gba = unsafe { GBAState::from_addr((*reg).rdi) };

gba.r0=total;
    
}


unsafe extern "win64" fn on_hook7(
    reg: *mut ilhook::x64::Registers,
    _return_addr: usize,
    from_addr: usize,
) -> usize 
 {
   
    let gba = unsafe { GBAState::from_addr((*reg).rdi) };


    
    let bluefacepal = gba.read_u32(0x2ebfc);
  
//1408aa9ca-1408aa9b9  ca-b9
if currSoul>0 && currSoul<7 {
    total2=FACEPALLOC+gba.r0;
}
else {
    total2=gba.r0+bluefacepal;
}
gba.r0=total2;

from_addr + 0x11

    
}


unsafe extern "win64" fn on_hook9(
    reg: *mut ilhook::x64::Registers,
    _return_addr: usize
) { 
let gba = unsafe { GBAState::from_addr((*reg).rbx) };
currSoul=gba.r4 as u8;
if currSoul>6 {
gba.r4=(currSoul-6) as u32;

}
    
}

unsafe extern "win64" fn on_hook10(
    reg: *mut ilhook::x64::Registers,
    _return_addr: usize

) {
   
    let gba = unsafe { GBAState::from_addr((*reg).rdi) };

if currSoul>6 {
    total=FACELOC+gba.r0;

}
else {
    total=gba.r0+gba.r1;
}
    
}



unsafe extern "win64" fn on_hook11(
    reg: *mut ilhook::x64::Registers,
    _return_addr: usize,

    from_addr: usize,
) -> usize  {
   
    let gba = unsafe { GBAState::from_addr((*reg).rdi) };


    //1403554ba- 1403554a9=ba-a9 
    let redfacepal = gba.read_u32(0x2ebfc);
if currSoul>6 {
    total2=FACEPALLOC+gba.r0;

}
else {
    total2=gba.r0+redfacepal;
}
gba.r0=total2;

from_addr + 0x11


    
}





