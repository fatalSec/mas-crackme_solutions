var libnative_loaded = 0;
var do_dlopen = null;
var call_ctor = null;

hookImportedFunctions();

Process.findModuleByName('linker64').enumerateSymbols().forEach(function (sym) {
    if (sym.name.indexOf('do_dlopen') >= 0) {
        do_dlopen = sym.address;
    } else if (sym.name.indexOf('call_constructor') >= 0) {
        call_ctor = sym.address;
    }
});

Interceptor.attach(do_dlopen, function () {
    var libraryPath = this.context.x0.readCString();
    if (libraryPath.indexOf('libnative-lib.so') > -1) {
        console.log(`target libnative loaded....`);
        
        Interceptor.attach(call_ctor, function () {
            if (libnative_loaded == 0) {
                var native_mod = Process.findModuleByName('libnative-lib.so');
                console.warn(`[+] libnative loaded @${native_mod.base}`);
                patchOffset1(native_mod.base);
                hookSVCInstructions(native_mod.base); 
                patchPthreadCreate(native_mod.base); 
            }
            libnative_loaded = 1;
        });
    }
});

function hookImportedFunctions(base_addr,size) {
    var arg0 = null;
    Interceptor.attach(Module.findExportByName("libc.so", "snprintf"), {
        onEnter: function (args) {
            arg0 = args[0];
        },
        onLeave: function (retval) {
            console.log(`snprintf: ${arg0.readCString()}`);
            if (arg0.readCString().indexOf("/status") > -1) {
                arg0.writeUtf8String("/data/local/tmp/fake_status");
            }
            if (arg0.readCString().indexOf("/proc/self/fd") > -1) {
                arg0.writeUtf8String("/proc/self/fd/45");
            }
        }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "open"), {
        onEnter: function (args) {
            console.log(`open: ${args[0].readCString()}`);
        }
    });

    // Interceptor.attach(Module.findExportByName("libc.so", "lstat"), {
    //     onEnter: function (args) {
    //         console.log(`lstat: ${args[0].readCString()}`);
    //     }
    // });

    // Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
    //     onEnter: function (args) {
    //         console.log(`strstr: ${args[0].readCString()}`);
    //     }
    // });
}

function patchPthreadCreate(base_addr) {
    Memory.patchCode(base_addr.add(0x5870), Process.pageSize, code => {
        const cw = new Arm64Writer(code, { pc: base_addr.add(0x5870) });
        cw.putInstruction(0xD2800000);//000080D2
        console.log(`patched instruction: ${Instruction.parse(base_addr.add(0x5870))}`);
    });
    Memory.patchCode(base_addr.add(0x5874), Process.pageSize, code => {
        const cw = new Arm64Writer(code, { pc: base_addr.add(0x5874) });
        cw.putInstruction(0xD65F03C0);//000080D2
        console.log(`patched instruction: ${Instruction.parse(base_addr.add(0x5874))}`);
    });
}

function hookSVCInstructions(base_addr){
    let svc_addr = [0x00009870, 0x0000b448, 0x0000c950, 0x00011674, 0x00011944, 0x00011de0, 0x00011fb0, 0x00012884, 0x00013170, 0x000145f8, 0x00015124, 0x000156e4, 0x00015fa0, 0x00017118, 0x00017738, 0x0001805c, 0x00020ee0, 0x000231e8, 0x00024a6c, 0x0002a07c, 0x0002a2dc, 0x0002c368, 0x0002daf8, 0x00036a1c, 0x0003897c, 0x0003a068, 0x0003dbf4, 0x0003df84, 0x00043448, 0x00043664, 0x00045330, 0x00045530, 0x00048ff0, 0x0004ae6c, 0x0004c3b4, 0x00056034, 0x00056674, 0x000585f4, 0x00059bc4, 0x00064f88, 0x0006554c, 0x0006deb0, 0x0006fd08, 0x000713b8, 0x00074b40, 0x00074f24, 0x000783e0, 0x00079fd8, 0x0007b5b4, 0x000803fc, 0x000806d4, 0x00080b6c, 0x00080d44, 0x0008160c, 0x00081f1c, 0x000834a8, 0x00083fc0, 0x000845e0, 0x00084eb0, 0x000860cc, 0x00086788, 0x00087030, 0x00088b64, 0x0008a718, 0x0008bd1c, 0x00090bbc, 0x00090ea0, 0x00091330, 0x00091508, 0x00091e20, 0x00092750, 0x00093c38, 0x000947c4, 0x00094db4, 0x00095648, 0x0009689c, 0x00096f00, 0x000977d8, 0x000992a4, 0x000993f0, 0x00099e30, 0x0009f2f8, 0x000a2148, 0x000a4604, 0x000aa750, 0x000aa964, 0x000ad3a4, 0x000af548, 0x000b9810, 0x000bc4c0, 0x000be8a8, 0x000c4d0c, 0x000c4f4c, 0x000c78f0, 0x000c99b8, 0x000d718c, 0x000d7448, 0x000d99ac, 0x000d9c6c, 0x000dedb0, 0x000e1940, 0x000e3d70, 0x000e8984, 0x000e8d68];

    for (let i = 0; i < svc_addr.length; i++) {
        Interceptor.attach(base_addr.add(svc_addr[i]), {
            onEnter: function (args) {
                if(this.context.x8.toInt32() == 56){
                    console.log(`[+] ${this.context.pc.sub(base_addr)} -> SVC ${this.context.x1.readCString()}`);
                    var path = this.context.x1.readCString();
                    if(path.indexOf("/proc/self/status") >= 0){
                        this.context.x1.writeUtf8String("/proc/self/task/123/status");
                        console.error(`Modified path: ${this.context.x1.readCString()}`);
                    }
                }else if(this.context.x8.toInt32() !== 63){
                    console.log(`[+] ${this.context.pc.sub(base_addr)} -> SVC ${this.context.x8.toInt32()}`);
                }
                
            }
        })
    }
}


function patchOffset1(base_addr){
    Memory.patchCode(base_addr.add(0xb8ec4), Process.pageSize, code => {
        const cw = new Arm64Writer(code, { pc: base_addr.add(0xb8ec4) });
        cw.putNop();
        console.log(`patched instruction: ${Instruction.parse(base_addr.add(0xb8ec4))}`);
    });
}


function startStalkingTextSectionCrash(base_addr) {
    Stalker.follow(Process.getCurrentThreadId(), {
        transform: function (iterator) {
            let instruction = iterator.next();
            do {
                if (instruction.address >= base_addr.add(0x9b438) && instruction.address <= base_addr.add(0xeedd4)) {
                    if(instruction.mnemonic == "csel"){
                        console.warn(`${instruction.address.sub(base_addr)} ${instruction} `);
                    }  
                }
              
                iterator.keep();
            } while ((instruction = iterator.next()) !== null);
        }
    });
}
