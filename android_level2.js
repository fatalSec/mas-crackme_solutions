Java.perform(function(){

    var b = Java.use("sg.vantagepoint.a.b");

    b['a'].implementation = function(){
        console.log(`b.a function is called...`);
        var ret = this.a();
        console.log(`original ret val : ${ret}`);
        ret = false;
        return ret;
    }

    b['b'].implementation = function(){
        console.log(`b.b function is called...`);
        var ret = this.b();
        console.log(`original ret val : ${ret}`);
        ret = false;
        return ret;
    }

    b['c'].implementation = function(){
        console.log(`b.c function is called...`);
        var ret = this.c();
        console.log(`original ret val : ${ret}`);
        ret = false;
        return ret;
    }
});


var dlopen_func_addr = Module.findExportByName(null, "android_dlopen_ext");

var libfoo_loaded = 0;
Interceptor.attach(dlopen_func_addr, {
    onEnter: function(args){
        if(args[0].readCString().includes("libfoo.so")){
            libfoo_loaded = 1;
        }

    },
    onLeave: function(retval){
        if(libfoo_loaded == 1){
            console.log(`libfoo loaded...`);
            var base_addr = Process.findModuleByName("libfoo.so").base;
            console.log(`libfoo loaded at: ${base_addr}`);

            interceptStrnCmp(base_addr);
        }
    }
});

function interceptStrnCmp(base_addr){
    Interceptor.attach(base_addr.add(0x00000e5c), {
        onEnter: function(args){
            console.log(`s1: ${this.context.x0.readCString()}, s2: ${this.context.x1.readCString()}`);
        }
    });
}
