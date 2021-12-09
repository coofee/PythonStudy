'use strict';

// rpc.exports = {
//     init: function (stage, parameters) {
//         console.log('[init]', stage, JSON.stringify(parameters));

//         Interceptor.attach(Module.getExportByName(null, 'open'), {
//             onEnter: function (args) {
//                 var path = args[0].readUtf8String();
//                 console.log('open("' + path + '")');
//             }
//         });
//     },
//     dispose: function () {
//         console.log('[dispose]');
//     }
// };




console.log("Waiting for Java..");

while(!Java.available) {
    console.log("Not available...");
}

function main() {
    Java.perform(function() { 
        console.log('load hook script...')

        var Log = Java.use("android.util.Log")
        var Throwable = Java.use("java.lang.Throwable")

        function log(msg) {
            Log.d("Frida", msg)
            console.log(msg)
            send(msg)
        }

        // hook Activity
        var Activity = Java.use("android.app.Activity");
        Activity.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
            log("Activity onCreate: this=" + this)
            this.onCreate(bundle);
        }
        Activity.onResume.implementation = function() {
            log("Activity onResume: this=" + this)
            this.onResume();
        }

        // hook Thread
        var Thread =  Java.use("java.lang.Thread");
        Thread.start.implementation = function(){
            log("Thread start: this=" + this + ", by " + Thread.currentThread() + ", stacktrace=" + Log.getStackTraceString(Throwable.$new()))
            return this.start();
        } 
    })
}

setImmediate(main)
