
function log(msg) {
    console.log(msg)
    send(msg)
}

log('load hook script...')

function main() {
    Java.perform(function() { 
        var Log = Java.use("android.util.Log")
        var Throwable = Java.use("java.lang.Throwable")

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