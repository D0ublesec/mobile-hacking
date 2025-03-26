// Author: D0ublesec
// Attach to process of app with the following command via usb:
// frida -p $(adb shell "ps -A | grep -i system_server" | cut -d ' ' -f 9) --load android_deeplink_app.js --usb

var seenIntents = {};
var targetPackage = "com.package.name"; // Replace this with the package name of the app you want to monitor

Java.perform(function() {
    var Intent = Java.use("android.content.Intent");
    var Context = Java.use("android.content.Context");

    // Overriding the getData method for Intent
    Intent.getData.implementation = function() {
        var action = this.getAction() !== null ? this.getAction().toString() : false;

        if (action) {
            // Get the package name of the current intent's target component
            var packageName = this.getComponent() !== null ? this.getComponent().getPackageName() : null;
            
            // Only process intents for the target app
            if (packageName && packageName === targetPackage) {
                // Create a unique key for the current intent by concatenating its action and data URI
                var key = action + '|' + (this.getData() !== null ? this.getData().toString() : '');
                
                // Check if this intent has been seen before
                if (!seenIntents.hasOwnProperty(key)) {
                    // Mark this intent as seen by adding it to the global object
                    seenIntents[key] = true;
                    console.log("\n=================================")
                    console.log("[*] Intent.getData() was called");
                    console.log("[*] Activity: " + (this.getComponent() !== null ? this.getComponent().getClassName() : "unknown"));
                    console.log("[*] Action: " + action);
                    
                    var uri = this.getData();
                    if (uri !== null) {
                        console.log("\n-----[ Data ]-----");
                        console.log("[-] Scheme: " + uri.getScheme());
                        console.log("[-] Host: " + uri.getHost());
                        console.log("[-] Params: " + uri.getQuery());
                        console.log("[-] Fragment: " + uri.getFragment());
                        console.log("[-] Deep Link: " + uri.getScheme() + "://" + uri.getHost() + "/" + uri.getQuery() + "/" + uri.getFragment());
                        console.log("------------------\n");
                    } else {
                        console.log("[-] No data supplied.");
                    }
                }
            }
        }
        return this.getData();
    };
});