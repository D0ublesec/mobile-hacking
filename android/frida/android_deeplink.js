// Author: D0ublesec
// Attach to process of app with the following command via usb:
// frida -p $(adb shell "ps -A | grep -i system_server" | cut -d ' ' -f 9) --load android_deeplink.js --usb

// Define a global object to store previously seen intents
var seenIntents = {};
Java.perform(function() {
    var Intent = Java.use("android.content.Intent");
    Intent.getData.implementation = function() {
        var action = this.getAction() !== null ? this.getAction().toString() : false;
        if (action) {
            // Create a unique key for the current intent by concatenating its action and data URI
            var key = action + '|' + (this.getData() !== null ? this.getData().toString() : '');
            // Check if this intent has been seen before
            if (seenIntents.hasOwnProperty(key)) {
                return this.getData();
            } else {
                // Mark this intent as seen by adding it to the global object
                seenIntents[key] = true;
                console.log("\n=================================");
                console.log("[*] Intent.getData() was called");
                console.log("[*] Action: " + action);

                // Handle explicit and implicit intents
                var component = this.getComponent();
                if (component !== null) {
                    var packageName = component.getPackageName();
                    var className = component.getClassName();
                    console.log("[*] Package: " + packageName);
                    console.log("[*] Activity: " + className);
                } else {
                    // If component is null, check if the package is explicitly set in the Intent
                    var packageName = this.getPackage();
                    if (packageName !== null) {
                        console.log("[*] Package: " + packageName);
                    } else {
                        console.log("[*] No package name available.");
                    }

                    // For implicit intents, we might still have the activity information in the action
                    var className = this.getStringExtra("android.intent.extra.STREAM");
                    if (className !== null) {
                        console.log("[*] Activity (from Intent Extras): " + className);
                    } else {
                        console.log("[*] No activity information available.");
                    }
                }

                // Log URI details
                var uri = this.getData();
                if (uri !== null) {
                    console.log("\n-----[ Data ]-----");
                    console.log("- Scheme: " + uri.getScheme());
                    console.log("- Host: " + uri.getHost());
                    console.log("- Params: " + uri.getQuery());
                    console.log("- Fragment: " + uri.getFragment());
                    console.log("- Deep Link: " + uri.getScheme() + "://" + uri.getHost() + "/" + uri.getQuery() + "/" + uri.getFragment())
                    console.log("------------------\n");
                } else {
                    console.log("[-] No data supplied.");
                }
            }
        }
        return this.getData();
    }
});
