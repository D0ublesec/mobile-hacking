// Author: D0ublesec
// Attach to process of app with the following command via usb:
// frida -p $(adb shell "ps -A | grep -i system_server" | cut -d ' ' -f 9) --load android_deeplink_app_param_overwrite.js --usb

var seenIntents = {};
var targetPackage = "com.package.name"; // Replace this with the package name of the app you want to monitor
var userDefinedParamKey = "paramkey"; // The key of the parameter you want to add/modify
var userDefinedParamValue = "paramvalue"; // The value of the parameter you want to add/modify

Java.perform(function() {
    var Intent = Java.use("android.content.Intent");
    var Uri = Java.use("android.net.Uri");

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
                console.log("\n[*] Processing intent with key: " + key);  // Log the intent's unique key

                // Check if this intent has been seen before
                if (!seenIntents.hasOwnProperty(key)) {
                    // Mark this intent as seen by adding it to the global object
                    seenIntents[key] = true;
                    console.log("\n=================================");
                    console.log("[*] Intent.getData() was called");
                    console.log("[*] Action: " + action);

                    var uri = this.getData();
                    if (uri !== null) {
                        console.log("\n-----[ Original Data ]-----");
                        console.log("[-] Scheme: " + uri.getScheme());
                        console.log("[-] Host: " + uri.getHost());
                        console.log("[-] Params: " + uri.getQuery());
                        console.log("[-] Fragment: " + uri.getFragment());
                        console.log("[-] Deep Link: " + uri.getScheme() + "://" + uri.getHost() + "/" + uri.getQuery() + "/" + uri.getFragment());
						console.log("------------------\n");

                        // Modify the URI by replacing the existing parameter (if it exists)
                        var currentParams = uri.getQuery();
                        var newParams = [];

                        // If there are existing parameters, process them
                        if (currentParams) {
                            var paramPairs = currentParams.split("&");

                            // Iterate through parameters and modify the specified one
                            var paramFound = false;
                            for (var i = 0; i < paramPairs.length; i++) {
                                var param = paramPairs[i].split("=");
                                if (param[0] === userDefinedParamKey) {
                                    // Replace the existing parameter with the new value
                                    param[1] = userDefinedParamValue;
                                    paramFound = true;
                                }
                                newParams.push(param[0] + "=" + param[1]);
                            }

                            // If the parameter wasn't found, add it
                            if (!paramFound) {
                                newParams.push(userDefinedParamKey + "=" + userDefinedParamValue);
                            }
                        } else {
                            // If there were no params, just add the new one
                            newParams.push(userDefinedParamKey + "=" + userDefinedParamValue);
                        }

                        // Create a new URI with the updated parameters
                        var newUri = Uri.parse(uri.getScheme() + "://" + uri.getHost() + "?" + newParams.join("&"));

                        // Log the new URI with the modified parameters
                        console.log("\n-----[ Modified Data ]-----");
                        console.log("[-] Params: " + newParams.join("&"));
                        console.log("[-] Deep Link: " + newUri.toString());
						console.log("------------------\n");
						
                        // Set the new URI to the intent
                        this.setData(newUri);

                    } else {
                        console.log("[-] No data in the intent.");
                    }
                }
            }
        }
        return this.getData();
    };
});