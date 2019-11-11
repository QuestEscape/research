/* Frida script for SSL stripping */

Java.perform(function() {
	var array_list = Java.use("java.util.ArrayList");
	var ApiClient = Java.use("com.android.org.conscrypt.TrustManagerImpl")

try {
	ApiClient.verifyChain.implementation = function(untrust, trustanchor, host, cauth, oscp, sctdata) {
		console.log("intercepted trustmanager");
		return untrust;
	}
} catch (err){

}

try {
	var CertPin = Java.use("okhttp3.CertificatePinner");
	CertPin.check.overload("java.lang.String", "java.util.List").implementation = function(str) {
		console.log("intercept okhttp3 " + str);
		return;
	}

	CertPin.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function(p0,p1) {
		console.log("intercept okhttp3 cert");
		return;
	}


} catch (err) {

}

try {
	//fb pinning
	var FBPin = Java.use("com.facebook.netlite.certificatepinning.internal.FbPinningTrustManager");
	FBPin.checkServerTrusted.implementation = function(a0, a1) {
		console.log("FB pin");
		return;
	}
} catch (err) {

}

	//linked in libcurl
	var sos=[];
	var libs = ["libdialogui.so", "libavatars.so", "libcurl.so",
		    "libovrplatform.so", "libovrplatform_64.so", "libovrplatformplugin.so",
		    "libhome.so"];

	for(var x in libs) {

	  var attach = Module.findExportByName(libs[x], "curl_easy_setopt");
          console.log(libs[x] + " -> " + attach);
	  if(!attach) continue;
	  console.log("found module for " + libs[x]);
	  sos[libs[x]] = Interceptor.attach(attach, {
		onEnter: function(args) {
			console.log("setopt called" + JSON.stringify(args));
		},

		onLeave: function(retval) {
			console.log("setopt over")
		}
	  });

        }


	const System = Java.use('java.lang.System');
	const Runtime = Java.use('java.lang.Runtime');
	const VMStack = Java.use('dalvik.system.VMStack');
	System.loadLibrary.implementation = function(library) {
		console.log("System.loadLibrary('" + library + "')");
		try {
			const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library)
			return loaded;
		} catch(err) {
			console.log(err);
		}
	}

	System.load.implementation = function(library) {
		console.log("System.load('" + library + "')");
		try {
			const loaded = Runtime.getRuntime().load0(VMStack.getCallingClassLoader(), library)
			return loaded;
		} catch(err) {
			console.log(err);
		}

	}

	function hookCurlSetOpt(address) {
        Interceptor.attach(address, {
                onEnter: function(args) {
                        if (args[1] == 81) {
                                console.log("CURLOPT_SSL_VERIFYHOST -> 0")
                                this.context.r2 = 0
                        }
                        if (args[1] == 64) {
                                console.log("CURLOPT_SSL_VERIFYPEER -> 0")
                                this.context.r2 = 0
                        }
                        if (args[1] == 10230) {
                                console.log("CURLOPT_PINNEDPUBLICKEY -> 0")
                                this.context.r2 = 0
                        }
                }
        });

	}


	function hookModuleHelper(name, offset, handler) {
		var base = Module.findBaseAddress(name)
	        console.log(name + " @ " + base);
		if (base == null) return;
		var target = base.add(offset);
		handler(target);
	}

	//Statically linked libcurl. Need to manually update the offsets for now
	hookModuleHelper("libovrplatform.so", 0xea49c-0x10000 +1, hookCurlSetOpt)
	hookModuleHelper("libhome.so", 0x57407c-0x10000 +1, hookCurlSetOpt)
	hookModuleHelper("libavatars.so", 0x9e460-0x10000  , hookCurlSetOpt)


}, 0);
