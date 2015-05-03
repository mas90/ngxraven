# ngxraven
This module for the nginx web server implements the WAA side of the WAA->WLS communication protocol used by the University of Cambridge's central web authentication service.

In its current state (version "1.0.0") it is not considered to be fit for production use. Although fully functional, it is intended as a "proof of concept", a test bed of ideas. The code is largely untested, and there may still be bugs. Some novel design features of this module when compared with typical implementations include:

	- Employing the SSL library "mbed TLS" (formerly PolarSSL) to handle encryption instead of using OpenSSL.
	- Loading the WLS public key from disk into RAM for optimised performance (does not touch disk when verifying signature in WLS response).
	- HMAC-SHA256 protection for session cookies.
	- Constant-time strcmp replacement to avoid early-out optimisations and timing attacks against the session cookie.
	- Uses libuuid to generate a GUID for each server instance, which is included in the WLS request (as "params") and then used to help check the authenticity of WLS response.
	- "Lazy clock" mode for avoiding issues with high-latency connections (does not check last digit of timestamp like "19700101T000000Z").
	- < 1000 lines of code.
	- Written for the nginx web server!

If you're interested in using Raven with the nginx web server, or just curious about developing nginx modules (documentation is scarce), then this project might be of interest to you. To get started:

1. Download nginx source.
2. Download this module.
3. From nginx directory, run:

	./configure --add-module=/path/to/module/dir
	make
	make install (will land in "/usr/local/nginx")

4. Make a location configuration something like this:

	error_log	logs/error.log	info; # Optional, but useful to see some messages

	* * * * *

	location /test{
		RavenActive on;
		RavenLogin https://demo.raven.cam.ac.uk/auth/authenticate.html;
		RavenLogin https://demo.raven.cam.ac.uk/auth/logout.html;
		RavenSecretKey	qwertyui;
		RavenLazyClock	on;
		RavenAllow	test0001;
		RavenDeny	test0002;
		RavenAllow	test0003;
		RavenDeny	test0004;
		RavenAllow	test0005;
	}

	* * * * *

5. Get a copy of the public key for the test server from here:

	https://raven.cam.ac.uk/project/keys/demo_server/pubkey901.crt

6. Convert key to suitable format like this:

	openssl x509 -pubkey -noout -in pubkey901.crt > raven.pem

7. Make sure key is in the nginx "/usr/local/nginx/conf" directory (or modify code to suit).

8. Start nginx:

	/usr/local/nginx/sbin

A quick note about how the "RavenAllow" and "RavenDeny" directives work:

	- First match in rule chain wins (from top to bottom).
	- If there are no rules, there is an implicit "RavenAllow all".
	- If there are some rules, there is an implicit trailing "RavenDeny all" rule.
	- You can create a "blacklist" by preceding "RavenAllow all" with deny rules.
	- You can create a "whitelist" by preceding "RavenDeny all" with allow rules.

This module does not implement all of the features present in the widely used Apache module "mod_ucam_webauth.c". It is intended to be lightweight, and includes only the bare minimum of features required for operation. For example, it will not perform multiple redirects to "tidy up" the WLS response from the location bar of users' browsers. All code is experimental, and as such this module should not be used to protect important information.
