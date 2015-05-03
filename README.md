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

If you're interested in using Raven with the nginx web server, or just curious about developing nginx modules (documentation is scarce), then this project might be of interst to you.

This module does not implement all of the features present in the widely used Apache module "mod_ucam_webauth.c". It is intended to be lightweight, and includes only the bare minimum of features required for operation. For example, it will not perform multiple redirects to "tidy up" the WLS response from the location bar of users' browsers. All code is experimental, and as such this module should not be used to protect important information.
