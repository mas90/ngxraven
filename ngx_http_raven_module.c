/*
* ngx_http_raven_module.c, v1.0.0
*
* Copyright (C) 2015 Graham Rymer. All Rights Reserved
* Distributed under the MIT Licence (see bundled file "LICENSE", or copy at (http://opensource.org/licenses/MIT")
*
* This module for the nginx web server implements the WAA side of the WAA->WLS communication protocol used by the
* University of Cambridge's central web authentication service (Raven)
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>

#include <stdio.h> // Needed for ngx_http_raven_init file ops
#include <stdlib.h> // Need strsep
#include <uuid/uuid.h> // Need to generate a unique identifer to "fingerprint" WLS requests

#include <mbedtls/pk.h> // Need for checking sig in WLS response
#include <mbedtls/sha1.h> // Need for checking sig in WLS response
#include <mbedtls/md.h> // Need for HMAC generation for session cookie
#include <mbedtls/error.h> // Used to decode error codes

#define MIN_KEY_LENGTH 8 // This is checked when config is loaded
#define WLS_RESPONSE_EXPECTED_PARAMS 14 // Number of expected WLS response parameters (including ptags, ver >= 3)
#define COOKIE_EXPECTED_PARAMS 3 // Number of expected cookie parameters
#define PUBKEY "../conf/raven.pem" // Just for testing, maybe merge this into config some time. Put cert wherever you like
#define VER "3" // Version of WAA->WLS protocol supported
#define EMPTY_PARAM ""; // Default parameter value used when constructing WLS request
#define TIMESTAMP_EPOCH "19700101T000000Z" // We use this to size issue time checking array
#define TIMESTAMP_FORMAT "%Y%m%dT%H%M%SZ" // "A scheme based on RFC 3339, except that time-offset MUST be 'Z', the alphabetic characters MUST be in upper case and the punctuation characters are omitted"
#define RESPONSE_TIMEOUT 20 // The length of time for which WLS responses are considered valid

/*
 * Initialised during postconfiguration (init), eliminates the need for calls to fopen during operation
 * Key "rollover" is of course not possible with this approach, which may or may not matter to you
 * A key change requires a server restart
 */
static mbedtls_pk_context pk; // RSA public key
static char *guid; // A GUID generated for each server instance so it can verify WLS responses are not replayed from another server

/*
 *  This stucture holds an allow/deny rule specified in the configuration file
 */
typedef struct {
	ngx_str_t principal;
	ngx_uint_t deny; /* unsigned  deny:1; */
} ngx_http_raven_rule_t;

/*
 * Configuration struct for location context
 * Apart from RavenSecretKey, the configuration directives specific to this module are optional. However, if the server's clock is not
 * NTP synchronised then RavenLazyClock will also need to be set. The same applies when running over high-latency links
 */
typedef struct {
	ngx_flag_t RavenActive; // Determine whether to handle request for a specific location or not
	ngx_str_t RavenPublicKey; // The RSA public key used to verify signatures in WLS responses, currently not used (hardcoded)
	ngx_array_t *rules; // Array of ngx_http_raven_rule_t
	ngx_str_t RavenLogin; // The full URL for the authentication service to be used
	ngx_str_t RavenLogout; // The full URL for the logout page on the authentication service in use
	ngx_str_t RavenDescription; // A text description of the resource that is requesting authentication. This may be displayed to the user by the authentication service
	ngx_flag_t RavenLazyClock; // Use if the clocks on the server running this handler and on the authentication service are out of sync (maybe high latency etc)
	time_t RavenMaxSessionLife; // The period of time for which an established session will be valid
	ngx_str_t RavenSecretKey; // A random key used to protect session cookies from tampering
	ngx_str_t RavenCookieName; // The name used for the session cookie
	ngx_flag_t RavenCleanUrl; // After authentication, redirect again to remove WLS-Response from the URL
	ngx_flag_t RavenSetUser; // Set $remote_user to the authenticated Raven principal (by faking an Authorization: Basic header)
	/*
	 *  If a cookie's domain and path are not specified by the server, they default to the domain and path of the
	 *  resource that was requested. Domain and path configuration parameters are not currently supported (unlikely to be needed
	 *  in most cases)
	 */
} ngx_http_raven_loc_conf_t;

/*
 * Need at least these forward declarations
 */
static char *ngx_http_raven_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_raven_init(ngx_conf_t *cf);

/*
 * A module's directives appear in a static array of ngx_command_t
 */
static ngx_command_t ngx_http_raven_commands[] = {

		{ ngx_string("RavenActive"), // Directive string, no spaces
NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, // Directive is valid in a location config, directive can take 0 arguments
ngx_conf_set_flag_slot, // Saves a flag
		NGX_HTTP_LOC_CONF_OFFSET, // Tells nginx whether this value will get saved to the module's main configuration, server configuration, or location configuration
		offsetof(ngx_http_raven_loc_conf_t, RavenActive), // Specifies which part of this configuration struct to write to
		NULL }, // Just a pointer to other things the module might need while it's reading the configuration. It's often NULL

		{ ngx_string("RavenPublicKey"), // Directive string, no spaces
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, // Directive is valid in a location config, directive can take 0 arguments
		ngx_conf_set_str_slot, // Saves a string as an ngx_str_t
				NGX_HTTP_LOC_CONF_OFFSET, // Tells nginx whether this value will get saved to the module's main configuration, server configuration, or location configuration
				offsetof(ngx_http_raven_loc_conf_t, RavenPublicKey), // Specifies which part of this configuration struct to write to
				NULL }, // Just a pointer to other things the module might need while it's reading the configuration. It's often NULL

		{ ngx_string("RavenAllow"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, // Directive is valid in a location config, directive can take exactly 1 argument
		ngx_http_raven_rule, NGX_HTTP_LOC_CONF_OFFSET, 0, // Custom handler adds new allow or deny rule to ruleset
				NULL }, // Just a pointer to other things the module might need while it's reading the configuration. It's often NULL

		{ ngx_string("RavenDeny"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, // Directive is valid in a location config, directive can take exactly 1 argument
		ngx_http_raven_rule, NGX_HTTP_LOC_CONF_OFFSET, 0, // Custom handler adds new allow or deny rule to ruleset
				NULL }, // Just a pointer to other things the module might need while it's reading the configuration. It's often NULL

		{ ngx_string("RavenLogin"), // Directive string, no spaces
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, // Directive is valid in a location config, directive can take exactly 1 argument
		ngx_conf_set_str_slot, // Saves a string as an ngx_str_t
				NGX_HTTP_LOC_CONF_OFFSET, // Save to module's location configuration
				offsetof(ngx_http_raven_loc_conf_t, RavenLogin), // Specifies which part of this configuration struct to write to
				NULL }, // Just a pointer to other things the module might need while it's reading the configuration. It's often NULL

		{ ngx_string("RavenLogout"), // Directive string, no spaces
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, // Directive is valid in a location config, directive can take exactly 1 argument
		ngx_conf_set_str_slot, // Saves a string as an ngx_str_t
				NGX_HTTP_LOC_CONF_OFFSET, // Save to module's location configuration
				offsetof(ngx_http_raven_loc_conf_t, RavenLogout), // Specifies which part of this configuration struct to write to
				NULL }, // Just a pointer to other things the module might need while it's reading the configuration. It's often NULL

		{ ngx_string("RavenDescription"), // Directive string, no spaces
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, // Directive is valid in a location config, directive can take exactly 1 argument
		ngx_conf_set_str_slot, // Saves a string as an ngx_str_t
				NGX_HTTP_LOC_CONF_OFFSET, // Save to module's location configuration
				offsetof(ngx_http_raven_loc_conf_t, RavenDescription), // Specifies which part of this configuration struct to write to
				NULL }, // Just a pointer to other things the module might need while it's reading the configuration. It's often NULL

		{ ngx_string("RavenLazyClock"), // Directive string, no spaces
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, // Directive is valid in a location config, directive can take exactly 1 argument
		ngx_conf_set_flag_slot, // Saves a flag
				NGX_HTTP_LOC_CONF_OFFSET, // Save to module's location configuration
				offsetof(ngx_http_raven_loc_conf_t, RavenLazyClock), // Specifies which part of this configuration struct to write to
				NULL }, // Just a pointer to other things the module might need while it's reading the configuration. It's often NULL

		{ ngx_string("RavenMaxSessionLife"), // Directive string, no spaces
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, // Directive is valid in a location config, directive can take exactly 1 argument
		ngx_conf_set_sec_slot, // Saves an integer as an ngx_uint_t
				NGX_HTTP_LOC_CONF_OFFSET, // Save to module's location configuration
				offsetof(ngx_http_raven_loc_conf_t, RavenMaxSessionLife), // Specifies which part of this configuration struct to write to
				NULL }, // Just a pointer to other things the module might need while it's reading the configuration. It's often NULL

		{ ngx_string("RavenSecretKey"), // Directive string, no spaces
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, // Directive is valid in a location config, directive can take exactly 1 argument
		ngx_conf_set_str_slot, // Saves a string as an ngx_str_t
				NGX_HTTP_LOC_CONF_OFFSET, // Save to module's location configuration
				offsetof(ngx_http_raven_loc_conf_t, RavenSecretKey), // Specifies which part of this configuration struct to write to
				NULL }, // Just a pointer to other things the module might need while it's reading the configuration. It's often NULL

		{ ngx_string("RavenCookieName"), // Directive string, no spaces
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, // Directive is valid in a location config, directive can take exactly 1 argument
		ngx_conf_set_str_slot, // Saves a string as an ngx_str_t
				NGX_HTTP_LOC_CONF_OFFSET, // Save to module's location configuration
				offsetof(ngx_http_raven_loc_conf_t, RavenCookieName), // Specifies which part of this configuration struct to write to
				NULL }, // Just a pointer to other things the module might need while it's reading the configuration. It's often NULL

		{ ngx_string("RavenCleanUrl"), // Directive string, no spaces
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, // Directive is valid in a location config, directive can take exactly 1 argument
		ngx_conf_set_flag_slot, // Saves a flag
				NGX_HTTP_LOC_CONF_OFFSET, // Save to module's location configuration
				offsetof(ngx_http_raven_loc_conf_t, RavenCleanUrl), // Specifies which part of this configuration struct to write to
				NULL }, // Just a pointer to other things the module might need while it's reading the configuration. It's often NULL

		{ ngx_string("RavenSetUser"), // Directive string, no spaces
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, // Directive is valid in a location config, directive can take exactly 1 argument
		ngx_conf_set_flag_slot, // Saves a flag
				NGX_HTTP_LOC_CONF_OFFSET, // Save to module's location configuration
				offsetof(ngx_http_raven_loc_conf_t, RavenSetUser), // Specifies which part of this configuration struct to write to
				NULL }, // Just a pointer to other things the module might need while it's reading the configuration. It's often NULL

		ngx_null_command };

/*
 * The function which initializes memory for the module configuration structure
 */
static void *
ngx_http_raven_create_loc_conf(ngx_conf_t *cf) {
	ngx_http_raven_loc_conf_t *conf;
	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_raven_loc_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}

	conf->RavenActive = NGX_CONF_UNSET;
	conf->RavenLazyClock = NGX_CONF_UNSET;
	conf->RavenMaxSessionLife = NGX_CONF_UNSET;
	conf->RavenCleanUrl = NGX_CONF_UNSET;
	conf->RavenSetUser = NGX_CONF_UNSET;

	return conf;
}

/*
 * The merge function
 */
static char *
ngx_http_raven_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
	ngx_http_raven_loc_conf_t *prev = parent;
	ngx_http_raven_loc_conf_t *conf = child;

	ngx_conf_merge_value(conf->RavenActive, prev->RavenActive, 0); // Defaults to off (0)

	if (conf->rules == NULL) {
		conf->rules = prev->rules;
	}

	ngx_conf_merge_str_value(conf->RavenPublicKey, prev->RavenPublicKey,
				"../conf/raven.pem"); // Defaults to "../conf/raven.pem"
	ngx_conf_merge_str_value(conf->RavenLogin, prev->RavenLogin,
			"https://raven.cam.ac.uk/auth/authenticate.html"); // Defaults to "https://raven.cam.ac.uk/auth/authenticate.html"
	ngx_conf_merge_str_value(conf->RavenLogout, prev->RavenLogout,
			"https://raven.cam.ac.uk/auth/logout.html"); // Defaults to "https://raven.cam.ac.uk/auth/logout.html"
	ngx_conf_merge_str_value(conf->RavenDescription, prev->RavenDescription, NULL); // Defaults to NULL
	ngx_conf_merge_value(conf->RavenLazyClock, prev->RavenLazyClock, 0); // Defaults to off (0)
	ngx_conf_merge_value(conf->RavenMaxSessionLife, prev->RavenMaxSessionLife,
			7200); // Defaults to 7200 seconds (2 hours)
	ngx_conf_merge_str_value(conf->RavenSecretKey, prev->RavenSecretKey, NULL); // Defaults to NULL
	ngx_conf_merge_value(conf->RavenCleanUrl, prev->RavenCleanUrl, 0); // Defaults to off (0)
	ngx_conf_merge_value(conf->RavenSetUser, prev->RavenSetUser, 1); // Defaults to on (1)

	if (conf->RavenSecretKey.data != NULL) { // Location has key
		ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "ngx_http_raven_merge_loc_conf: Adding cookie key"); // RavenSecretKey's value is redacted from logs for obvious reasons
		if (conf->RavenSecretKey.len < MIN_KEY_LENGTH) { // You wanna choose a longer key maybe?!
			if (conf->RavenActive) // We refuse to start if a location is active and configured with a poor key
			{
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"ngx_http_raven_merge_loc_conf: RavenSecretKey is too short, must be at least %d characters long", MIN_KEY_LENGTH);
				return NGX_CONF_ERROR;
			}
		}
	} else { // Location has no key
		if (conf->RavenActive) // We refuse to start if a location is active and configured with no key
		{
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx_http_raven_merge_loc_conf: No RavenSecretKey set");
			return NGX_CONF_ERROR;
		}
	}

	ngx_conf_merge_str_value(conf->RavenCookieName, prev->RavenCookieName,
			"Ucam-WebAuth-Session"); // Defaults to Ucam-WebAuth-Session

	return NGX_CONF_OK;
}

/*
 * The module context is a static ngx_http_module_t struct, which just has a bunch of function references for creating
 * the configurations and merging them together
 */
static ngx_http_module_t ngx_http_raven_module_ctx = { NULL, // Preconfiguration
		ngx_http_raven_init, // Postconfiguration

		NULL, // Creating the main conf
		NULL, // Initializing the main conf

		NULL, // Creating the server conf
		NULL, // Merging it with the main conf

		ngx_http_raven_create_loc_conf, // Creating the location conf
		ngx_http_raven_merge_loc_conf // Merging it with the server conf
		};

/*
 * The module definition binds the context and commands
 */
ngx_module_t ngx_http_raven_module = { NGX_MODULE_V1,
		&ngx_http_raven_module_ctx, // Module context
		ngx_http_raven_commands, // Module directives
		NGX_HTTP_MODULE, // Module type
		NULL, // Init master
		NULL, // Init module
		NULL, // Init process
		NULL, // Init thread
		NULL, // Exit thread
		NULL, // Exit process
		NULL, // Exit master
		NGX_MODULE_V1_PADDING };

/*
 * This function checks a given username (principal in Raven parlance)
 * It returns NGX_OK on success (access granted), or NGX_DECLINED on failure (access denied)
 */
static ngx_int_t ngx_http_raven_check_principal(ngx_http_request_t *r,
		char *principal, ngx_http_raven_loc_conf_t *raven_config) {
	ngx_uint_t i;
	ngx_http_raven_rule_t *rule;

	if (raven_config->rules) { // Have some rules
		i = raven_config->rules->nelts;
		rule = raven_config->rules->elts;

		for (i = 0; i < raven_config->rules->nelts; i++) {

			if(strcmp(principal, (char *)rule[i].principal.data) == 0){ // Discovered principal
				if(!rule[i].deny) // Whitelisted
				{
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_http_raven_check_principal: User OK: %s", principal);
				return NGX_OK; // Access granted for discovered principal
				}
				if(rule[i].deny){ // Blacklisted
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_http_raven_check_principal: User denied: %s", principal);
					return NGX_DECLINED; // Access denied for discovered principal
				}
			} // End discovered principal

			if(strcmp((char *)rule[i].principal.data, "all") == 0){ // Discovered "all"
				if(!rule[i].deny){ // Whitelisted
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_http_raven_check_principal: User OK: %s", principal);
			   return NGX_OK; // Access granted for "all"
				}
				if(rule[i].deny){ // Blacklisted
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_http_raven_check_principal: User denied: %s", principal);
			        return NGX_DECLINED; // Access denied for "all"
				}
			} // End discovered "all"

		} // End loop
	} // End have some rules
	else{ // Have no rules
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_http_raven_check_principal: No rules defined");
		return NGX_OK; // Implcit allow "all"
	}
	return NGX_DECLINED; // Safety net, we should never get here, but it's safe to do so (access denied)
}

/*
 * This function returns NGX_OK if a session cookie is found, NGX_DECLINED otherwise
 *
 * Uses the function ngx_http_parse_multi_header_lines to locate a header line that contains the cookie with the name that is specified
 * by the configuration
 */
static ngx_int_t ngx_http_session_cookie_check(ngx_http_request_t *r,
		ngx_str_t *value, ngx_http_raven_loc_conf_t *raven_config) {

	if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, // Find the cookie!
			&raven_config->RavenCookieName, value) == NGX_DECLINED) {
		return NGX_DECLINED;
	}
	return NGX_OK;
}

/*
 * Constant-time function to replace strcmp, avoiding early-out optimisations and thus also evading timing attacks
 * Returns 0 on success, -1 on length mismatch, some other number on further failure
 */
static ngx_int_t ngx_http_raven_strneq(char *s1, char *s2) {
	ngx_int_t i = 0;
	char *c1 = s1, *c2 = s2; // Disposable pointers
	if (strlen(s1) != strlen(s2)) // Don't wish to access beyond end of s2, and this is a fail anyway!
		return -1;
	for (i = 0; c1[i]; c1[i] != c2[i] ? i++ : *c1++, *c2++)
		; // Stupid unreadable on-liner to wade through entire string
	return i;
}

/*
 * This function checks the validity and authenticity of a session cookie
 * and writes a pointer to the principal into **principal
 * Returns NGX_OK for a good cookie, NGX_DECLINED otherwise
 */
static ngx_int_t ngx_http_raven_cookie_ok(ngx_http_request_t *r, ngx_str_t *value,
		ngx_http_raven_loc_conf_t *raven_config, char **principal) {
	struct {
		char *principal;
		char *expiry;
		char *sig;
	} COOKIE_STRUCT;
	char *str, *payload;
	ngx_str_t unencoded_sig;
	ngx_str_t encoded_sig;
	unsigned char hash[32]; // To hold SHA256-HMAC hash
	int i;
	/*
	 * First we check to see if there are enough parameters
	 */
	str = (char *) value->data; // Set pointer to start of data

	for (i = 0; str[i]; str[i] == '!' ? i++ : *str++); // Stupid unreadable one-liner for counting occurrences of '!'
	if (i != COOKIE_EXPECTED_PARAMS - 1) // - 1 as last parameter will not have an '!' appended to it
		return NGX_DECLINED; // Broken cookie, not enough or too many parameters
    /*
     * Now we unwrap the cookie's internal parameters and test them
     */
	str = (char *) value->data; // Reset pointer to start of data

	COOKIE_STRUCT.principal = strsep(&str, "!");

	if (ngx_http_raven_check_principal(r, COOKIE_STRUCT.principal, raven_config)
			!= NGX_OK) {
				return NGX_DECLINED; // Principal not defined in rule or explicitly denied
			}

	COOKIE_STRUCT.expiry = strsep(&str, "!");

	if(ngx_atoi((u_char *)COOKIE_STRUCT.expiry, strlen(COOKIE_STRUCT.expiry)) < ngx_time())
	{
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_http_raven_cookie_ok: Cookie has expired");
		return NGX_DECLINED;
	}

	COOKIE_STRUCT.sig = strsep(&str, "!$"); // Cookies are terminated with a dollar to make it easier to find the end of the string

	payload = (char *) ngx_pcalloc(r->pool, 8 + strlen(COOKIE_STRUCT.principal) // 8 counts for token separators with some slack too
			+strlen(COOKIE_STRUCT.expiry)
			+strlen(COOKIE_STRUCT.sig) + 1); // +1 for NULL termination

	ngx_sprintf((u_char *) payload, "%s!%s", COOKIE_STRUCT.principal, // Make check string
			COOKIE_STRUCT.expiry);

	mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), // Generate SHA256-HMAC sig
			(const unsigned char *) raven_config->RavenSecretKey.data,
			raven_config->RavenSecretKey.len, (const unsigned char*) payload,
			strlen(payload), hash);

	ngx_pfree(r->pool, payload);

	unencoded_sig.len = 32; // Right size for holding raw SHA256-HMAC
	unencoded_sig.data = (u_char *) hash;

	encoded_sig.len = ngx_base64_encoded_length(32); // Defined in ngx_string.h
	encoded_sig.data = ngx_pcalloc(r->pool, encoded_sig.len + 1); // +1 for NULL termination

	ngx_encode_base64(&encoded_sig, &unencoded_sig); // (dst, src)

	encoded_sig.data[encoded_sig.len] = '\0'; // Null terminate to be safe and tidy

	if (ngx_http_raven_strneq((char *) encoded_sig.data, COOKIE_STRUCT.sig) == 0) { // Signatures match
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
				"ngx_http_raven_cookie_ok: Sig match,\nA: %s\nB: %s",
				COOKIE_STRUCT.sig, (char *) encoded_sig.data);

		*principal = COOKIE_STRUCT.principal;

		ngx_pfree(r->pool, encoded_sig.data);

		return NGX_OK;
	}

	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, // Signatures do not match
			"ngx_http_raven_cookie_ok: Sig mismatch,\nA: %s\nB: %s",
			COOKIE_STRUCT.sig, (char *) encoded_sig.data);

	ngx_pfree(r->pool, encoded_sig.data);

	return NGX_DECLINED;
}

/*
 * This function retuns NGX_OK if a WLS response is found, NGX_DECLINED otherwise
 *
 * Returns any discovered WLS response at "value" (read only please)
 */
static ngx_int_t ngx_http_wls_response_check(ngx_http_request_t *r,
		ngx_str_t *value) {
	ngx_str_t search_string = ngx_string("WLS-Response");
	/*
	 * Function below sets "value" to point within request structure, does not make a deep copy
	 */
	ngx_int_t search_string_exists = ngx_http_arg(r, search_string.data,
			search_string.len, value);

	if ((search_string_exists == NGX_OK) && value->len > 0) {
		return NGX_OK; // Found a WLS response
		}
	return NGX_DECLINED; // Did not find a WLS response
}

/*
 * This function checks the signature of a WLS response. It returns 1 for success, 0 on failure
 *
 * In mbed TLS there is a direct way (by using the RSA module) and an advised way (by using the Public Key layer) to use RSA
 * To obtain pubkey use 'openssl x509 -pubkey -noout -in pubkey901.crt > raven.pem
 */
static ngx_int_t ngx_http_raven_check_sig(ngx_http_request_t *r, char *dat, char *sig) {
	int res = 0;
	int verified = 0; // Separate variable for reporting verification failure/success
	unsigned char hash[20]; // To hold SHA1 hash
	char errbuf[128];
	mbedtls_sha1((unsigned char*) dat, strlen(dat), hash);
	if ((res = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA1, hash, 20,
			(const unsigned char*) sig, 128)) == 0) { // Can't use strlen(sig) here, as sig is binary data and may have an embedded NULL
		verified = 1; // Success
	} else {
		/* Fetch mbed TLS error description */
		mbedtls_strerror(res, errbuf, sizeof(errbuf));
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_raven_check_sig: mbedtls_pk_verify error %d: %s",
				res, errbuf);
	}
	return verified; // Might change to return NGX_OK/NGX_DECLINED for consitency
}

/*
 * This function is used to "URL escape" a string, but is avoids "!" and "%" characters
 *
 * Curiously, mod_ucam_webauth.c seems to escape a string, and then unescape these characters, which seems inefficient
 */
static ngx_int_t ngx_http_raven_special_escape(char *sSource, char *sDest) {
	int nLength;
	for (nLength = 0; *sSource; nLength++) {
		if (*sSource == '%' && sSource[1] && sSource[2] && isxdigit(sSource[1])
				&& isxdigit(sSource[2])) {
			if (strncmp(sSource + 1, "21", 2) != 0
					&& strncmp(sSource + 1, "25", 2) != 0) { // Skip special characters
				sSource[1] -=
						sSource[1] <= '9' ?
								'0' : (sSource[1] <= 'F' ? 'A' : 'a') - 10;
				sSource[2] -=
						sSource[2] <= '9' ?
								'0' : (sSource[2] <= 'F' ? 'A' : 'a') - 10;
				sDest[nLength] = 16 * sSource[1] + sSource[2];
				sSource += 3;
				continue;
			}
		}
		sDest[nLength] = *sSource++;
	}
	sDest[nLength] = '\0';
	return nLength;
}

/*
 * This function validates a WLS response, returning NGX_OK on success, NGX_DECLINED otherwise
 *
 * Warning: "value" will be overwritten/destroyed as it gets fed to strsep! Om nom nom
 */
static ngx_int_t ngx_http_raven_wls_response_ok(ngx_http_request_t *r, ngx_str_t *value,
		char **original_url, ngx_http_raven_loc_conf_t *raven_config) {
	struct {
		char *ver;
		char *status;
		char *msg;
		char *issue;
		char *id;
		char *url;
		char *principal;
		char *ptags;
		char *auth;
		char *sso;
		char *life;
		char *params;
		char *kid;
		char *sig;
	} WLS_RESPONSE;
	char *str, *dat;
	ngx_str_t encoded_sig;
	ngx_str_t decoded_sig;
	int i;
	time_t cur_time; // To hold the actual time (UTC)
	struct tm issue_tm; // To hold the WLS response issue time (UTC)
	time_t issue_time; // To hold the WLS response issue time (UTC)
	time_t time_skew; // The number of seconds either side of "now" that we'll accept a WLS response issue time
	/*
	 * First we check to see if there are enough parameters
	 */
	str = (char *) value->data; // Set pointer to start of data

	for (i = 0; str[i]; str[i] == '!' ? i++ : *str++); // Stupid unreadable one-liner for counting occurrences of '!'
	if (i != WLS_RESPONSE_EXPECTED_PARAMS - 1) // - 1 as last parameter will not have an "!" appended to it
		return NGX_DECLINED; // Broken response, not enough or too many parameters
/*
 * Now we unwrap the internal parameters of the WLS response
 */
	str = (char *) value->data; // reset pointer to start of data

	ngx_http_raven_special_escape(str, str); // Escapes args, avoiding "!" and "%"

	/*
	 * We use strsep instead of strtok to correctly parse "missing" tokens (strtok would skip successive delimiters)
	 * This is less portable, but still very portable
	 */
	WLS_RESPONSE.ver = strsep(&str, "!");

	if(strcmp(WLS_RESPONSE.ver, VER) != 0) // Check here that version is 3+
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"ngx_http_raven_wls_response_ok: Unknown WLS response version %s",
				WLS_RESPONSE.ver);
		return NGX_DECLINED; // This version is unkown, and we do not know how to handle
	}
	WLS_RESPONSE.status = strsep(&str, "!");

	if(strcmp(WLS_RESPONSE.status, "200") != 0) // Check here that status is 200 "OK"
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"ngx_http_raven_wls_response_ok: Unexpected WLS response status %s",
				WLS_RESPONSE.status);
		return NGX_DECLINED; // Authentication apparently failed, but this should be handled by the WLS, so we probably never get here
	}

	WLS_RESPONSE.msg = strsep(&str, "!");
	WLS_RESPONSE.issue = strsep(&str, "!");

	/*
	 * Check issue time
	 */
	cur_time = ngx_time();
	strptime(WLS_RESPONSE.issue, TIMESTAMP_FORMAT, &issue_tm);
	issue_time = timegm(&issue_tm);
	// RavenLazyClock init
	if(raven_config->RavenLazyClock) {
		time_skew = 60;
	} else {
		// Allow for small time difference causing second wrap (matching the behaviour of mod_ucam_webauth)
		time_skew = 1;
	}
	if(issue_time > cur_time + time_skew) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"ngx_http_raven_wls_response_ok: WLS response issued in the future (local clock incorrect?); issue time %s (%d) vs. local clock %d",
				WLS_RESPONSE.issue,
				issue_time,
				cur_time);
		return NGX_DECLINED;
	}
	if(cur_time - time_skew - 1 > issue_time + RESPONSE_TIMEOUT) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"ngx_http_raven_wls_response_ok: WLS response issued too long ago (local clock incorrect?); issue time %s (%d) vs. local clock %d",
				WLS_RESPONSE.issue,
				issue_time,
				cur_time);
		return NGX_DECLINED;
	}

	WLS_RESPONSE.id = strsep(&str, "!");
	WLS_RESPONSE.url = strsep(&str, "!");
	/*
	 * We don't bother checking the URL, we just check the returned params instead (weaker perhaps, but simpler and faster)
	 */
	WLS_RESPONSE.principal = strsep(&str, "!");

	if (ngx_http_raven_check_principal(r, WLS_RESPONSE.principal, raven_config) // Check user
			!= NGX_OK) { // Bad user
		return NGX_DECLINED; // User not accounted for
	}

	WLS_RESPONSE.ptags = strsep(&str, "!"); // Not currently implemented, but would be a simple addition
	WLS_RESPONSE.auth = strsep(&str, "!");
	WLS_RESPONSE.sso = strsep(&str, "!");
	WLS_RESPONSE.life = strsep(&str, "!");
	WLS_RESPONSE.params = strsep(&str, "!");

	if(strcmp(WLS_RESPONSE.params, guid) != 0){ // Check returned params here
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"ngx_http_raven_wls_response_ok: Incorrect or missing server GUID (replayed response from another server?)");
		return NGX_DECLINED; // Probably the response was intercepted from another server and replayed
	}

	WLS_RESPONSE.kid = strsep(&str, "!");
	WLS_RESPONSE.sig = strsep(&str, "!");

	if (WLS_RESPONSE.sig == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"ngx_http_raven_wls_response_ok: No sig found");
		return NGX_DECLINED; // Can't do anything without a sig, plus it will break the routine below
	}

	/*
	 * Replace special characters in sig. This is done by the WLS to reduce encoding overhead, but it is a bit annoying in practice
	 */
	for (i = 0; i < (int) strlen(WLS_RESPONSE.sig); i++) {
		if (WLS_RESPONSE.sig[i] == '-')
			WLS_RESPONSE.sig[i] = '+';
		else if (WLS_RESPONSE.sig[i] == '.')
			WLS_RESPONSE.sig[i] = '/';
		else if (WLS_RESPONSE.sig[i] == '_')
			WLS_RESPONSE.sig[i] = '=';
	}

	encoded_sig.len = strlen(WLS_RESPONSE.sig);
	encoded_sig.data = (u_char *) WLS_RESPONSE.sig;

	decoded_sig.len = ngx_base64_decoded_length(encoded_sig.len) + 1; // + 1 for NULL termination
	decoded_sig.data = ngx_pcalloc(r->pool, decoded_sig.len);

	if (ngx_decode_base64(&decoded_sig, &encoded_sig) == NGX_OK) { // Did we have trouble Base64 decoding the sig?
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
				"ngx_http_raven_wls_response_ok: Decoded sig OK, length: %d", decoded_sig.len);
	} else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"ngx_http_raven_wls_response_ok: Bad decoded sig, length: %d", decoded_sig.len);
	}

	decoded_sig.data[decoded_sig.len] = '\0'; // NULL terminate to be safe and tidy

	dat = (char *) ngx_pcalloc(r->pool, 64 // strlen(FORMAT_STRING) < 64
			+ strlen(WLS_RESPONSE.ver)
			+ strlen(WLS_RESPONSE.status)
			+ strlen(WLS_RESPONSE.msg)
			+ strlen(WLS_RESPONSE.issue)
			+ strlen(WLS_RESPONSE.id)
			+ strlen(WLS_RESPONSE.url)
			+ strlen(WLS_RESPONSE.principal)
			+ strlen(WLS_RESPONSE.ptags)
			+ strlen(WLS_RESPONSE.auth)
			+ strlen(WLS_RESPONSE.sso)
			+ strlen(WLS_RESPONSE.life)
			+ strlen(WLS_RESPONSE.params) + 1); // + 1 for NULL termination

	ngx_sprintf((u_char *) dat, "%s!%s!%s!%s!%s!%s!%s!%s!%s!%s!%s!%s", // Make check string
			WLS_RESPONSE.ver, WLS_RESPONSE.status, WLS_RESPONSE.msg,
			WLS_RESPONSE.issue, WLS_RESPONSE.id, WLS_RESPONSE.url,
			WLS_RESPONSE.principal,
			WLS_RESPONSE.ptags, // <- This one has ptags (v3+)
			WLS_RESPONSE.auth, WLS_RESPONSE.sso, WLS_RESPONSE.life,
			WLS_RESPONSE.params);

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
			"ngx_http_raven_wls_response_ok: Checking WLS-Response: %s", dat);

	if (!ngx_http_raven_check_sig(r, dat, (char *) decoded_sig.data)) {
		ngx_pfree(r->pool, decoded_sig.data);
		ngx_pfree(r->pool, dat);
		return NGX_DECLINED;
	}
	ngx_pfree(r->pool, decoded_sig.data);
	ngx_pfree(r->pool, dat);
	value->len = strlen(WLS_RESPONSE.principal);
	value->data = (u_char *)WLS_RESPONSE.principal; // Return principal in value parameter
	*original_url = WLS_RESPONSE.url; // Return pointer to url
	return NGX_OK;
}

/*
 * This function drops a session cookie on the client. Returns NGX_OK on success, NGX_DECLINED otherwise
 * Warning: 'value' will be overwritten/destroyed as it gets fed to strsep! Om nom nom
 */
static ngx_int_t ngx_http_raven_drop_cookie(ngx_http_request_t *r, char *principal,
		ngx_http_raven_loc_conf_t *raven_config) {
	char *cookie, *payload;
	ngx_table_elt_t *set_cookie;
	unsigned char hash[32]; // To hold SHA256-HMAC hash
	ngx_str_t unencoded_sig;
	ngx_str_t encoded_sig;
	time_t expires;
	/*
	 * The "expires" field should be big enough to accommodate 9 digits (max Sat, 20th Nov 2286 @ 17:46:39)
	 */
	// Memory to be handed over to r->headers_out list entry
	cookie = ngx_pcalloc(r->pool, 256 + strlen(principal) + 1); // Make sure is zeroed, as will be returned to client and may otherwise leak data
	if (cookie == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"ngx_http_raven_drop_cookie: Could not allocate memory for cookie: %s", strerror(errno));
		return NGX_DECLINED;
	}

	payload = (char *) ngx_pcalloc(r->pool,  64 +  strlen(principal)  + 1);

	expires = ngx_time() + raven_config->RavenMaxSessionLife;

	ngx_sprintf((u_char *) payload, "%s!%d", principal, expires);

	mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
			(const unsigned char *) raven_config->RavenSecretKey.data,
			raven_config->RavenSecretKey.len, (const unsigned char*) payload,
			strlen(payload), hash);

	unencoded_sig.len = 32;
	unencoded_sig.data = (u_char *) hash;

	encoded_sig.len = ngx_base64_encoded_length(32); // Defined in ngx_string.h
	encoded_sig.data = ngx_pcalloc(r->pool, encoded_sig.len + 1); // +1 for NULL termination

	ngx_encode_base64(&encoded_sig, &unencoded_sig); // (dst, src)

	encoded_sig.data[encoded_sig.len] = '\0'; // Null terminate to be safe and tidy

	ngx_sprintf((u_char *) cookie, "%s=%s!%s$; HttpOnly", // Cookies are terminated with a dollar to make it easier to find the end of the sig
			(char *) raven_config->RavenCookieName.data, payload,
			(char *) encoded_sig.data);

	ngx_pfree(r->pool, encoded_sig.data);

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_http_raven_drop_cookie: Set-Cookie: %s", cookie);

	set_cookie = ngx_list_push(&r->headers_out.headers);
	if (set_cookie == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"ngx_http_raven_drop_cookie: Could not allocate memory for Set-Cookie header: %s", strerror(errno));
		return NGX_DECLINED;
	}

	set_cookie->hash = 1;
	ngx_str_set(&set_cookie->key, "Set-Cookie");
	set_cookie->value.len = strlen(cookie);
	set_cookie->value.data = (u_char *) cookie;

	return NGX_OK;
}

/*
 *  Useful function from ngx_http_modsecurity.c
 *  nginx only provides ngx_pstrdup, perhaps due to it's preferred use of "ngx_str_t" and its incumbent "len" member
 */
static inline u_char *
ngx_pstrdup0(ngx_pool_t *pool, ngx_str_t *src) {
	u_char *dst;
	dst = ngx_pnalloc(pool, src->len + 1);
	if (dst == NULL) {
		return NULL;
	}
	ngx_memcpy(dst, src->data, src->len);
	dst[src->len] = '\0';
	return dst;
}

/*
 * Fake up a basic Authorization header so that $remote_user is set
 */
static ngx_int_t ngx_http_raven_fake_auth_header(ngx_http_request_t *r, char *principal) {
	ngx_str_t auth_hdr_decoded;
	ngx_str_t auth_hdr;
	ngx_str_t auth_hdr_p;
	ngx_http_raven_loc_conf_t *raven_config;

	raven_config = ngx_http_get_module_loc_conf(r, ngx_http_raven_module);
	if (!raven_config->RavenSetUser) {
		return NGX_DECLINED;
	}

	auth_hdr_decoded.len = strlen(principal)+1;  // for trailing colon, <username>:
	auth_hdr_decoded.data = ngx_pcalloc(r->pool, auth_hdr_decoded.len+1); // for NULL termination
	if (auth_hdr_decoded.data != NULL) {
		ngx_memcpy(auth_hdr_decoded.data, principal, auth_hdr_decoded.len-1);
		auth_hdr_decoded.data[auth_hdr_decoded.len-1] = ':';
		auth_hdr_decoded.data[auth_hdr_decoded.len] = '\0';
		auth_hdr.len = ngx_base64_encoded_length(auth_hdr_decoded.len) + sizeof("Basic ") - 1;
		// Memory to be handed over to r->headers_in list entry
		auth_hdr.data = ngx_pcalloc(r->pool, auth_hdr.len+1);
		if (auth_hdr.data != NULL) {
			ngx_memcpy(auth_hdr.data, (char *)"Basic ", sizeof("Basic ") - 1);
			auth_hdr_p.data = auth_hdr.data + sizeof("Basic ") - 1;
			auth_hdr_p.len = auth_hdr.len - sizeof("Basic ") + 1;
			ngx_encode_base64(&auth_hdr_p, &auth_hdr_decoded);
			ngx_pfree(r->pool, auth_hdr_decoded.data);

			if (r->headers_in.authorization == NULL) {
				r->headers_in.authorization = ngx_list_push(&r->headers_in.headers);
			}
			r->headers_in.authorization->hash = 1;
			r->headers_in.authorization->key.data = ngx_pcalloc(r->pool, sizeof("Authorization\0"));
			if (r->headers_in.authorization->key.data != NULL) {
				ngx_memcpy(r->headers_in.authorization->key.data, (char *)"Authorization\0", sizeof("Authorization\0"));
				r->headers_in.authorization->key.len = sizeof("Authorization");
			}
			r->headers_in.authorization->value = auth_hdr;

			return NGX_OK;
		}
		ngx_pfree(r->pool, auth_hdr_decoded.data);
	}
	return NGX_ERROR;
}

/*
 * This is the main handler function. Where the magic happens
 *
 * Returns NGX_HTTP_FORBIDDEN, unless it finds and validates either a session cookie or a WLS response (in that order),
 * in which case it returns NGX_DECLINED
 */
static ngx_int_t ngx_http_raven_handler(ngx_http_request_t *r) {
	struct {
		char *ver;
		char *url;
		char *url_escaped; // Working space
		char *desc;
		char *aauth;
		char *iact;
		char *msg;
		char *params;
		char *date;
		char *skew;
		char *fail;
	} WLS_REQUEST;
	in_port_t port; // e.g. "8080"
	char *principal; // The authenticated user, e.g. "fjc55"
	struct sockaddr_in *sin;
#if (NGX_HAVE_INET6)
	struct sockaddr_in6 *sin6;
#endif

	ngx_http_raven_loc_conf_t *raven_config;
	ngx_str_t value, cookie_string, wls_response_string; // Somewhere to keep either the cookie string or WLS response string we (may) find
	char *redirect; // String for redirection URL
	char *uri; // We save a copy of the uri field in the request as it will be overwritten by strsep later

	raven_config = ngx_http_get_module_loc_conf(r, ngx_http_raven_module);
/*
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "UUID: %s", guid);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Public key: %s", key);
*/
	  if (r->main->internal) { // Is this the first time we've seen this request?
	    return NGX_DECLINED;
	  }

	  r->main->internal = 1; // Apparently not

	if (!raven_config->RavenActive){ // Should we interfere with requests for this location?
		return NGX_DECLINED; // Apparently not
	}

	if (raven_config->RavenCookieName.len == 0) {
		/*
		 * We need a cookie name to work with! Should at least be a default, else something has gone terribly wrong
		 */
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_raven_handler: zero-length cookie name");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	/*
	 * Try and find a session cookie
	 */
	if (ngx_http_session_cookie_check(r, &value, raven_config) == NGX_OK) { // Is there a cookie?
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_http_raven_handler: Found cookie \"%s\"", (char *)raven_config->RavenCookieName.data);
		cookie_string.data = ngx_pstrdup0(r->pool, &value); // Make a copy of value, as we may work destructively with this string
		if (ngx_http_raven_cookie_ok(r, &cookie_string, raven_config, &principal) == NGX_OK) {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_http_raven_handler: Cookie OK");
			ngx_http_raven_fake_auth_header(r, principal);
			return NGX_DECLINED;
		}
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_raven_handler: Bad cookie");
	}
	/*
	 * We only get here if there is no valid session cookie, so now we look for a WLS response
	 */
	if (ngx_http_wls_response_check(r, &value) == NGX_OK) { // is there a WLS response?
		wls_response_string.data = ngx_pstrdup0(r->pool, &value); // Make a copy of value, as we may work destructively with this string
		if (ngx_http_raven_wls_response_ok(r, &wls_response_string, &redirect, raven_config) == NGX_OK) {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
					"ngx_http_raven_handler: WLS response is OK");
			principal = (char *)wls_response_string.data;
			/*
			 * Drop a cookie with the discovered principal
			 */
			if (ngx_http_raven_drop_cookie(r, principal, raven_config) != NGX_OK) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"ngx_http_raven_handler: Failed to set cookie");
			}

			/*
			 * Successful authentication; return (optionally to a cleaned-up URL)
			 */
			ngx_http_raven_fake_auth_header(r, principal);
			if(raven_config->RavenCleanUrl) {
				r->headers_out.location = ngx_list_push(&r->headers_out.headers);
				r->headers_out.location->hash = 1;
				r->headers_out.location->key.len = sizeof("Location") - 1;
				r->headers_out.location->key.data = (u_char *) "Location";
				r->headers_out.location->value.len = strlen(redirect);
				r->headers_out.location->value.data = (unsigned char *)redirect;

				if (r->http_version >= NGX_HTTP_VERSION_11) {
					return NGX_HTTP_SEE_OTHER; // 303
				} else {
					return NGX_HTTP_MOVED_TEMPORARILY; // 302
				}
			} else {
				return NGX_DECLINED;
			}
		} else {
			return NGX_HTTP_FORBIDDEN; // Looks like someone has tampered with the sig, or some other condition is not met
		}
	}

/*
 * We only get here if there is no valid session cookie or WLS response, so now we perform redirect
 */
	WLS_REQUEST.ver = VER
	;

	/*
	 * You might think we can use r->port_start, but it is actually not used and always NULL
	 */
	switch (r->connection->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *) r->connection->local_sockaddr;
		port = ntohs(sin6->sin6_port);
		break;
#endif

	default: // AF_INET
		sin = (struct sockaddr_in *) r->connection->local_sockaddr;
		port = ntohs(sin->sin_port);
		break;
	}

	uri = (char *) ngx_pcalloc(r->pool, r->uri.len + 1 + r->args.len + 1); // to accommodate '?' and NULL terminator
	if (uri == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"ngx_http_raven_handler: Could not allocate memory for uri: %s", strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ngx_memcpy(uri, r->uri.data, r->uri.len); // Copy
	if (r->args.len > 0) {
		uri[r->uri.len] = '?';
		ngx_memcpy(uri + r->uri.len + 1, r->args.data, r->args.len);
		uri[r->uri.len + 1 + r->args.len] = '\0'; // NULL terminate to be safe and tidy
	} else {
		uri[r->uri.len] = '\0'; // NULL terminate to be safe and tidy
	}

	WLS_REQUEST.url = (char *) ngx_pcalloc(r->pool, 16 + r->headers_in.server.len + r->uri.len + 1 + r->args.len + 1); // strlen("https://:65535") < 14, + '?' + NULL termination
	WLS_REQUEST.url_escaped = (char *) ngx_pcalloc(r->pool, 3*(16 + r->headers_in.server.len + r->uri.len + 1 + r->args.len) + 1); // Same as above, but three times bigger for maximum possible escaping

#if (NGX_HTTP_SSL)
	if(r->http_connection->ssl) // Make an "https://" prefixed url
	{
		ngx_sprintf((u_char *)WLS_REQUEST.url, "https://%V:%ui%s", &r->headers_in.server, port, uri);
	}
	else // Make an "http://" prefixed url
	{
		ngx_sprintf((u_char *)WLS_REQUEST.url, "http://%V:%ui%s", &r->headers_in.server, port, uri);
	}
#endif
#if(!NGX_HTTP_SSL)
	ngx_sprintf((u_char *) WLS_REQUEST.url, "http://%V:%ui%s", &r->headers_in.server, port, uri);
#endif

	ngx_pfree(r->pool, uri);

	ngx_escape_uri((u_char *) WLS_REQUEST.url_escaped,
			(u_char *) WLS_REQUEST.url, strlen(WLS_REQUEST.url),
			NGX_ESCAPE_URI_COMPONENT); // Important; use ngx_escape_uri_component, not ngx_escape_uri

	WLS_REQUEST.desc = EMPTY_PARAM
	;
	WLS_REQUEST.aauth = EMPTY_PARAM
	;
	WLS_REQUEST.iact = EMPTY_PARAM
	;
	WLS_REQUEST.msg = EMPTY_PARAM
	;
	WLS_REQUEST.params = guid; // This will help to fingerprint the anticipated WLS response and avoid replay attacks
	;
	WLS_REQUEST.date = EMPTY_PARAM
	;
	WLS_REQUEST.skew = "0"; // MUST be "0" if it is included, it is now deprecated
	WLS_REQUEST.fail = "yes"; // Get WLS to handle error conditions for simplicity

	// Memory to be handed over to r->headers_out list entry
	redirect = (char *) ngx_pcalloc(r->pool, 64 + raven_config->RavenLogin.len // strlen(FORMAT_STRING) < 64
			+ strlen(WLS_REQUEST.ver)
			+ strlen(WLS_REQUEST.url_escaped)
			+ strlen(WLS_REQUEST.desc)
			+ strlen(WLS_REQUEST.aauth)
			+ strlen(WLS_REQUEST.iact)
			+ strlen(WLS_REQUEST.msg)
			+ strlen(WLS_REQUEST.params)
			+ strlen(WLS_REQUEST.date)
			+ strlen(WLS_REQUEST.skew)
			+ strlen(WLS_REQUEST.fail) + 1); // + 1 for NULL termination

	ngx_sprintf((u_char *) redirect, // Make check string
			"%s?ver=%s&url=%s&desc=%s&aauth=%s&iact=%s&msg=%s&params=%s&date=%s&skew=%s&fail=%s",
			raven_config->RavenLogin.data, WLS_REQUEST.ver,
			WLS_REQUEST.url_escaped, WLS_REQUEST.desc, WLS_REQUEST.aauth,
			WLS_REQUEST.iact, WLS_REQUEST.msg, WLS_REQUEST.params,
			WLS_REQUEST.date, WLS_REQUEST.skew, WLS_REQUEST.fail);

	ngx_pfree(r->pool, WLS_REQUEST.url);
	ngx_pfree(r->pool, WLS_REQUEST.url_escaped);

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_http_raven_handler: Redirecting to: %s", redirect);

	r->headers_out.location = ngx_list_push(&r->headers_out.headers);
	if (r->headers_out.location == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"ngx_http_raven_handler: Could not allocate memory for Location header: %s", strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	r->headers_out.location->hash = 1;
	r->headers_out.location->key.len = sizeof("Location") - 1;
	r->headers_out.location->key.data = (u_char *) "Location";
	r->headers_out.location->value.len = strlen(redirect);
	r->headers_out.location->value.data = (u_char *) redirect;

	if (r->http_version >= NGX_HTTP_VERSION_11) {
		return NGX_HTTP_SEE_OTHER; // 303
	} else {
		return NGX_HTTP_MOVED_TEMPORARILY; // 302
	}
	// Shell Beach
}

/*
 * This function is referenced by ngx_http_raven_commands
 * Used for handling multiple allow/deny rules
 */
static char *
ngx_http_raven_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_raven_loc_conf_t *raven_conf = conf;
	ngx_uint_t all;
	ngx_str_t *value;
	ngx_http_raven_rule_t *rule;

	value = cf->args->elts;

	all = (value[1].len == 3 && ngx_strcmp(value[1].data, "all") == 0);

	if (!all) {
		/*
		 *  No work here, decided to handle this downstream in ngx_http_raven_check_principal
		 */
	}

	if (raven_conf->rules == NULL) {
		raven_conf->rules = ngx_array_create(cf->pool, 4,
				sizeof(ngx_http_raven_rule_t));
		if (raven_conf->rules == NULL) {
			return NGX_CONF_ERROR;
		}
	}

	rule = ngx_array_push(raven_conf->rules);
	if (rule == NULL) {
		return NGX_CONF_ERROR;
	}

	rule->principal = value[1];
	rule->deny = (value[0].data[5] == 'D') ? 1 : 0; // Deny? (Raven!D!eny)
	if (rule->deny) {
		ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
				"ngx_http_raven_rule: Adding rule #%d (deny) for user %s", raven_conf->rules->nelts,
				rule->principal.data);
	} else {
		ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
				"ngx_http_raven_rule: Adding rule #%d (allow) for user %s", raven_conf->rules->nelts,
				rule->principal.data);
	}
	return NGX_CONF_OK;
}

/*
 * This function sets up access phase handler, and initialises global variables "key" and "uuid"
 */
static ngx_int_t ngx_http_raven_init(ngx_conf_t *cf) {
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf;
	uuid_t uu; // u_char *uu[16]
	int res = 0;
	char errbuf[128];

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}
	*h = ngx_http_raven_handler;

/*
 * Load public key from disk into RAM
 */
	mbedtls_pk_init(&pk);
	if ((res = mbedtls_pk_parse_public_keyfile(&pk, PUBKEY)) != 0) {
		/* Fetch mbed TLS error description */
		mbedtls_strerror(res, errbuf, sizeof(errbuf));
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"ngx_http_raven_init: Cannot load public key '%s': mbedtls_pk_parse_public_keyfile error %d: %s",
				PUBKEY, res, errbuf);
		return NGX_ERROR;
	}

/*
 * Generate GUID for this instance (will be sent to WLS in params as a "fingerprint")
 */
	uuid_generate_time(uu);
	guid = (char *) ngx_pcalloc(cf->pool, 37); // The uuid_unparse function converts the supplied UUID uu from the binary representation into a 36-byte string (plus trailing '\0')
	uuid_unparse(uu, guid); // Guaranteed to be NULL terminated

	return NGX_OK;
}
