/*
 * firebase-auth.c
 * 
 * Copyright 2021 chehw <hongwei.che@gmail.com>
 * 
 * The MIT License
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of 
 * this software and associated documentation files (the "Software"), to deal in 
 * the Software without restriction, including without limitation the rights to 
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
 * of the Software, and to permit persons to whom the Software is furnished to 
 * do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
 * SOFTWARE.
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <json-c/json.h>
#include <curl/curl.h>
#include "firebase-auth.h"
#include "utils.h"

enum mime_type
{
	mime_type_json = 0,
};

static const char * s_supported_mime_types[] = {
	[mime_type_json] = "application/json",
	NULL,
};

static const char * content_type_to_supported_ptr(const char * content_type)
{
	assert(content_type);
	for(size_t i = 0; i < (sizeof(s_supported_mime_types) / sizeof(s_supported_mime_types[0])); ++i)
	{
		const char * supported_type = s_supported_mime_types[i];
		if(NULL == supported_type) return NULL;
		if(0 == strcasecmp(content_type, supported_type)) return supported_type;
	}
	return NULL;
}

const firebase_auth_endpoints_t g_firebase_auth_endpoints[1] = {{
	.oauth_sign_in = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp",
	.email_sign_up = "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
	.email_sign_in = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword",
	.email_send_email_verification = "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode",
	.email_confirm_email_verification = "https://identitytoolkit.googleapis.com/v1/accounts:update",
	.change_email = "https://identitytoolkit.googleapis.com/v1/accounts:update",
	.change_password = "https://identitytoolkit.googleapis.com/v1/accounts:update",
	.send_password_reset = "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode",
	.verify_password_reset_code = "https://identitytoolkit.googleapis.com/v1/accounts:resetPassword",
}};

/****************************************
 * firebase_response 
****************************************/
//~ typedef struct firebase_response
//~ {
	//~ long http_response_code;
	//~ const char * content_type;
	//~ auto_buffer_t buf[1];
	//~ json_object * jresponse;
	
	//~ int err_code;
	//~ const char * err_desc;
//~ }firebase_response_t;
firebase_response_t * firebase_response_new(void)
{
	firebase_response_t * response = calloc(1, sizeof(*response));
	assert(response);
	
	auto_buffer_init(response->buf, 0);
	return response;
}
void firebase_response_free(firebase_response_t * response)
{
	if(NULL == response) return;
	
	if(response->jresponse) {
		json_object_put(response->jresponse);
		response->jresponse = NULL;
	}
		
	auto_buffer_cleanup(response->buf);
	free(response);
	return;
}

void firebase_response_dump(const firebase_response_t * response)
{
	fprintf(stderr, "==== %s(%p) ====\n", __FUNCTION__, response);
	assert(response);
	fprintf(stderr, "response_code: %ld\n", response->http_response_code);
	fprintf(stderr, "content-type: %s\n", response->content_type);
	fprintf(stderr, "content-length: %ld\n", (long)response->buf->length);
	
	if(response->content_type == s_supported_mime_types[mime_type_json] && response->jresponse) {
		fprintf(stderr, "json_response: %s\n", json_object_to_json_string_ext(response->jresponse, JSON_C_TO_STRING_PRETTY));
	}
	else if(response->buf->length > 0) {
#define MAX_DUMP_LENGTH (100)
		int dump_length = (response->buf->length < MAX_DUMP_LENGTH)?response->buf->length:MAX_DUMP_LENGTH;
		if(dump_length > 0) fprintf(stderr, "response_body: %*s", dump_length, (char *)response->buf->data);
#undef MAX_DUMP_LENGTH
	}
	
	if(response->err_code != 0) fprintf(stderr, "error: code=%d, desc='%s'\n", response->err_code, response->err_desc);
}

/****************************************
 * firebase_auth Implementations
****************************************/
typedef struct firebase_auth_private
{
	firebase_auth_context_t * ctx;
	json_object * jconfig;
	char * api_key;
}firebase_auth_private_t;
static firebase_auth_private_t * firebase_auth_private_new(firebase_auth_context_t * auth) 
{
	assert(auth);
	firebase_auth_private_t * priv = calloc(1, sizeof(*priv));
	assert(priv);
	priv->ctx = auth;
	auth->priv = priv;
	
	return priv;
}
static void firebase_auth_private_free(firebase_auth_private_t * priv)
{
	if(NULL == priv) return;
	
	// clear secets
	if(priv->api_key) {
		int cb_api_key = strlen(priv->api_key);
		
		if(cb_api_key > 0) memset(priv->api_key, 0, cb_api_key);
		free(priv->api_key);
		priv->api_key = NULL;
	}
	
	if(priv->jconfig) {
		json_object_put(priv->jconfig);
		priv->jconfig = NULL;
	}
	
	free(priv);
	return;
}

static int load_credentials(struct firebase_auth_context * auth, const char * credentials_file)
{
	assert(auth && auth->priv);
	firebase_auth_private_t * priv = auth->priv;
	
	json_object * jconfig = json_object_from_file(credentials_file);
	if(NULL == jconfig) return -1;
	
	assert(jconfig);
	
	priv->jconfig = jconfig;
	
	const char * api_key = json_get_value(jconfig, string, api_key);
	assert(api_key);
	
	priv->api_key = strdup(api_key);
	api_key = NULL;
		
	return 0;
}
static const char * get_api_key(struct firebase_auth_context * auth)
{
	assert(auth && auth->priv);
	firebase_auth_private_t * priv = auth->priv;

	return priv->api_key;
}

// "https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp",
static firebase_response_t * oauth_sign_in(struct firebase_auth_context * auth, json_object * jrequest)
{
	static const firebase_auth_endpoints_t * endpoints = g_firebase_auth_endpoints;
	debug_printf("%s() -> endpoint: %s", __FUNCTION__, endpoints->oauth_sign_in);
	

	return NULL;
}

firebase_auth_context_t * firebase_auth_context_init(firebase_auth_context_t * auth, void * user_data)
{
	if(NULL == auth) auth = calloc(1, sizeof(*auth));
	assert(auth);
	
	auth->user_data = user_data;
	
	auth->load_credentials = load_credentials;
	auth->get_api_key = get_api_key;
	auth->oauth_sign_in = oauth_sign_in;
	
	firebase_auth_private_t * priv = firebase_auth_private_new(auth);
	assert(priv && auth->priv == priv);
	
	firebase_auth_email_t * auth_email = firebase_auth_email_init(auth->auth_email, auth);
	assert(auth_email && auth_email == auth->auth_email && auth_email->auth == auth);

	return auth;
}
void firebase_auth_context_cleanup(firebase_auth_context_t * auth)
{
	if(NULL == auth) return;
	firebase_auth_private_free(auth->priv);
	return;
}

/****************************************
 * firebase_auth_email Implementations
****************************************/

static size_t auth_email_on_response(void * ptr, size_t size, size_t n, void * user_data)
{
	firebase_response_t * response = user_data;
	assert(response);
	
	size_t cb = size * n;
	if(cb == 0) return 0;
	
	auto_buffer_push(response->buf, ptr, cb);
	return cb;
}

static firebase_response_t * email_sign_up(struct firebase_auth_email * auth_email, const char * email, const char * password)
{
	const char * endpoint = g_firebase_auth_endpoints->email_sign_up;
	debug_printf("%s() -> endpoint: %s", __FUNCTION__, endpoint);
	
	assert(email && password);
	
	
	assert(auth_email && auth_email->auth && auth_email->curl);
	firebase_auth_context_t * auth = auth_email->auth;
	
	CURL * curl = auth_email->curl;
	curl_easy_reset(curl);
	
	char url[PATH_MAX] = "";
	const char * api_key = auth->get_api_key(auth);
	assert(api_key);
	
	int cb = snprintf(url, sizeof(url), "%s?key=%s", endpoint, api_key);
	assert(cb > 0);
	
	firebase_response_t * response = firebase_response_new();
	assert(response);
	
	CURLcode ret = 0;
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, auth_email->hdr_post_json);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, auth_email_on_response);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
	
	json_object * jrequest = json_object_new_object();
	assert(jrequest);
	
	json_object_object_add(jrequest, 
	
	
	
	ret = curl_easy_perform(curl);
	if(ret == CURLE_OK) {
		response->http_response_code = 0;
		ret = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->http_response_code);
		
		char * content_type = NULL;
		ret = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
		if(ret == CURLE_OK && content_type) {
			response->content_type = content_type_to_supported_ptr(content_type);
			if(NULL == response->content_type) response->content_type = content_type;
		}
	}
	
	if(ret != CURLE_OK) {
		response->err_code = ret;
		response->err_desc = curl_easy_strerror(ret);
	}
	api_key = NULL;
	return response;
}
static firebase_response_t * email_sign_in(struct firebase_auth_email * auth_email, const char * email, const char * password)
{
	assert(auth_email && auth_email->curl);
	return NULL;
}		  
static firebase_response_t * email_send_email_verification(struct firebase_auth_email * auth_email, const char * id_token)
{
	assert(auth_email && auth_email->curl);
	return NULL;
}
static firebase_response_t * email_confirm_email_verification(struct firebase_auth_email * auth_email, const char * email, const char * password)
{
	assert(auth_email && auth_email->curl);
	return NULL;
}
static firebase_response_t * email_change_email(struct firebase_auth_email * auth_email, const char * id_token, const char * new_email)
{
	assert(auth_email && auth_email->curl);
	return NULL;
}
static firebase_response_t * email_change_password(struct firebase_auth_email * auth_email, const char * id_token, const char * new_passwd)
{
	assert(auth_email && auth_email->curl);
	return NULL;
}
static firebase_response_t * email_send_password_reset_email(struct firebase_auth_email * auth_email, const char * email)
{
	assert(auth_email && auth_email->curl);
	return NULL;
}
static firebase_response_t * email_verify_password_reset_code(struct firebase_auth_email * auth_email, const char * oob_code)
{
	assert(auth_email && auth_email->curl);
	return NULL;
}
static firebase_response_t * email_confirm_password_reset(struct firebase_auth_email * auth_email, const char * oob_code, const char * new_passwd)
{
	assert(auth_email && auth_email->curl);
	return NULL;
}

firebase_auth_email_t * firebase_auth_email_init(firebase_auth_email_t * auth_email, struct firebase_auth_context * auth_ctx)
{
	assert(auth_ctx);
	if(NULL == auth_email) auth_email = calloc(1, sizeof(*auth_email));
	auth_email->auth = auth_ctx;
	
	CURL * curl = curl_easy_init();
	auth_email->hdr_post_json = curl_slist_append(NULL, "Content-Type: application/json");
	
	assert(curl);
	auth_email->curl = curl;
	
	auth_email->sign_up = email_sign_up;
	auth_email->sign_in = email_sign_in;					  
	auth_email->send_email_verification = email_send_email_verification;
	auth_email->confirm_email_verification = email_confirm_email_verification;
	auth_email->change_email = email_change_email;
	auth_email->change_password = email_change_password;
	auth_email->send_password_reset_email = email_send_password_reset_email;
	auth_email->verify_password_reset_code = email_verify_password_reset_code;
	auth_email->confirm_password_reset = email_confirm_password_reset;
	
	return auth_email;
}
void firebase_auth_email_cleanup(firebase_auth_email_t * auth_email)
{
	if(NULL == auth_email) return;
	if(auth_email->curl) {
		curl_easy_cleanup(auth_email->curl);
		auth_email->curl = NULL;
	}
	if(auth_email->hdr_post_json) {
		curl_slist_free_all(auth_email->hdr_post_json);
		auth_email->hdr_post_json = NULL;
	}
	return;
}

#if defined(_TEST_FIREBASE_AUTH) && defined(_STAND_ALONE)
int main(int argc, char **argv)
{
	/**
	 * credentials_file example: (json_file)
	 * 
	 * {
	 * 		"api_key": "[Your API_KEY]",
	 * }
	**/
	const char * credentials_file = "../../private/firebase-credentials.json";
	if(argc > 1) credentials_file = argv[1];
	
	firebase_auth_context_t firebase_auth[1];
	memset(firebase_auth, 0, sizeof(firebase_auth));
	
	firebase_auth_context_t * auth = firebase_auth_context_init(firebase_auth, NULL);
	assert(auth);
	
	int rc = auth->load_credentials(auth, credentials_file);
	assert(0 == rc);
	
	firebase_auth_email_t * auth_email = auth->auth_email;
	assert(auth_email);
	auth_email->locale = "ja_JP.UTF-8";
	
	
	const char * test_email = "chehw.jp@gmail.com";
	const char * test_change_email = "chehw.tlzs@gmail.com";
	const char * test_password = "00000000";
	const char * rest_reset_password = "11111111";
	
	// test email signup
	firebase_response_t * result = auth_email->sign_up(auth_email, test_email, test_password);
	firebase_response_dump(result);
	firebase_response_free(result);
	
	return 0;
}
#endif

