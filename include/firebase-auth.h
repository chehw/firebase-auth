#ifndef _FIREBASE_AUTH_H_
#define _FIREBASE_AUTH_H_

#include <stdio.h>
#include <json-c/json.h>
#include <stdarg.h>
#include "auto_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

//~ // helper function for languages other than C
//~ json_object * json_from_string(const char * json_str);
//~ const char * json_to_string(json_object * jobject);

typedef struct firebase_response
{
	long http_response_code;
	const char * content_type;
	auto_buffer_t buf[1];
	json_object * jresponse;
	
	int err_code;
	const char * err_desc;
}firebase_response_t;
firebase_response_t * firebase_response_new(void);
void firebase_response_free(firebase_response_t * response);	
void firebase_response_dump(const firebase_response_t * response);

typedef struct firebase_auth_endpoints
{
	const char * oauth_sign_in;		// https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key=[API_KEY]
	
	const char * email_sign_up; 	// https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=[API_KEY]
	const char * email_sign_in; 	// https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=[API_KEY]
	const char * email_send_email_verification;		// https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=[API_KEY]
	const char * email_confirm_email_verification; 	// https://identitytoolkit.googleapis.com/v1/accounts:update?key=[API_KEY]
	const char * email_change_email; 		// https://identitytoolkit.googleapis.com/v1/accounts:update?key=[API_KEY]
	const char * email_change_password; 	// https://identitytoolkit.googleapis.com/v1/accounts:update?key=[API_KEY]
	const char * email_send_password_reset_email; // https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=[API_KEY]
	const char * email_verify_password_reset_code; // https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key=[API_KEY]
	const char * email_confirm_password_reset; // https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key=[API_KEY]
}firebase_auth_endpoints_t;
extern const firebase_auth_endpoints_t g_firebase_auth_endpoints[];

typedef struct firebase_auth_email
{
// private:
	struct firebase_auth_context * auth;
	void * user_data;
	CURL * curl;
	struct curl_slist * hdr_post_json;
	const char * locale;	// Optional Headers; X-Firebase-Locale:
	int return_secure_token_flag;	// Whether or not to return an ID and refresh token. Default: 1(true)
	
// public: 
	firebase_response_t * (*sign_up)(struct firebase_auth_email * auth_email, const char * email, const char * password);
	firebase_response_t * (*sign_in)(struct firebase_auth_email * auth_email, const char * email, const char * password);
	
	firebase_response_t * (*send_email_verification)(struct firebase_auth_email * auth_email, const char * id_token);
	firebase_response_t * (*confirm_email_verification)(struct firebase_auth_email * auth_email, const char * oob_code);
	
	firebase_response_t * (*change_email)(struct firebase_auth_email * auth_email, const char * id_token, const char * new_email);
	firebase_response_t * (*change_password)(struct firebase_auth_email * auth_email, const char * id_token, const char * new_passwd);
	
	firebase_response_t * (*send_password_reset_email)(struct firebase_auth_email * auth_email, const char * email);
	firebase_response_t * (*verify_password_reset_code)(struct firebase_auth_email * auth_email, const char * oob_code);
	firebase_response_t * (*confirm_password_reset)(struct firebase_auth_email * auth_email, const char * oob_code, const char * new_passwd);
}firebase_auth_email_t;
firebase_auth_email_t * firebase_auth_email_init(firebase_auth_email_t * auth_email, struct firebase_auth_context * auth_ctx);
void firebase_auth_email_cleanup(firebase_auth_email_t * auth_email);

typedef struct firebase_auth_context
{
	void * user_data;
	void * priv;

	struct firebase_auth_email auth_email[1];
	
	int (* load_credentials)(struct firebase_auth_context * auth, const char * credentials_file);
	const char * (*get_api_key)(struct firebase_auth_context * auth);
	firebase_response_t * (* oauth_sign_in)(struct firebase_auth_context * auth, json_object * jrequest);
	
	int (* set_locale)(struct firebase_auth_context * auth, const char * locale);
}firebase_auth_context_t;

firebase_auth_context_t * firebase_auth_context_init(firebase_auth_context_t * auth, void * user_data);
void firebase_auth_context_cleanup(firebase_auth_context_t * auth);

#ifdef __cplusplus
}
#endif
#endif
