package com.miracl.maas_sdk;

/**
 * Class containing messages strings
 */
final class MiraclMessages {
	static final String MIRACL_CLIENT_PV_PULL_ERROR_OCCURED_WHILE_EXECUTING_REQUEST = "An error occured while executing a pluggable verification pull request.";
	static final String MIRACL_CLIENT_PV_PULL_UNABLE_TO_AUTHENTICATE = "Unable to authenticate towards the pluggable verification pull endpoint.";
	static final String MIRACL_CLIENT_PV_PULL_MPIN_ID_NOT_FOUND = "MPin ID hash not been found in the pull verification request.";
	static final String MIRACL_CLIENT_PV_PULL_ACTIVATION_KEY_NOT_FOUND = "Activation key not been found in the pull verification request.";
	static final String MIRACL_CLIENT_PV_PULL_REQUEST_EXPIRED = "Pull pluggable verification request has expired.";
	static final String MIRACL_CLIENT_PV_PULL_UNABLE_TO_CREATE_POST_REQUEST = "Unable to create a pluggable verification pull POST request.";
	static final String MIRACL_CLIENT_PV_PULL_UNABLE_TO_EXECUTE_POST_REQUEST = "Unable to execute a pluggable verification pull POST request.";
	static final String NETWORK_ERROR_EXCEPTION_DESC = "Network error: %s";
	static final String USER_NOT_AUTHORIZED = "User is not authorized";
    static final String MIRACL_CLIENT_GET_SIGNING_ALGORITHM_INVALID_JWT = "Invalid JWT";
	static final String MIRACL_CLIENT_GET_SIGNING_ALGORITHM_UNABLE_TO_PARSE_JWT_HEADER = "Unable to parse JWT header";
	static final String MIRACL_CLIENT_GET_SIGNING_ALGORITHM_SIGNING_ALGORITHM_NOT_SPECIFIED_IN_JWT_HEADER = "Signing algorithm not specified in JWT header";
	static final String MIRACL_CLIENT_PV_PUSH_UNABLE_TO_EXTRACT_NEW_USER_TOKEN_FROM_REQUEST_BODY_LOG = "Unable to extract a new user token from the request body %s.";
	static final String MIRACL_CLIENT_PV_PUSH_UNABLE_TO_EXTRACT_JSON_OBJECT_FROM_REQUEST_BODY = "Unable to extract a JSON object from the request body.";
	static final String MIRACL_CLIENT_PV_PUSH_UNABLE_TO_EXTRACT_JSON_OBJECT_FROM_REQUEST_BODY_LOG = "Unable to extract a JSON object from the request body %s.";
	static final String MIRACL_CLIENT_PV_PUSH_UNABLE_TO_GET_THE_JSON_WEB_TOKEN_SIGNING_ALGORITHM_LOG = "Unable to get the JSON Web Token signing algorithm.";
	static final String MIRACL_CLIENT_PV_PUSH_UNABLE_TO_EXTRACT_NEW_USER_TOKEN_FROM_REQUEST_BODY = "Unable to extract a new user token from the request body.";
	static final String MIRACL_CLIENT_PV_PUSH_INVALID_PUSH_TOKEN_IN_THE_REQUEST_BODY_LOG = "Invalid push token in the request body: %s.";
	static final String MIRACL_CLIENT_PV_PUSH_INVALID_PUSH_TOKEN_IN_THE_REQUEST_BODY = "Invalid push token in the request body.";
	static final String MIRACL_CLIENT_PV_PUSH_EVENTS_KEY_NOT_FOUND_IN_ACTIVATION_JWT = "\"events\" key not found in activation JWT";
	static final String MIRACL_CLIENT_PV_PUSH_NEW_USER_KEY_NOT_FOUND_IN_ACTIVATION_JWT = "\"newUser\" key not found in activation JWT";
	static final String MIRACL_CLIENT_PV_ACTIVATE_UNABLE_TO_EXECUTE_ACTIVATION_POST_REQUEST_LOG = "Unable to execute a pluggable verification activation POST request.";
	static final String MIRACL_CLIENT_PV_ACTIVATE_UNABLE_TO_EXECUTE_ACTIVATION_POST_REQUEST = "An error occured while activating user.";
	static final String MIRACL_CLIENT_PV_ACTIVATE_UNABLE_TO_SET_VERIFICATION_CONTENT_TYPE_LOG = "Unable to set pluggable verification content type.";
	static final String MIRACL_CLIENT_PV_ACTIVATE_UNABLE_TO_SET_VERIFICATION_CONTENT_TYPE = "An error occured while activating user.";
	static final String MIRACL_CLIENT_PV_ACTIVATE_UNABLE_TO_CREATE_ACTIVATION_POST_REQUEST_LOG = "Unable to create a pluggable verification activation POST request.";
	static final String MIRACL_CLIENT_PV_ACTIVATE_UNABLE_TO_CREATE_ACTIVATION_POST_REQUEST = "An error occured while activating user.";
}
