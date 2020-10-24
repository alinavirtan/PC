#ifndef _REQUESTS_
#define _REQUESTS_

// computes and returns a GET request string (query_params
// and cookies can be set to NULL if not needed)
char *compute_get_request(const char *host, const char *url, char *query_params,
							char **cookies, int cookies_count, const char* token);

// computes and returns a POST request string (cookies can be NULL if not needed)
char *compute_post_request(const char *host, const char *url, char* content_type, 
	const char *body_data, char** cookies, int cookies_count, const char* token);

// computes and returns a DELETE request string (cookies can be NULL if not needed)
char *compute_delete_request(const char *host, const char *url, char *query_params,
                char **cookies, int cookies_count, const char* token);
#endif
