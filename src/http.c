/*
 * A partial implementation of HTTP/1.0
 *
 * This code is mainly intended as a replacement for the book's 'tiny.c' server
 * It provides a *partial* implementation of HTTP/1.0 which can form a basis for
 * the assignment.
 *
 * @author G. Back for CS 3214 Spring 2018
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <jansson.h>
#include <dirent.h>

#include "http.h"
#include "hexdump.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"

// Need macros here because of the sizeof
#define CRLF "\r\n"
#define CR "\r"
#define STARTS_WITH(field_name, header) \
    (!strncasecmp(field_name, header, sizeof(header) - 1))

static const char *NEVER_EMBED_A_SECRET_IN_CODE = "supa secret"; //??

static void
print_details(char *fmt, ...)
{
    if (silent_mode)
        return;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}
/* Parse HTTP request line, setting req_method, req_path, and req_version. */
static bool
http_parse_request(struct http_transaction *ta)
{
    size_t req_offset;
    ssize_t len = bufio_readline(ta->client->bufio, &req_offset);
    if (len < 2) // error, EOF, or less than 2 characters
        return false;

    char *request = bufio_offset2ptr(ta->client->bufio, req_offset);
    request[len - 2] = '\0'; // replace LF with 0 to ensure zero-termination
    char *endptr;
    char *method = strtok_r(request, " ", &endptr);
    if (method == NULL)
        return false;

    if (!strcmp(method, "GET"))
        ta->req_method = HTTP_GET;
    else if (!strcmp(method, "POST"))
        ta->req_method = HTTP_POST;
    else
        ta->req_method = HTTP_UNKNOWN;

    char *req_path = strtok_r(NULL, " ", &endptr);
    if (req_path == NULL)
        return false;

    ta->req_path = bufio_ptr2offset(ta->client->bufio, req_path);

    char *http_version = strtok_r(NULL, CR, &endptr);
    if (http_version == NULL) // would be HTTP 0.9
        return false;

    // record client's HTTP version in request
    if (!strcmp(http_version, "HTTP/1.1"))
        ta->req_version = HTTP_1_1;
    else if (!strcmp(http_version, "HTTP/1.0"))
        ta->req_version = HTTP_1_0;
    else
        return false;

    // printf("\nGOT HERE1\n\n");
    return true;
}

/* Process HTTP headers. */
static bool
http_process_headers(struct http_transaction *ta)
{
    for (;;)
    {
        size_t header_offset;
        ssize_t len = bufio_readline(ta->client->bufio, &header_offset);
        if (len <= 0)
            return false;

        char *header = bufio_offset2ptr(ta->client->bufio, header_offset);
        if (len == 2 && STARTS_WITH(header, CRLF)) // empty CRLF
            return true;

        header[len - 2] = '\0';
        /* Each header field consists of a name followed by a
         * colon (":") and the field value. Field names are
         * case-insensitive. The field value MAY be preceded by
         * any amount of LWS, though a single SP is preferred.
         */
        char *endptr;
        char *field_name = strtok_r(header, ":", &endptr);
        if (field_name == NULL)
            return false;

        // skip white space
        char *field_value = endptr;
        while (*field_value == ' ' || *field_value == '\t')
            field_value++;

        // you may print the header like so
        // printf("Header: %s: %s\n", field_name, field_value);
        if (!strcasecmp(field_name, "Content-Length"))
        {
            ta->req_content_len = atoi(field_value);
        }

        /* Handle other headers here. Both field_value and field_name
         * are zero-terminated strings.
         */
        else if (!strcasecmp(field_name, "Cookie"))
        {
            // ta->req_auth_token = field_value; //300 bytes
            char *rest = field_value;
            char *token = NULL;
            // printf("%s\n", field_value);
            while ((token = strtok_r(rest, "=", &rest)))
            {

                if (strcasecmp("auth_token", token) != 0 && strcasecmp(" auth_token", token) != 0)
                {
                    token = strtok_r(rest, "; ", &rest);

                    continue;
                }
                
                token = strtok_r(rest, "; ", &rest);
                if(token == NULL) break;
                ta->req_auth_token = strdup(token);
                break;
            }
        }
        else if (!strcasecmp(field_name, "Range"))
        {
            int lower = -1;
            int higher = -1;
            // char *token;
            // int size = 9125406 + 1000;

            sscanf(field_value, "bytes=%d-%d", &lower, &higher);

            // if (lower < -1)
            // {
            //     higher = size - 1;
            //     lower = size + lower;
            // }
            // else if (higher == -1)
            // {
            //     higher = size - 1;
            // }
            ta->rangeRequest = true;
            ta->lower = lower;
            ta->higher = higher;
        }
    }
}

const int MAX_HEADER_LEN = 2048;

/* add a formatted header to the response buffer. */
void http_add_header(buffer_t *resp, char *key, char *fmt, ...)
{
    va_list ap;

    buffer_appends(resp, key);
    buffer_appends(resp, ": ");

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(resp, MAX_HEADER_LEN);
    int len = vsnprintf(error, MAX_HEADER_LEN, fmt, ap);
    resp->len += len > MAX_HEADER_LEN ? MAX_HEADER_LEN - 1 : len;
    va_end(ap);

    buffer_appends(resp, "\r\n");
}

/* add a content-length header. */
static void
add_content_length(buffer_t *res, size_t len)
{
    http_add_header(res, "Content-Length", "%ld", len);
}

/* start the response by writing the first line of the response
 * to the response buffer.  Used in send_response_header */
static void
start_response(struct http_transaction *ta, buffer_t *res)
{
    if (ta->req_version == HTTP_1_0)
        buffer_appends(res, "HTTP/1.0 ");
    else
        buffer_appends(res, "HTTP/1.1 ");

    switch (ta->resp_status)
    {
    case HTTP_OK:
        buffer_appends(res, "200 OK");
        break;
    case HTTP_PARTIAL_CONTENT:
        buffer_appends(res, "206 Partial Content");
        break;
    case HTTP_BAD_REQUEST:
        buffer_appends(res, "400 Bad Request");
        break;
    case HTTP_PERMISSION_DENIED:
        buffer_appends(res, "403 Permission Denied");
        break;
    case HTTP_NOT_FOUND:
        buffer_appends(res, "404 Not Found");
        break;
    case HTTP_METHOD_NOT_ALLOWED:
        buffer_appends(res, "405 Method Not Allowed");
        break;
    case HTTP_REQUEST_TIMEOUT:
        buffer_appends(res, "408 Request Timeout");
        break;
    case HTTP_REQUEST_TOO_LONG:
        buffer_appends(res, "414 Request Too Long");
        break;
    case HTTP_NOT_IMPLEMENTED:
        buffer_appends(res, "501 Not Implemented");
        break;
    case HTTP_SERVICE_UNAVAILABLE:
        buffer_appends(res, "503 Service Unavailable");
        break;
    case HTTP_INTERNAL_ERROR:
    default:
        buffer_appends(res, "500 Internal Server Error");
        break;
    }
    buffer_appends(res, CRLF);
}

/* Send response headers to client */
static bool
send_response_header(struct http_transaction *ta)
{
    buffer_t response;
    buffer_init(&response, 80);

    start_response(ta, &response);
    if (bufio_sendbuffer(ta->client->bufio, &response) == -1)
        return false;

    buffer_appends(&ta->resp_headers, CRLF);
    if (bufio_sendbuffer(ta->client->bufio, &ta->resp_headers) == -1)
        return false;

    buffer_delete(&response);
    return true;
}

/* Send a full response to client with the content in resp_body. */
static bool
send_response(struct http_transaction *ta)
{
    // add content-length.  All other headers must have already been set.
    add_content_length(&ta->resp_headers, ta->resp_body.len);

    if (!send_response_header(ta))
        return false;

    return bufio_sendbuffer(ta->client->bufio, &ta->resp_body) != -1;
}

const int MAX_ERROR_LEN = 2048;

/* Send an error response. */
static bool
send_error(struct http_transaction *ta, enum http_response_status status, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(&ta->resp_body, MAX_ERROR_LEN);
    int len = vsnprintf(error, MAX_ERROR_LEN, fmt, ap);
    ta->resp_body.len += len > MAX_ERROR_LEN ? MAX_ERROR_LEN - 1 : len;
    va_end(ap);
    ta->resp_status = status;
    http_add_header(&ta->resp_headers, "Content-Type", "text/plain");
    return send_response(ta);
}

/* Send Not Found response. */
static bool
send_not_found(struct http_transaction *ta)
{
    return send_error(ta, HTTP_NOT_FOUND, "File %s not found",
                      bufio_offset2ptr(ta->client->bufio, ta->req_path));
}

/* A start at assigning an appropriate mime type.  Real-world
 * servers use more extensive lists such as /etc/mime.types
 */
static const char *
guess_mime_type(char *filename)
{
    char *suffix = strrchr(filename, '.');
    if (suffix == NULL)
        return "text/plain";

    if (!strcasecmp(suffix, ".html"))
        return "text/html";

    if (!strcasecmp(suffix, ".gif"))
        return "image/gif";

    if (!strcasecmp(suffix, ".png"))
        return "image/png";

    if (!strcasecmp(suffix, ".jpg"))
        return "image/jpeg";

    if (!strcasecmp(suffix, ".js"))
        return "text/javascript";

    if (!strcasecmp(suffix, ".svg"))
        return "image/svg+xml";

    if (!strcasecmp(suffix, ".mp4"))
        return "video/mp4";
    
    if (!strcasecmp(suffix, ".css"))
        return "text/css";

    return "text/plain";
}

/* Handle HTTP transaction for static files. */
static bool
handle_static_asset(struct http_transaction *ta, char *basedir)
{
    char fname[PATH_MAX];

    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    // The code below is vulnerable to an attack.  Can you see
    // which?  Fix it to avoid indirect object reference (IDOR) attacks.
    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);

    http_add_header(&ta->resp_headers, "Accept-Ranges", "bytes");

    // if ()

    if (access(fname, R_OK))
    {
        // printf("in access denied\n");
        if (errno == EACCES)
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        else if (html5_fallback)
        {
            snprintf(fname, sizeof fname, "%s%s", basedir, "/index.html");
        }
        else
            return send_not_found(ta);
    }

    if (!(strcmp(req_path, "/")))
    {
        snprintf(fname, sizeof fname, "%s%s", basedir, "/index.html");
    }

    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    if (rc == -1)
    {
        // printf("failed at rc == -1\n");
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");
    }

    int filefd = open(fname, O_RDONLY);
    if (filefd == -1)
    {
        return send_not_found(ta);
    }

    ta->resp_status = HTTP_OK;
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));
    off_t from = 0, to = st.st_size - 1;

    if (ta->rangeRequest)
    {

        // printf("GOT HERE2\n");
        if (ta->lower < -1)
        {
            ta->higher = st.st_size - 1;
            ta->lower = st.st_size + ta->lower;
        }
        else if (ta->higher == -1)
        {
            ta->higher = st.st_size - 1;
        }
        from = ta->lower;
        to = ta->higher;
        //..
        ta->resp_status = HTTP_PARTIAL_CONTENT;
        http_add_header(&ta->resp_headers, "Content-Range", "bytes %d-%d/%d", from, to, st.st_size); //-1
    }
    off_t content_length = to + 1 - from;
    add_content_length(&ta->resp_headers, content_length);

    bool success = send_response_header(ta);
    if (!success)
        goto out;

    // sendfile may send fewer bytes than requested, hence the loop
    while (success && from <= to)
        success = bufio_sendfile(ta->client->bufio, filefd, &from, to + 1 - from) > 0;

out:
    close(filefd);
    // printf("exiting\n");
    return success;
}

static char *create_jwt(const char *username, char **token_json)
{
    jwt_t *token;
    int rc = jwt_new(&token);
    if (rc)
    {
        return NULL;
    }

    rc = jwt_add_grant(token, "sub", username);
    if (rc)
    {
        jwt_free(token);
        return NULL;
    }
    time_t now = time(NULL);
    rc = jwt_add_grant_int(token, "iat", now);
    if (rc)
    {
        jwt_free(token);
        return NULL;
    }

    rc = jwt_add_grant_int(token, "exp", now + token_expiration_time);
    if (rc)
    {
        jwt_free(token);
        return NULL;
    }

    rc = jwt_set_alg(token, JWT_ALG_HS256,
                     (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE,
                     strlen(NEVER_EMBED_A_SECRET_IN_CODE));
    if (rc)
    {
        jwt_free(token);
        return NULL;
    }

    // printf("dump:\n");
    // rc = jwt_dump_fp(token, stdout, 1);
    // if (rc)
    // {
    //     jwt_free(token);
    //     return NULL;
    // }
    char *temp = jwt_get_grants_json(token, NULL); // gets the token as a json string
    *token_json = temp;
    char *token_buf = jwt_encode_str(token);
    if (token_buf == NULL)
    {
        jwt_free(token);
        return NULL;
    }
    jwt_free(token);
    return token_buf;
}
static bool
verify_token(jwt_t **ymtoken, struct http_transaction *ta, bool send)
{
    int rc = jwt_decode(ymtoken, ta->req_auth_token,
                        (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE,
                        strlen(NEVER_EMBED_A_SECRET_IN_CODE));
    free(ta->req_auth_token);
    if (rc)
    {
        print_details("\tFAL::%s::token decoding failed.\n", __FUNCTION__);

        if (send)
            send_error(ta, HTTP_PERMISSION_DENIED, "Caught you lacking");
        return false;
    }

    long exp = jwt_get_grant_int(*ymtoken, "exp");
    const char *user = jwt_get_grant(*ymtoken, "sub");
    if (exp == 0 || user == NULL)
    {
        print_details("\tERR::%s:: Extraction of exp or sub from decoded token failed\n", __FUNCTION__);
        if (send)
            send_error(ta, HTTP_PERMISSION_DENIED, "Caught you lacking");
        return false;
    }
    print_details("\tINFO::%s:: exp:%ld, sub: %s \n", __FUNCTION__, exp, user);

    time_t now = time(NULL);
    if (exp <= now)
    {

        print_details("\tFAL::%s:: Token expired\n", __FUNCTION__);
        if (send)
            send_error(ta, HTTP_PERMISSION_DENIED, "Token Expired");
        return false;
    }
    if (strcmp("user0", user))
    {
        print_details("\tFAL::%s:: unidentified User\n", __FUNCTION__);
        if (send)
            send_error(ta, HTTP_PERMISSION_DENIED, "Invalid User");
        return false;
    }

    return true;
}
static bool
handle_api(struct http_transaction *ta)
{
    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    if (strcmp(req_path, "/api/login") == 0)
    {

        if (ta->req_method == HTTP_GET)
        {
            print_details("REQ::%s::GET request for login\n", __FUNCTION__);
            if (!ta->req_auth_token)
            {
                print_details("\tINFO::%s::no token provided\n", __FUNCTION__);
                http_add_header(&ta->resp_headers, "Content-Type", "application/json");
                buffer_appends(&ta->resp_body, "{}");
                ta->resp_status = HTTP_OK;
                return send_response(ta);
            }
            jwt_t *ymtoken = NULL;
            bool rc = verify_token(&ymtoken, ta, false);
            char *token_json = jwt_get_grants_json(ymtoken, NULL);
            print_details("\tINFO::%s::token:%s\n", __FUNCTION__, token_json);
            if (!rc)
            {
                print_details("\tINFO::%s::token unverified\n", __FUNCTION__);
                http_add_header(&ta->resp_headers, "Content-Type", "application/json");
                buffer_appends(&ta->resp_body, "{}");
                ta->resp_status = HTTP_OK;
                return send_response(ta);
            }
            print_details("\tINFO::%s::token verified\n", __FUNCTION__);
            http_add_header(&ta->resp_headers, "Content-Type", "application/json");
            buffer_appends(&ta->resp_body, token_json);
            ta->resp_status = HTTP_OK;
            jwt_free(ymtoken);
            jwt_free_str(token_json);
            return send_response(ta);
        }
        else if (ta->req_method == HTTP_POST)
        {
            print_details("REQ::%s::POST request for login\n", __FUNCTION__);
            char *body = NULL;
            body = bufio_offset2ptr(ta->client->bufio, ta->req_body); // body of the post request

            json_t *root;
            json_error_t error;

            root = json_loadb(body, ta->req_content_len, 0, &error); // decodes json string to json object
            if (!root || !json_is_object(root))
            {
                print_details("\tERR::%s::Incorrect json formatting %s\n", __FUNCTION__, body);
                json_decref(root);
                return send_error(ta, HTTP_BAD_REQUEST, "Get your request in order man1"); // fails here for incorrect object keys not in man2?
            }
            // bufio_truncate(ta->client->bufio);
            json_t *username = json_object_get(root, "username");
            json_t *password = json_object_get(root, "password");
            // check that both username and password inputs exists
            if (!username || !password)
            {
                json_decref(root);
                print_details("ERR::%s::incorrect json format", __FUNCTION__);
                return send_error(ta, HTTP_BAD_REQUEST, "Get your request in order man2");
            }
            // check username and passwrod are correct
            if (strcmp(json_string_value(username), "user0") != 0 || strcmp(json_string_value(password), "thepassword") != 0)
            {
                print_details("FAL::%s::Incorrect username or password\n", __FUNCTION__);
                json_decref(root);
                return send_error(ta, HTTP_PERMISSION_DENIED, "you messed up your username or password :P"); // MIGHT NEED TO CHENGE TO 401?
            }
            print_details("INFO::%s::username: %s, password: %s\n", __FUNCTION__, json_string_value(username), json_string_value(password));
            char *token_json = NULL;
            char *token_buf = create_jwt(json_string_value(username), &token_json);
            if (token_buf == NULL || token_json == NULL)
            {
                print_details("ERR::%s::Token creation error\n", __FUNCTION__);
                jwt_free_str(token_buf);
                jwt_free_str(token_json);
                json_decref(root); // delete json object
                return send_error(ta, HTTP_INTERNAL_ERROR, "My bad I messed up :(");
            }

            print_details("INFO::%s::setting cookie %s\n", __FUNCTION__, token_buf);
            json_decref(root); // delete json object
            http_add_header(&ta->resp_headers, "Set-Cookie", "auth_token=%s%s", token_buf, "; Path=/");
            http_add_header(&ta->resp_headers, "Content-Type", "application/json");
            buffer_appends(&ta->resp_body, token_json);
            jwt_free_str(token_buf); // free buffer holding jwt
            jwt_free_str(token_json);

            // add_content_length(&ta->resp_headers, strlen(token_json));
            ta->resp_status = HTTP_OK;
            return send_response(ta);
        }
        else
        {
            return send_error(ta, HTTP_NOT_IMPLEMENTED, "API not implemented");
        }
    }
    else if (STARTS_WITH(req_path, "/api/video"))
    {
        // loop through the server_root and check for each file
        DIR *dir = opendir(server_root);
        // iterate
        struct dirent *file;
        json_t *jsonArray = json_array();
        while ((file = readdir(dir)))
        {
            if (strcmp(guess_mime_type(file->d_name), "video/mp4") == 0)
            {
                // add into the json array
                json_t *obj = json_object();
                char jsonName[PATH_MAX];
                size_t jsonSize = sizeof(jsonName);
                snprintf(jsonName, jsonSize, "%s/%s", server_root, file->d_name);
                struct stat jasonStat;
                stat(jsonName, &jasonStat);
                json_object_set_new(obj, "size", json_integer(jasonStat.st_size));
                json_object_set_new(obj, "name", json_string(file->d_name));
                json_array_append(jsonArray, obj);
            }
        }
        char *dump = json_dumps(jsonArray, JSON_INDENT(5));
        buffer_appends(&ta->resp_body, dump);
        http_add_header(&ta->resp_headers, "Content-Type", "application/json");

        ta->resp_status = HTTP_OK;
        return send_response(ta);
    }
    return send_error(ta, HTTP_NOT_FOUND, "API not implemented");
}

static bool
handle_private(struct http_transaction *ta)
{
    print_details("REQ::%s::GET request for private file\n", __FUNCTION__);
    bool rc;
    if (ta->req_auth_token == NULL)
    {

        print_details("\tFAL::%s::auth token key != \"auth_token\"\n", __FUNCTION__);
        send_error(ta, HTTP_PERMISSION_DENIED, "Caught you lacking");
        return false;
    }
    print_details("\tINF::%s:: auth_token= %s\n", __FUNCTION__, ta->req_auth_token);
    jwt_t *ymtoken = NULL;
    rc = verify_token(&ymtoken, ta, true);
    free(ymtoken);
    return rc;
}

/* Set up an http client, associating it with a bufio buffer. */
void http_setup_client(struct http_client *self, struct bufio *bufio)
{
    self->bufio = bufio;
}

/* Handle a single HTTP transaction.  Returns true on success. */
bool http_handle_transaction(struct http_client *self)
{
    struct http_transaction ta;
    memset(&ta, 0, sizeof ta);
    ta.client = self;

    if (!http_parse_request(&ta))
    {
        // printf("GOT HERE");
        return false;
    }

    if (!http_process_headers(&ta))
    {
        return false;
    }

    if (ta.req_content_len > 0)
    {
        int rc = bufio_read(self->bufio, ta.req_content_len, &ta.req_body);
        if (rc != ta.req_content_len)
            return false;

        // To see the body, use this:
        // char *body = bufio_offset2ptr(ta.client->bufio, ta.req_body);
        // hexdump(body, ta.req_content_len);
    }

    buffer_init(&ta.resp_headers, 1024);
    http_add_header(&ta.resp_headers, "Server", "CS3214-Personal-Server");
    buffer_init(&ta.resp_body, 0);

    bool rc = false;
    char *req_path = bufio_offset2ptr(ta.client->bufio, ta.req_path);

    // avoids the dot dot attack
    if (STARTS_WITH(req_path, ".."))
    {
        return send_error(&ta, HTTP_NOT_FOUND, "Dot-dot violation");
    }

    if (STARTS_WITH(req_path, "/api"))
    {
        rc = handle_api(&ta);
    }
    else if (STARTS_WITH(req_path, "/private"))
    {
        /* not implemented */
        rc = handle_private(&ta);
        if (rc)
        {
            handle_static_asset(&ta, server_root);
        }
    }
    else
    {
        char *temp = strstr(req_path, "/private");
        if (temp)
        {
            send_error(&ta, HTTP_NOT_FOUND, "File not found"); //? ask about this test case: test_access_control_private_path
            rc = false;
        }
        else
            rc = handle_static_asset(&ta, server_root);
    }

    // bufio_truncate(ta.client->bufio);
    buffer_delete(&ta.resp_headers);
    buffer_delete(&ta.resp_body);
    return ta.req_version == HTTP_1_1 ? rc : false;
}
