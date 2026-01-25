CREATE TABLE IF NOT EXISTS pacer_response_codes (
    http_status_code INTEGER PRIMARY KEY,
    reason_phrase TEXT NOT NULL,
    enum_name TEXT NOT NULL,
    application_usage TEXT NOT NULL,
    description TEXT NOT NULL
);

INSERT INTO pacer_response_codes (
    http_status_code,
    reason_phrase,
    enum_name,
    application_usage,
    description
) VALUES
    (
        200,
        'OK',
        'OK',
        'Successful GET, HEAD, PUT, POST',
        'The request has succeeded. For GET, the resource is returned in the body. For HEAD, headers only. For PUT or POST, the result of the action is returned.'
    ),
    (
        204,
        'No Content',
        'NO_CONTENT',
        'Successful request with no response body',
        'The server successfully processed the request and is not returning any content, but headers may be useful.'
    ),
    (
        400,
        'Bad Request',
        'BAD_REQUEST',
        'Invalid argument, running exception, stopped state',
        'The server could not understand the request due to invalid syntax or malformed input.'
    ),
    (
        401,
        'Unauthorized',
        'UNAUTHORIZED',
        'User not authenticated',
        'Authentication is required and has failed or has not yet been provided.'
    ),
    (
        404,
        'Not Found',
        'NOT_FOUND',
        'Report not found',
        'The server cannot find the requested resource. The endpoint may exist, but the resource does not.'
    ),
    (
        406,
        'Not Acceptable',
        'NOT_ACCEPTABLE',
        'Validation exception',
        'The server cannot produce a response matching the list of acceptable values defined by the client.'
    ),
    (
        429,
        'Too Many Requests',
        'TOO_MANY_REQUESTS',
        'Too many reports running',
        'The user has sent too many requests in a given amount of time, rate limiting.'
    ),
    (
        500,
        'Internal Server Error',
        'INTERNAL_SERVER_ERROR',
        'Report failed, all other exceptions',
        'The server encountered an unexpected condition that prevented it from fulfilling the request.'
    );
