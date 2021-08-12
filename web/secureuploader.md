---
grand_parent: Categories
parent: Web
title: Secure Uploader
nav_order: 7
---

# Secure Uploader

```
A new secure, safe and smooth uploader!
```

## Challenge

> TL;DR: Python's `os.path.join` will ignore all previous path components if it reads an absolute path from any intermediate component.

Looking at the source code, it appears that we are unable to use `../` in filenames to obtain path traversal during our upload since it checks for `.` in the filename.  A slight catch is that we could still upload files with filenames like `/foo`. The uploaded file is then saved to `uploads/FILE_NAME`. At the same time, the filename is stored into an SQL table `files`. 

**Source**: `app/app.py`
```py
@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return redirect('/')
    file = request.files['file']
    if "." in file.filename:
        return "Bad filename!", 403
    conn = db()
    cur = conn.cursor()
    uid = uuid.uuid4().hex
    try:
        cur.execute("insert into files (id, path) values (?, ?)", (uid, file.filename,))
    except sqlite3.IntegrityError:
        return "Duplicate file"
    conn.commit()
    file.save('uploads/' + file.filename)
    return redirect('/file/' + uid)
```

Looking at the Dockerfile, we see that the flag is stored at `/flag`. This is a big hint as it reveals that our goal is reachable without using `.`.

**Source**: `Dockerfile`
```docker
COPY app /app
COPY flag.txt /flag
WORKDIR /app
```

Okay, what about when the file is retrieved then? It appears that it obtains the `path` from the `files` table, which was inserted into previously.

**Source**: `app/app.py`
```py
@app.route('/file/<id>')
def file(id):
    conn = db()
    cur = conn.cursor()
    cur.execute("select path from files where id=?", (id,))
    res = cur.fetchone()
    if res is None:
        return "File not found", 404
    with open(os.path.join("uploads/", res[0]), "r") as f:
        return f.read()
```

Looking at how the final path for the `open()` call is obtained, we see that it uses `os.path.join()`, specifying the path `uploads/` followed by the value from the `files` table. So, it would open files from `uploads/FILE_NAME` directory... right?

What if our filename is simply just `/flag`, would the `open()` call result in opening `uploads//flag`? Well, inspecting the [docs](https://docs.python.org/3/library/os.path.html#os.path.join) for `os.path.join()` revealed the answer:

> If a component is an absolute path, **all previous components are thrown away** and joining continues from the absolute path component.

So the `uploads/` relative path will be ignored since we are specifying an absolute path `/flag`, resulting in the final path being `/flag`.

<img src="images/secureuploader-01.jpg">

Following the redirect gives us the flag:

<img src="images/secureuploader-02.jpg">

Flag: `rarctf{4lw4y5_r34d_th3_d0c5_pr0p3rly!-71ed16}`
