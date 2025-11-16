# vCIA CTF Challenge Writeup

## Challenge Information
- **Name:** vCIA
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

### Key Discovery
The server implements case-sensitive validation:
- **`flagDaw`** (exact case from JavaScript) → `Not Allowd to Click It` (blocked)
- **`FlagDaw`, `FLAGDAW`, `flagdaw`, `Flagdaw`** → `Ehh asche flag nite!! joggota hoise??` (Bengali message)

### Server Technology
- Uses **Express.js** (Node.js framework)
- Uses **Fastify** error messages (FST_ERR_CTP_INVALID_MEDIA_TYPE)
- Requires `application/json` or `text/plain;charset=UTF-8` Content-Type

### Bengali Message Analysis
The message "Ehh asche flag nite!! joggota hoise??" roughly translates to:
- "Hey, the flag is coming! What happened??"

This suggests the flag should be returned but something is preventing it.

## Attempted Approaches

1. **Direct POST requests** - Blocked with "Not Allowd to Click It"
2. **Browser automation (Puppeteer)** - Still blocked even with real browser clicks
3. **Header manipulation** - Tried various headers (Referer, Origin, User-Agent, etc.)
4. **Content-Type variations** - Tested `application/json` and `text/plain;charset=UTF-8`
5. **Key name variations** - Only exact `flagDaw` is blocked, others return Bengali message
6. **Request interception** - Confirmed browser sends `text/plain;charset=UTF-8` by default

## Current Status

The challenge appears to have server-side validation that:
1. Specifically blocks requests with the exact key `flagDaw` (case-sensitive)
2. Returns a Bengali hint message for other key variations
3. Even blocks legitimate browser requests from Puppeteer

## Possible Solutions (To Investigate)

1. **Server-side validation bypass** - There may be a specific header or request pattern that bypasses the check
2. **Hidden endpoint** - The flag might be accessible through a different endpoint
3. **Client-side manipulation** - Modifying the JavaScript before execution
4. **Session/Cookie requirement** - The server might require a specific session state
5. **Timing-based validation** - The server might check request timing or sequence

## Files Created

- `index.html` - Saved website source
- `test.html` - Test HTML file
- `solve.js` - Puppeteer automation script
- Various test scripts for different approaches

## Next Steps

1. Investigate if the Bengali message contains encoded data
2. Check for hidden endpoints or alternative paths
3. Analyze server response headers for clues
4. Try different request sequences or timing
5. Check if there's a way to bypass the `flagDaw` validation

---

**Note:** This challenge is still being investigated. The server's validation mechanism appears to be specifically designed to block the expected request pattern, requiring a creative bypass technique.

