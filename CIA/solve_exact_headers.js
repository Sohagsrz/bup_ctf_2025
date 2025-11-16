const http = require('http');

const url = new URL('http://49.213.52.6:6969/');
const postData = JSON.stringify({ flagDaw: true });

// Use the exact headers that the browser sends
const options = {
  hostname: url.hostname,
  port: url.port,
  path: url.pathname,
  method: 'POST',
  headers: {
    'Content-Type': 'text/plain;charset=UTF-8',
    'Content-Length': Buffer.byteLength(postData),
    'Referer': 'http://49.213.52.6:6969/',
    'Origin': 'http://49.213.52.6:6969',
    'Accept': '*/*',
    'Accept-Language': 'en-GB,en;q=0.9',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
  }
};

const req = http.request(options, (res) => {
  console.log(`Status Code: ${res.statusCode}`);
  console.log(`Headers:`, res.headers);
  
  let data = '';
  res.on('data', (chunk) => {
    data += chunk;
  });
  
  res.on('end', () => {
    console.log('\nResponse:', data);
    if (data.includes('CS{')) {
      console.log('\n*** FLAG FOUND ***');
    }
  });
});

req.on('error', (e) => {
  console.error(`Problem with request: ${e.message}`);
});

req.write(postData);
req.end();

