// Test what headers fetch() sends by default
const http = require('http');

const url = new URL('http://49.213.52.6:6969/');
const postData = JSON.stringify({ flagDaw: true });

// When fetch() is used with JSON.stringify() without setting Content-Type,
// browsers typically send it as text/plain or don't set it
// But let's try with minimal headers that fetch might send

const options = {
  hostname: url.hostname,
  port: url.port,
  path: url.pathname,
  method: 'POST',
  headers: {
    'Content-Length': Buffer.byteLength(postData),
    // No Content-Type - let's see what happens
  }
};

const req = http.request(options, (res) => {
  let data = '';
  res.on('data', (chunk) => { data += chunk; });
  res.on('end', () => {
    console.log('Response:', data);
  });
});

req.write(postData);
req.end();

