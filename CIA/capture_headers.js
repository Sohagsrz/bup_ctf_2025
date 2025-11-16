const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  
  // Capture the exact request that gets sent
  await page.setRequestInterception(true);
  page.on('request', request => {
    if (request.method() === 'POST') {
      console.log('\n=== CAPTURED POST REQUEST ===');
      console.log('URL:', request.url());
      console.log('Method:', request.method());
      console.log('Headers:', JSON.stringify(request.headers(), null, 2));
      console.log('Post Data:', request.postData());
      request.continue();
    } else {
      request.continue();
    }
  });
  
  page.on('response', async response => {
    if (response.url().includes('6969') && response.request().method() === 'POST') {
      const text = await response.text();
      console.log('\n=== RESPONSE ===');
      console.log('Status:', response.status());
      console.log('Response:', text);
      if (text.includes('CS{')) {
        console.log('\n*** FLAG FOUND ***');
      }
    }
  });
  
  page.on('dialog', async dialog => {
    const message = dialog.message();
    console.log('\n=== ALERT ===');
    console.log(message);
    if (message.includes('CS{')) {
      console.log('\n*** FLAG FOUND ***');
    }
    await dialog.accept();
  });
  
  try {
    await page.goto('http://49.213.52.6:6969/');
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    console.log('Clicking button to capture headers...');
    await page.click('#button');
    await new Promise(resolve => setTimeout(resolve, 3000));
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

