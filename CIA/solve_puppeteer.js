const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  
  // Monitor all responses
  page.on('response', async response => {
    if (response.url().includes('6969') && response.request().method() === 'POST') {
      const text = await response.text();
      console.log('POST Response Status:', response.status());
      console.log('POST Response Body:', text);
      if (text.includes('CS{')) {
        console.log('*** FLAG FOUND IN RESPONSE ***');
      }
    }
  });
  
  page.on('dialog', async dialog => {
    const message = dialog.message();
    console.log('ALERT DIALOG:', message);
    if (message.includes('CS{')) {
      console.log('*** FLAG FOUND IN ALERT ***');
    }
    await dialog.accept();
  });
  
  try {
    await page.goto('http://49.213.52.6:6969/');
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Click the button - this should trigger the original code
    console.log('Clicking button...');
    await page.click('#button');
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 5000));
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

