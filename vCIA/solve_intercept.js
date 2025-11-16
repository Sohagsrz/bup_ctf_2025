const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  
  // Intercept requests to see what's being sent
  await page.setRequestInterception(true);
  
  page.on('request', request => {
    if (request.method() === 'POST' && request.url().includes('6969')) {
      console.log('POST Request intercepted:');
      console.log('URL:', request.url());
      console.log('Headers:', request.headers());
      console.log('Post Data:', request.postData());
    }
    request.continue();
  });
  
  page.on('response', response => {
    if (response.url().includes('6969') && response.request().method() === 'POST') {
      console.log('POST Response:');
      console.log('Status:', response.status());
      console.log('Headers:', response.headers());
      response.text().then(text => {
        console.log('Body:', text);
      });
    }
  });
  
  try {
    await page.goto('http://49.213.52.6:6969/');
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Click the button
    await page.click('#button');
    await new Promise(resolve => setTimeout(resolve, 3000));
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

