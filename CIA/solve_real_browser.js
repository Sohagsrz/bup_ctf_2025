const puppeteer = require('puppeteer');

(async () => {
  // Try with headless: false to see if that makes a difference
  const browser = await puppeteer.launch({ 
    headless: false,
    args: ['--disable-blink-features=AutomationControlled']
  });
  const page = await browser.newPage();
  
  // Remove webdriver property
  await page.evaluateOnNewDocument(() => {
    Object.defineProperty(navigator, 'webdriver', {
      get: () => undefined
    });
  });
  
  page.on('response', async response => {
    if (response.url().includes('6969') && response.request().method() === 'POST') {
      const text = await response.text();
      console.log('POST Response:', text);
      if (text.includes('CS{')) {
        console.log('\n*** FLAG FOUND ***');
        console.log('FLAG:', text);
      }
    }
  });
  
  page.on('dialog', async dialog => {
    const message = dialog.message();
    console.log('ALERT:', message);
    if (message.includes('CS{')) {
      console.log('\n*** FLAG FOUND IN ALERT ***');
      console.log('FLAG:', message);
    }
    await dialog.accept();
  });
  
  try {
    await page.goto('http://49.213.52.6:6969/', { waitUntil: 'networkidle2' });
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    console.log('Clicking button...');
    await page.click('#button');
    await new Promise(resolve => setTimeout(resolve, 5000));
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    // Keep browser open for a bit
    await new Promise(resolve => setTimeout(resolve, 3000));
    await browser.close();
  }
})();

