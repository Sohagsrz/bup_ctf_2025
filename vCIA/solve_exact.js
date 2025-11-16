const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: false }); // Not headless to see what happens
  const page = await browser.newPage();
  
  try {
    await page.goto('http://49.213.52.6:6969/');
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Set up alert handler
    page.on('dialog', async dialog => {
      const message = dialog.message();
      console.log('ALERT MESSAGE:', message);
      if (message.includes('CS{')) {
        console.log('FLAG FOUND:', message);
      }
      await dialog.accept();
    });
    
    // Click the button
    console.log('Clicking button...');
    await page.click('#button');
    
    // Wait for alert
    await new Promise(resolve => setTimeout(resolve, 5000));
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

