// basic usage
// https://pptr.dev/guides/getting-started

// writing to a file
// https://github.com/checkly/puppeteer-examples/blob/master/1.%20basics/download_upload.js

// how to find elements with puppeteer
// class starts with .
// id starts with #

// how to get __dirname
// https://stackoverflow.com/questions/8817423/why-is-dirname-not-defined-in-node-repl

import puppeteer from 'puppeteer';
import fs from 'fs';
import path from 'path';
import util from 'util';
import url from 'url';

const writeFileAsync = util.promisify(fs.writeFile);

(async () => {
  // Launch the browser and open a new blank page; timeout prevents early exit when os-san makes things slow
  const browser = await puppeteer.launch({headless: false, args: [`--window-size=1920,1080`], protocolTimeout: 1000_000});
  const page = await browser.newPage();

  // Navigate the page to a URL
  await page.goto('https://browserbench.org/Speedometer3.0/');

  // Set screen size
  await page.setViewport({width: 1920, height: 1080});

  // Wait and click on start button
  const start = '.start-tests-button';
  await page.waitForSelector(start);
  await page.click(start);
  // console.log('Here1');

  // Wait for test to finish
  const details = '.scatter-plot';
  await page.waitForSelector(details, { timeout: 600000 });
  // console.log('Here2');

  // Locate JSON result URL
  const textSelector = await page.waitForSelector('#download-full-json');
  const fullTitle = await textSelector?.evaluate(el => el.href);
  // console.log('Here3');

  // Print the full URL
  console.log('Full JSON URL "%s".', fullTitle);

  const version = await page.browser().version();
  console.log('Browser version: "%s".', version);

  // Write JSON contents to file
  const viewSource = await page.goto(fullTitle)
  const buffer = await viewSource.buffer()
  await writeFileAsync(path.join(path.dirname(url.fileURLToPath(import.meta.url)), 'speedometer_results.json'), buffer)
  // console.log('The file was saved!') 

  // To make page wait indefinitely
  // const details2 = '.whywhywhwy'; 
  // await page.waitForSelector(details2, { timeout: 600000 });

  await browser.close();
})();
