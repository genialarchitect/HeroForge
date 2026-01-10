#!/usr/bin/env node
/**
 * HeroForge Screenshot Service
 *
 * Captures screenshots of web pages using Playwright for security assessment reports.
 *
 * Usage:
 *   node screenshot-service.js <url> <output_path> [options]
 *
 * Options:
 *   --full-page       Capture full scrollable page
 *   --width=<n>       Viewport width (default: 1920)
 *   --height=<n>      Viewport height (default: 1080)
 *   --timeout=<ms>    Navigation timeout (default: 30000)
 *   --wait=<ms>       Wait after load before screenshot (default: 1000)
 *   --selector=<sel>  Screenshot specific element only
 *   --format=<fmt>    Output format: png or jpeg (default: png)
 *   --quality=<n>     JPEG quality 0-100 (default: 80)
 *   --dark-mode       Enable dark color scheme
 *   --mobile          Use mobile viewport (375x812)
 *   --auth=<token>    Add Authorization header with Bearer token
 *   --cookie=<data>   Add cookies (JSON format)
 *   --user-agent=<ua> Custom user agent string
 *   --ignore-ssl      Ignore SSL certificate errors
 *   --json            Output result as JSON
 *
 * Examples:
 *   node screenshot-service.js https://example.com ./screenshot.png
 *   node screenshot-service.js https://example.com ./full.png --full-page
 *   node screenshot-service.js https://example.com ./mobile.png --mobile
 */

const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

// Parse command line arguments
function parseArgs() {
    const args = process.argv.slice(2);
    const options = {
        url: null,
        outputPath: null,
        fullPage: false,
        width: 1920,
        height: 1080,
        timeout: 30000,
        wait: 1000,
        selector: null,
        format: 'png',
        quality: 80,
        darkMode: false,
        mobile: false,
        auth: null,
        cookies: null,
        userAgent: null,
        ignoreSsl: false,
        json: false,
    };

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];

        if (arg.startsWith('--')) {
            const [key, value] = arg.slice(2).split('=');

            switch (key) {
                case 'full-page':
                    options.fullPage = true;
                    break;
                case 'width':
                    options.width = parseInt(value, 10);
                    break;
                case 'height':
                    options.height = parseInt(value, 10);
                    break;
                case 'timeout':
                    options.timeout = parseInt(value, 10);
                    break;
                case 'wait':
                    options.wait = parseInt(value, 10);
                    break;
                case 'selector':
                    options.selector = value;
                    break;
                case 'format':
                    options.format = value;
                    break;
                case 'quality':
                    options.quality = parseInt(value, 10);
                    break;
                case 'dark-mode':
                    options.darkMode = true;
                    break;
                case 'mobile':
                    options.mobile = true;
                    options.width = 375;
                    options.height = 812;
                    break;
                case 'auth':
                    options.auth = value;
                    break;
                case 'cookie':
                    options.cookies = value;
                    break;
                case 'user-agent':
                    options.userAgent = value;
                    break;
                case 'ignore-ssl':
                    options.ignoreSsl = true;
                    break;
                case 'json':
                    options.json = true;
                    break;
            }
        } else if (!options.url) {
            options.url = arg;
        } else if (!options.outputPath) {
            options.outputPath = arg;
        }
    }

    return options;
}

// Output result
function output(options, success, data) {
    if (options.json) {
        console.log(JSON.stringify({
            success,
            ...data,
            timestamp: new Date().toISOString(),
        }));
    } else if (success) {
        console.log(`Screenshot saved: ${data.path}`);
        console.log(`Size: ${data.width}x${data.height}`);
        console.log(`File size: ${data.fileSize} bytes`);
    } else {
        console.error(`Error: ${data.error}`);
    }
}

// Main screenshot function
async function captureScreenshot(options) {
    const startTime = Date.now();
    let browser = null;

    try {
        // Validate inputs
        if (!options.url) {
            throw new Error('URL is required');
        }
        if (!options.outputPath) {
            throw new Error('Output path is required');
        }

        // Ensure output directory exists
        const outputDir = path.dirname(options.outputPath);
        if (outputDir && !fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        // Launch browser
        browser = await chromium.launch({
            headless: true,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
            ],
        });

        // Create context with options
        const contextOptions = {
            viewport: {
                width: options.width,
                height: options.height,
            },
            ignoreHTTPSErrors: options.ignoreSsl,
            colorScheme: options.darkMode ? 'dark' : 'light',
            deviceScaleFactor: 1,
        };

        if (options.userAgent) {
            contextOptions.userAgent = options.userAgent;
        }

        if (options.mobile) {
            contextOptions.isMobile = true;
            contextOptions.hasTouch = true;
        }

        const context = await browser.newContext(contextOptions);

        // Add cookies if provided
        if (options.cookies) {
            try {
                const cookies = JSON.parse(options.cookies);
                await context.addCookies(Array.isArray(cookies) ? cookies : [cookies]);
            } catch (e) {
                console.warn('Warning: Failed to parse cookies:', e.message);
            }
        }

        // Create page
        const page = await context.newPage();

        // Add auth header if provided
        if (options.auth) {
            await page.setExtraHTTPHeaders({
                'Authorization': `Bearer ${options.auth}`,
            });
        }

        // Navigate to URL
        await page.goto(options.url, {
            waitUntil: 'networkidle',
            timeout: options.timeout,
        });

        // Wait additional time if specified
        if (options.wait > 0) {
            await page.waitForTimeout(options.wait);
        }

        // Capture screenshot
        const screenshotOptions = {
            path: options.outputPath,
            fullPage: options.fullPage,
            type: options.format,
        };

        if (options.format === 'jpeg') {
            screenshotOptions.quality = options.quality;
        }

        let screenshot;
        if (options.selector) {
            const element = await page.$(options.selector);
            if (!element) {
                throw new Error(`Element not found: ${options.selector}`);
            }
            screenshot = await element.screenshot(screenshotOptions);
        } else {
            screenshot = await page.screenshot(screenshotOptions);
        }

        // Get page info
        const title = await page.title();
        const viewport = page.viewportSize();

        // Get file stats
        const stats = fs.statSync(options.outputPath);

        await browser.close();

        const duration = Date.now() - startTime;

        output(options, true, {
            path: options.outputPath,
            url: options.url,
            title,
            width: viewport.width,
            height: viewport.height,
            fullPage: options.fullPage,
            fileSize: stats.size,
            format: options.format,
            duration,
        });

        return true;

    } catch (error) {
        if (browser) {
            await browser.close();
        }

        output(options, false, {
            error: error.message,
            url: options.url,
            outputPath: options.outputPath,
        });

        return false;
    }
}

// Batch screenshot mode (reads URLs from stdin as JSON)
async function batchMode() {
    let input = '';

    process.stdin.setEncoding('utf8');

    for await (const chunk of process.stdin) {
        input += chunk;
    }

    try {
        const jobs = JSON.parse(input);
        const results = [];

        for (const job of jobs) {
            const options = {
                url: job.url,
                outputPath: job.output,
                fullPage: job.fullPage || false,
                width: job.width || 1920,
                height: job.height || 1080,
                timeout: job.timeout || 30000,
                wait: job.wait || 1000,
                selector: job.selector || null,
                format: job.format || 'png',
                quality: job.quality || 80,
                darkMode: job.darkMode || false,
                mobile: job.mobile || false,
                auth: job.auth || null,
                cookies: job.cookies ? JSON.stringify(job.cookies) : null,
                userAgent: job.userAgent || null,
                ignoreSsl: job.ignoreSsl || false,
                json: true,
            };

            const success = await captureScreenshot(options);
            results.push({
                url: job.url,
                output: job.output,
                success,
            });
        }

        console.log(JSON.stringify({ batch: true, results }));

    } catch (error) {
        console.log(JSON.stringify({
            batch: true,
            error: error.message,
            results: [],
        }));
    }
}

// Entry point
async function main() {
    const options = parseArgs();

    // Check for batch mode (piped input)
    if (!process.stdin.isTTY && !options.url) {
        await batchMode();
    } else {
        const success = await captureScreenshot(options);
        process.exit(success ? 0 : 1);
    }
}

main().catch(error => {
    console.error('Fatal error:', error.message);
    process.exit(1);
});
