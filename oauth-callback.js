// api/oauth-callback.js (for Vercel deployment)
// This handles the OAuth callback and completes the installation

import crypto from 'crypto';

export default async function handler(req, res) {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }
    
    try {
        const { code, shop, hmac, state } = req.query;
        
        // Your app credentials (set these in Vercel environment variables)
        const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
        const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
        
        // Verify HMAC
        const message = Object.keys(req.query)
            .filter(key => key !== 'signature' && key !== 'hmac')
            .sort()
            .map(key => `${key}=${req.query[key]}`)
            .join('&');
        
        const calculatedHmac = crypto
            .createHmac('sha256', CLIENT_SECRET)
            .update(message)
            .digest('hex');
        
        const isValid = crypto.timingSafeEqual(
            Buffer.from(hmac, 'hex'),
            Buffer.from(calculatedHmac, 'hex')
        );
        
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid HMAC' });
        }
        
        // Exchange code for access token
        const tokenResponse = await fetch(`https://${shop}/admin/oauth/access_token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                code: code
            })
        });
        
        if (!tokenResponse.ok) {
            throw new Error(`Token exchange failed: ${tokenResponse.statusText}`);
        }
        
        const tokenData = await tokenResponse.json();
        const { access_token, scope } = tokenData;
        
        // Log success (in production, save to database)
        console.log(`App installed for ${shop} with scopes: ${scope}`);
        
        // Return success page
        const successHTML = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Installation Complete - ${shop}</title>
                <meta charset="UTF-8">
                <style>
                    body { 
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        padding: 40px 20px; 
                        max-width: 600px; 
                        margin: 0 auto;
                        background: #f8f9fa;
                    }
                    .container {
                        background: white;
                        padding: 40px;
                        border-radius: 12px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                    }
                    .success { 
                        color: #28a745; 
                        font-size: 28px; 
                        text-align: center;
                        margin-bottom: 30px;
                    }
                    .info { 
                        background: #e8f5e8; 
                        padding: 20px; 
                        border-radius: 8px; 
                        margin: 20px 0;
                        border-left: 4px solid #28a745;
                    }
                    .shop-name {
                        font-weight: bold;
                        color: #6f42c1;
                    }
                    .next-steps {
                        background: #fff3cd;
                        border-left: 4px solid #ffc107;
                    }
                    .code {
                        font-family: 'Monaco', 'Menlo', monospace;
                        background: #f1f3f4;
                        padding: 2px 6px;
                        border-radius: 3px;
                        font-size: 14px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="success">✅ Installation Successful!</div>
                    
                    <div class="info">
                        <h3>✓ App Installed Successfully</h3>
                        <p><strong>Store:</strong> <span class="shop-name">${shop}</span></p>
                        <p><strong>Permissions Granted:</strong> <span class="code">${scope}</span></p>
                        <p><strong>Status:</strong> Ready for API access</p>
                    </div>
                    
                    <div class="info next-steps">
                        <h3>🚀 Next Steps for Power BI Integration:</h3>
                        <ol>
                            <li>Your app now has <strong>read_all_orders</strong> access</li>
                            <li>Check Shopify Admin → Settings → Apps to confirm installation</li>
                            <li>Use your Partner app credentials in Power Query</li>
                            <li>Access historical orders beyond 60 days via Admin API</li>
                        </ol>
                    </div>
                    
                    <p style="text-align: center; margin-top: 30px; color: #666;">
                        You can safely close this window.
                    </p>
                </div>
                
                <script>
                    // Auto-close after showing success for a few seconds
                    setTimeout(() => {
                        if (window.opener) {
                            window.close();
                        }
                    }, 5000);
                </script>
            </body>
            </html>
        `;
        
        res.setHeader('Content-Type', 'text/html');
        res.status(200).send(successHTML);
        
    } catch (error) {
        console.error('OAuth callback error:', error);
        
        const errorHTML = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Installation Failed</title>
                <style>
                    body { font-family: Arial, sans-serif; padding: 40px; text-align: center; }
                    .error { color: #dc3545; font-size: 24px; margin-bottom: 20px; }
                </style>
            </head>
            <body>
                <div class="error">❌ Installation Failed</div>
                <p>Error: ${error.message}</p>
                <p>Please try installing the app again from your Partner Dashboard.</p>
            </body>
            </html>
        `;
        
        res.setHeader('Content-Type', 'text/html');
        res.status(500).send(errorHTML);
    }
}
