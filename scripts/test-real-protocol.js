const http = require('http');
const https = require('https');

// Helper function to determine the correct protocol (same as in routes.ts)
function getProtocol(req) {
    console.log('=== Protocol Detection Debug ===');
    console.log('req.protocol:', req.protocol);
    console.log('req.secure:', req.secure);
    console.log('req.headers[x-forwarded-proto]:', req.headers['x-forwarded-proto']);
    console.log('req.headers[x-forwarded-ssl]:', req.headers['x-forwarded-ssl']);
    console.log('req.headers[x-forwarded-for]:', req.headers['x-forwarded-for']);
    console.log('req.headers[host]:', req.headers['host']);
    console.log('req.headers[origin]:', req.headers['origin']);
    console.log('req.headers[referer]:', req.headers['referer']);
    
    let protocol = req.protocol;
    
    if (req.headers['x-forwarded-proto']) {
        protocol = req.headers['x-forwarded-proto'];
        console.log('Using X-Forwarded-Proto:', protocol);
    } else if (req.headers['x-forwarded-ssl'] === 'on') {
        protocol = 'https';
        console.log('Using X-Forwarded-SSL, setting protocol to https');
    } else if (req.secure) {
        protocol = 'https';
        console.log('Using req.secure, setting protocol to https');
    } else {
        console.log('Using default req.protocol:', protocol);
    }
    
    console.log('Final protocol determined:', protocol);
    
    // Fallback: If the request comes from an HTTPS origin, force HTTPS
    if (req.headers['origin'] && req.headers['origin'].startsWith('https://')) {
        console.log('Origin is HTTPS, forcing protocol to https');
        protocol = 'https';
    } else if (req.headers['referer'] && req.headers['referer'].startsWith('https://')) {
        console.log('Referer is HTTPS, forcing protocol to https');
        protocol = 'https';
    }
    
    console.log('Final protocol after fallback:', protocol);
    console.log('=== End Protocol Detection Debug ===');
    
    return protocol;
}

// Create a simple HTTP server to test protocol detection
const server = http.createServer((req, res) => {
    console.log('\n=== Incoming Request ===');
    console.log('URL:', req.url);
    console.log('Method:', req.method);
    
    // Create a mock request object similar to Express
    const mockReq = {
        protocol: 'http',
        secure: false,
        headers: req.headers
    };
    
    const protocol = getProtocol(mockReq);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
        detectedProtocol: protocol,
        originalProtocol: mockReq.protocol,
        headers: req.headers
    }));
});

const PORT = 3001;
server.listen(PORT, () => {
    console.log(`Test server running on http://localhost:${PORT}`);
    console.log('\nTest with curl:');
    console.log(`curl -H "X-Forwarded-Proto: https" http://localhost:${PORT}/test`);
    console.log(`curl -H "Origin: https://app.calmpath.ai" http://localhost:${PORT}/test`);
    console.log(`curl -H "Referer: https://app.calmpath.ai/family-dashboard" http://localhost:${PORT}/test`);
});

// Auto-shutdown after 30 seconds
setTimeout(() => {
    console.log('\nShutting down test server...');
    server.close();
    process.exit(0);
}, 30000);
