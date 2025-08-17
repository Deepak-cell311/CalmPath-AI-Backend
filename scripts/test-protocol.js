const http = require('http');
const https = require('https');

// Helper function to determine the correct protocol (same as in routes.ts)
function getProtocol(req) {
    if (req.headers['x-forwarded-proto']) {
        return req.headers['x-forwarded-proto'];
    } else if (req.headers['x-forwarded-ssl'] === 'on') {
        return 'https';
    } else if (req.secure) {
        return 'https';
    }
    return req.protocol;
}

// Test cases
const testCases = [
    {
        name: 'Direct HTTP request',
        headers: {},
        protocol: 'http',
        secure: false,
        expected: 'http'
    },
    {
        name: 'Direct HTTPS request',
        headers: {},
        protocol: 'https',
        secure: true,
        expected: 'https'
    },
    {
        name: 'Behind proxy with X-Forwarded-Proto: https',
        headers: { 'x-forwarded-proto': 'https' },
        protocol: 'http',
        secure: false,
        expected: 'https'
    },
    {
        name: 'Behind proxy with X-Forwarded-SSL: on',
        headers: { 'x-forwarded-ssl': 'on' },
        protocol: 'http',
        secure: false,
        expected: 'https'
    },
    {
        name: 'Behind proxy with both headers',
        headers: { 
            'x-forwarded-proto': 'https',
            'x-forwarded-ssl': 'on'
        },
        protocol: 'http',
        secure: false,
        expected: 'https'
    },
    {
        name: 'Behind proxy with X-Forwarded-Proto: http',
        headers: { 'x-forwarded-proto': 'http' },
        protocol: 'https',
        secure: true,
        expected: 'http'
    }
];

console.log('Testing protocol detection logic...\n');

testCases.forEach((testCase, index) => {
    // Create a mock request object
    const mockReq = {
        protocol: testCase.protocol,
        secure: testCase.secure,
        headers: testCase.headers
    };
    
    const result = getProtocol(mockReq);
    const passed = result === testCase.expected;
    
    console.log(`Test ${index + 1}: ${testCase.name}`);
    console.log(`  Protocol: ${testCase.protocol}`);
    console.log(`  Secure: ${testCase.secure}`);
    console.log(`  Headers: ${JSON.stringify(testCase.headers)}`);
    console.log(`  Expected: ${testCase.expected}`);
    console.log(`  Got: ${result}`);
    console.log(`  Status: ${passed ? '✅ PASS' : '❌ FAIL'}`);
    console.log('');
});

console.log('Protocol detection test completed!');
console.log('\nTo test in production, upload a file and check the logs for:');
console.log('- Request protocol: http');
console.log('- X-Forwarded-Proto: https');
console.log('- Final protocol: https');
console.log('- Full URL being constructed: https://app.calmpath.ai/uploads/filename.jpg');
