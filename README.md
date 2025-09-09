# curl-wrap
Nodejs library that wraps curl command line

## Install
```sh
npm install curl-wrap
# OR
yarn add curl-wrap
```

## Usage

```js
const {Curl} = require('curl-wrap');

const response = await Curl.get('https://www.google.com');
console.log(response.body);
console.log(response.statusCode);
```

### Creating a Curl Instance

```js
const response = await Curl.url('https://www.example.com')
    .post()
    .header('Accept', 'application/json')
    .followRedirect(true)
    .timeout(30);

// you can also use
const curl = new Curl();
curl.url('https://www.example.com');
curl.post();
curl.header('Accept', 'application/json');
curl.followRedirect(true);
curl.timeout(30);
const res = await curl;
```

### Setting Headers

```js
curl.header('Content-Type', 'application/json');
curl.headers({
    'User-Agent': 'curl-wrap/1.0',
    'Accept': 'application/json'
});

// clear all headers
curl.clearHeaders();
```

### Setting Cookies

```js
curl.cookie('sessionId', 'abc123');
curl.cookies({
    'sessionId': 'abc123',
    'userId': 'user456'
});

// enable in memory cookie storage for all requests
curl.globalCookies();

// use a cookie file to store and read cookies
curl.cookieFile('cookies.json');
```

### Setting Proxy

```js
curl.proxy('http://proxy.example.com:8080');
curl.proxy({
    address: 'proxy.example.com',
    port: 8080,
    type: 'http',
    auth: {
        username: 'user',
        password: 'pass'
    }
});
```

### Authentication

```js
curl.httpAuth('username', 'password');
curl.bearerToken('your-token');
curl.apiToken('your-api-token');
```

### Impersonating a Browser

> **NOTE**: it will use `curl-impersonate` if it is in `PATH`.  
> **See**: `https://github.com/lexiforest/curl-impersonate`

```js
curl.impersonate('chrome');
curl.impersonate('chromeMobile');
curl.impersonate('firefox');
curl.impersonate('safari');
curl.impersonate('safariMobile');
curl.impersonate('edge');

// Or create a new instance with impersonation
const chromeCurl = Curl.impersonate('chrome');
```

### Setting Request Method

```js
curl.method('POST');
curl.get();
curl.post();
curl.put();
```

### Setting Request Body

```js
curl.body({key: 'value'});
curl.body('any data');
curl.json({key: 'value'});
```

### Setting POST/PUT Fields

```js
curl.field('key', 'value');
curl.fields({
    key1: value1,
    key2: value2,
});
```

### Setting Query Parameters

```js
curl.query('search', 'term');
curl.query({
    search: 'term',
    page: 1
});
```

### Setting Timeout

```js
curl.timeout(30); // in seconds
curl.timeoutMs(30000); // in milliseconds
```

### Handling Responses

```js
try {
    const response = await curl;
    console.log(response.body);
    console.log(response.statusCode);
}
catch (error) {
    console.error(error);
}
```

### Verbose Output

```js
curl.verbose(true);
const response = await curl;
console.log(response.stderr);
```

### Buffer Response

```js
curl.asBuffer();
const response = await curl;
console.log(response.body); // Buffer object instead of string
```

### Method Chaining

```js
Curl.url('https://www.example.com')
    .method('GET')
    .header('Accept', 'application/json')
    .followRedirect(true)
    .maxRedirects(5)
    .timeout(30)
    .then(response => {
        console.log(response.body);
    })
    .catch(error => {
        console.error(error);
    })
    .finally(() => {
        console.log('Request completed');
    });
```
