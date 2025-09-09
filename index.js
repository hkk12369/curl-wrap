const {spawn, spawnSync} = require('child_process');
const fs = require('fs/promises');
const {CookieJar} = require('tough-cookie');

/**
 * Returns proxy url based on the proxy options.
 *
 * @param  {object} proxy proxy options
 * @return {string} proxy url based on the options
 * @private
 */
// eslint-disable-next-line complexity
function makeProxyUrl(proxy, options) {
	if (!proxy) return '';
	let address = typeof proxy === 'string' ? proxy : (proxy.host || proxy.address || proxy.url);
	if (!address) return '';
	if (!address.includes('://')) {
		let type = proxy.type || options.type || 'http';
		if (type === 'socks') type = 'socks5';
		address = `${type}://${address}`;
	}

	const auth = proxy.auth || options.auth || {};
	const uri = new URL(address);
	if (!uri.port) {
		const port = proxy.port || options.port;
		if (port) {
			uri.port = port;
		}
		else if (uri.protocol.startsWith('socks')) {
			uri.port = '1080';
		}
	}
	if (!uri.username) {
		const username = proxy.username || options.username || auth.username;
		if (username) uri.username = username;
	}
	if (!uri.password) {
		const password = proxy.password || options.password || auth.password;
		if (password) uri.password = password;
	}
	return uri.toString();
}

/**
 * Parse curl command string into arguments array
 * 
 * @param {string} command
 * @return {string[]}
 */
function parseCommand(command) {
	// Clean up the command - remove line breaks and extra spaces
	command = command.replace(/\\\s*\n/g, ' ').replace(/\s+/g, ' ').trim();

	const args = [];
	let current = '';
	let inQuotes = false;
	let quoteChar = '';
	
	for (let i = 0; i < command.length; i++) {
		const char = command[i];
		const nextChar = command[i + 1];
		
		if ((char === '"' || char === "'") && !inQuotes) {
			inQuotes = true;
			quoteChar = char;
		}
		else if (char === quoteChar && inQuotes) {
			inQuotes = false;
			quoteChar = '';
		}
		else if (char === ' ' && !inQuotes) {
			if (current.trim()) {
				args.push(current.trim());
				current = '';
			}
		}
		else if (char === '\\' && nextChar === quoteChar && inQuotes) {
			current += nextChar;
			i++; // Skip next character
		}
		else {
			current += char;
		}
	}
	
	if (current.trim()) {
		args.push(current.trim());
	}
	
	return args;
}

class CurlResponse {
	constructor({body = ''} = {}) {
		this.url = '';
		this.body = body;
		this.headers = {};
		this.statusCode = 0;
		this.ip = '';
		this.errorMsg = '';
	}

	get status() {
		return this.statusCode;
	}

	setCurlJson(json, options = {}) {
		if (!json) return;
		this.curlJson = json;
		const data = json.json || {};
		this.statusCode = data.response_code || 0;
		this.ip = data.remote_ip || '';
		this.url = data.url_effective || data.url || '';
		this.errorMsg = data.errormsg || '';
		this.curlTimeTaken = Math.round((data.time_total || 0) * 1000);

		const headers = json.headers || {};
		for (const [key, value] of Object.entries(headers)) {
			this.headers[key.toLowerCase()] = value[0];
		}
		if (options.cookieJar) {
			const setCookies = headers['set-cookie'];
			if (setCookies) {
				setCookies.forEach((cookie) => {
					options.cookieJar.setCookie(cookie, this.url);
				});
			}
		}
	}
}

class Curl {
	/**
	 * Creates a new Curl object.
	 * @constructor
	 */
	constructor() {
		/**
		 * Various options (or parameters) defining the Connection
		 * @private
		 */
		this.options = {
			// url to send request at
			url: null,
			// method of the request (GET / POST / OPTIONS / DELETE / PATCH / PUT)
			method: 'GET',
			// headers to set
			headers: {
				accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
				// 'accept-encoding': 'gzip, deflate, br, zstd',
				'accept-language': 'en-US,en-IN;q=0.9,en;q=0.8',
				// set empty cookie header if no cookies exist
				// this is because some sites expect cookie header to be there
				cookie: '',
				// 'sec-ch-ua': '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
				// 'sec-ch-ua-arch': '"x86"',
				// 'sec-ch-ua-bitness': '"64"',
				// 'sec-ch-ua-full-version': '"129.0.6668.58"',
				// 'sec-ch-ua-full-version-list': '"Google Chrome";v="129.0.6668.58", "Not=A?Brand";v="8.0.0.0", "Chromium";v="129.0.6668.58"',
				// 'sec-ch-ua-mobile': '?0',
				// 'sec-ch-ua-model': '""',
				// 'sec-ch-ua-platform': '"Linux"',
				// 'sec-ch-ua-platform-version': '"6.2.0"',
				// 'sec-fetch-dest': 'empty',
				// 'sec-fetch-mode': 'navigate',
				// 'sec-fetch-site': 'same-origin',
				// 'upgrade-insecure-requests': 1,
				'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
			},
			// whether to follow redirects
			followRedirect: true,
			// maximum number of redirects to follow
			maxRedirects: 6,
			// whether to ask for compressed response (automatically handles accept-encoding)
			compress: true,
			// timeout of the request
			timeout: 120 * 1000,
			// whether to verify ssl certificate
			ignoreSSLError: true,
			// body of the request (valid in case of POST / PUT / PATCH / DELETE)
			body: '',
		};
	}

	get _cookies() {
		let cookies = this.options.cookies;
		if (!cookies) {
			cookies = {};
			this.options.cookies = cookies;
		}
		return cookies;
	}

	get _fields() {
		// post fields
		let fields = this.options.fields;
		if (!fields) {
			fields = {};
			this.options.fields = fields;
		}
		return fields;
	}

	get _query() {
		// query params
		let query = this.options.query;
		if (!query) {
			query = {};
			this.options.query = query;
		}
		return query;
	}

	/**
	 * Set the url for the connection.
	 *
	 * @param {string} url
	 * @return {Curl} self
	 */
	url(url) {
		this.options.url = url;
		return this;
	}

	/**
	 * @static
	 * Creates and returns a new Curl object with the given url.
	 *
	 * @param {string} url
	 * @return {Curl} A new Curl object with url set to the given url
	 */
	static url(url) {
		const curl = new this();
		curl.url(url);
		return curl;
	}

	/**
	 * @static
	 * Creates and returns a new Curl object (with get method) with the given url.
	 *
	 * @param {string} url
	 * @return {Curl} A new Curl object with url set to the given url
	 */
	static get(url) {
		const curl = new this();
		curl.url(url);
		curl.get();
		return curl;
	}

	/**
	 * @static
	 * Creates and returns a new Curl object (with post method) with the given url.
	 *
	 * @param {string} url
	 * @return {Curl} A new Curl object with url set to the given url
	 */
	static post(url) {
		const curl = new this();
		curl.url(url);
		curl.post();
		return curl;
	}

	/**
	 * @static
	 * Creates and returns a new Curl object (with put method) with the given url.
	 *
	 * @param {string} url
	 * @return {Curl} A new Curl object with url set to the given url
	 */
	static put(url) {
		const curl = new this();
		curl.url(url);
		curl.put();
		return curl;
	}

	/**
	 * @static
	 * Returns a new cookie jar.
	 * @param {Array<any>} args
	 * @return {CookieJar} A cookie jar
	 */
	static getNewCookieJar(...args) {
		return new CookieJar(...args);
	}

	/**
	 * @static
	 * Returns the global cookie jar.
	 * @returns {CookieJar} global cookie jar
	 */
	static getGlobalCookieJar() {
		if (!this._globalCookieJar) {
			this._globalCookieJar = this.getNewCookieJar();
		}
		return this._globalCookieJar;
	}

	/**
	 * @static
	 * whether curl-impersonate-chrome is available or not
	 * @see https://github.com/lexiforest/curl-impersonate
	 */
	static hasCurlImpersonate() {
		if (this._hasCurlImpersonate === undefined) {
			this._hasCurlImpersonate = spawnSync('curl-impersonate', ['--version']).status === 0;
		}
		return this._hasCurlImpersonate;
	}

	/**
	 * set cli command (default: curl)
	 *
	 * @param {string} command name of curl binary
	 * @return {Curl} self
	 */
	cliCommand(command) {
		this.options.cliCommand = command;
		return this;
	}

	/**
	 * add curl cli options
	 *
	 * @param {string|Array<string>} options curl cli options
	 * @return {Curl} self
	 */
	cliOptions(options) {
		const cliOptions = this.options.cliOptions || (this.options.cliOptions = []);
		if (typeof options === 'string') {
			cliOptions.push(options);
		}
		else {
			cliOptions.push(...options);
		}
		return this;
	}

	/**
	 * @typedef {"chrome"|"chromeMobile"|"edge"|"safari"|"safariMobile"|"firefox"} BrowserType
	 */

	/**
	 * impersonate a browser
	 *
	 * @param {BrowserType} browser browser to impersonate
	 * @return {Curl} self
	 */
	impersonate(browser = 'chrome') {
		if (browser === 'chrome') {
			if (this.constructor.hasCurlImpersonate()) {
				this.cliCommand('curl-impersonate');
				this.cliOptions([
					'--ciphers',
					'TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-ECDSA-CHACHA20-POLY1305,ECDHE-RSA-CHACHA20-POLY1305,ECDHE-RSA-AES128-SHA,ECDHE-RSA-AES256-SHA,AES128-GCM-SHA256,AES256-GCM-SHA384,AES128-SHA,AES256-SHA',
					'--curves',
					'X25519MLKEM768:X25519:P-256:P-384',
					'--http2',
					'--http2-settings',
					'1:65536;2:0;4:6291456;6:262144',
					'--http2-window-update',
					'15663105',
					'--http2-stream-weight',
					'256',
					'--http2-stream-exclusive',
					'1',
					'--compressed',
					'--ech',
					'grease',
					'--tlsv1.2',
					'--alps',
					'--tls-permute-extensions',
					'--cert-compression',
					'brotli',
					'--tls-grease',
					'--tls-use-new-alps-codepoint',
					'--tls-signed-cert-timestamps',
				]);
			}
			this.headers({
				'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
				'sec-ch-ua-mobile': '?0',
				'sec-ch-ua-platform': '"macOS"',
				'Upgrade-Insecure-Requests': '1',
				'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
				Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
				'Sec-Fetch-Site': 'none',
				'Sec-Fetch-Mode': 'navigate',
				'Sec-Fetch-User': '?1',
				'Sec-Fetch-Dest': 'document',
				'Accept-Encoding': 'gzip, deflate, br, zstd',
				'Accept-Language': 'en-US,en;q=0.9',
				'Priority': 'u=0, i',
			});
		}
		else if (browser === 'chromeMobile') {
			if (this.constructor.hasCurlImpersonate()) {
				this.cliCommand('curl-impersonate');
				this.cliOptions([
					'--ciphers',
					'TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-ECDSA-CHACHA20-POLY1305,ECDHE-RSA-CHACHA20-POLY1305,ECDHE-RSA-AES128-SHA,ECDHE-RSA-AES256-SHA,AES128-GCM-SHA256,AES256-GCM-SHA384,AES128-SHA,AES256-SHA',
					'--curves',
					'X25519:P-256:P-384',
					'--http2',
					'--http2-settings',
					'1:65536;2:0;4:6291456;6:262144',
					'--http2-window-update',
					'15663105',
					'--http2-stream-weight',
					'256',
					'--http2-stream-exclusive',
					'1',
					'--compressed',
					'--ech',
					'grease',
					'--tlsv1.2',
					'--alps',
					'--tls-permute-extensions',
					'--cert-compression',
					'brotli',
					'--tls-grease',
					'--tls-use-new-alps-codepoint',
					'--tls-signed-cert-timestamps',
				]);
			}
			this.headers({
				'sec-ch-ua': 'Google Chrome";v="137", "Chromium";v="137", "Not_A Brand";v="24"',
				'sec-ch-ua-mobile': '?0',
				'sec-ch-ua-platform': '"Android"',
				'Upgrade-Insecure-Requests': '1',
				'User-Agent': 'Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
				Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
				'Sec-Fetch-Site': 'none',
				'Sec-Fetch-Mode': 'navigate',
				'Sec-Fetch-User': '?1',
				'Sec-Fetch-Dest': 'document',
				'Accept-Encoding': 'gzip, deflate, br, zstd',
				'Accept-Language': 'en-US,en;q=0.9',
				'Priority': 'u=0, i',
			});
		}
		else if (browser === 'edge') {
			if (this.constructor.hasCurlImpersonate()) {
				this.cliCommand('curl-impersonate');
				this.cliOptions([
					'--ciphers',
					'TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-ECDSA-CHACHA20-POLY1305,ECDHE-RSA-CHACHA20-POLY1305,ECDHE-RSA-AES128-SHA,ECDHE-RSA-AES256-SHA,AES128-GCM-SHA256,AES256-GCM-SHA384,AES128-SHA,AES256-SHA',
					'--http2',
					'--http2-settings',
					'1:65536;3:1000;4:6291456;6:262144',
					'--http2-window-update',
					'15663105',
					'--http2-stream-weight',
					'256',
					'--http2-stream-exclusive',
					'1',
					'--compressed',
					'--tlsv1.2',
					'--alps',
					'--cert-compression',
					'brotli',
					'--tls-grease',
					'--tls-signed-cert-timestamps',
				]);
			}
			this.headers({
				'sec-ch-ua': ' Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
				'sec-ch-ua-mobile': '?0',
				'sec-ch-ua-platform': '"Windows"',
				'Upgrade-Insecure-Requests': '1',
				'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47',
				Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
				'Sec-Fetch-Site': 'none',
				'Sec-Fetch-Mode': 'navigate',
				'Sec-Fetch-User': '?1',
				'Sec-Fetch-Dest': 'document',
				'Accept-Encoding': 'gzip, deflate, br',
				'Accept-Language': 'en-US,en;q=0.9',
			});
		}
		else if (browser === 'safari') {
			if (this.constructor.hasCurlImpersonate()) {
				this.cliCommand('curl-impersonate');
				this.cliOptions([
					'--ciphers',
					'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:TLS_RSA_WITH_3DES_EDE_CBC_SHA',
					'--curves',
					'X25519:P-256:P-384:P-521',
					'--signature-hashes',
					'ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256,rsa_pkcs1_sha256,ecdsa_secp384r1_sha384,rsa_pss_rsae_sha384,rsa_pss_rsae_sha384,rsa_pkcs1_sha384,rsa_pss_rsae_sha512,rsa_pkcs1_sha512,rsa_pkcs1_sha1',
					'--http2',
					'--http2-settings',
					'2:0;3:100;4:2097152;9:1',
					'--http2-pseudo-headers-order',
					'msap',
					'--http2-window-update',
					'10420225',
					'--http2-stream-weight',
					'256',
					'--http2-stream-exclusive',
					'0',
					'--compressed',
					'--tlsv1.0',
					'--no-tls-session-ticket',
					'--cert-compression',
					'zlib',
					'--tls-grease',
					'--tls-signed-cert-timestamps',
				]);
			}
			this.headers({
				'sec-fetch-dest': 'document',
				'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15',
				accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
				'sec-fetch-site': 'none',
				'sec-fetch-mode': 'navigate',
				'accept-language': 'en-US,en;q=0.9',
				'priority': 'u=0, i',
				'accept-encoding': 'gzip, deflate, br',
			});
		}
		else if (browser === 'safariMobile') {
			if (this.constructor.hasCurlImpersonate()) {
				this.cliCommand('curl-impersonate');
				this.cliOptions([
					'--ciphers',
					'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:TLS_RSA_WITH_3DES_EDE_CBC_SHA',
					'--curves',
					'X25519:P-256:P-384:P-521',
					'--signature-hashes',
					'ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256,rsa_pkcs1_sha256,ecdsa_secp384r1_sha384,rsa_pss_rsae_sha384,rsa_pss_rsae_sha384,rsa_pkcs1_sha384,rsa_pss_rsae_sha512,rsa_pkcs1_sha512,rsa_pkcs1_sha1',
					'--http2',
					'--http2-settings',
					'2:0;3:100;4:2097152;9:1',
					'--http2-pseudo-headers-order',
					'msap',
					'--http2-window-update',
					'10420225',
					'--http2-stream-weight',
					'256',
					'--http2-stream-exclusive',
					'0',
					'--compressed',
					'--tlsv1.0',
					'--no-tls-session-ticket',
					'--cert-compression',
					'zlib',
					'--tls-grease',
					'--tls-signed-cert-timestamps',
				]);
			}
			this.headers({
				'sec-fetch-dest': 'document',
				'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1',
				accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
				'sec-fetch-site': 'none',
				'sec-fetch-mode': 'navigate',
				'accept-language': 'en-US,en;q=0.9',
				'priority': 'u=0, i',
				'accept-encoding': 'gzip, deflate, br',
			});
		}
		else if (browser === 'firefox') {
			if (this.constructor.hasCurlImpersonate()) {
				this.cliCommand('curl-impersonate');
				this.cliOptions([
					'--ciphers',
					'TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA',
					'--curves',
					'X25519MLKEM768:X25519:P-256:P-384:P-521:ffdhe2048:ffdhe3072',
					'--signature-hashes',
					'ecdsa_secp256r1_sha256,ecdsa_secp384r1_sha384,ecdsa_secp521r1_sha512,rsa_pss_rsae_sha256,rsa_pss_rsae_sha384,rsa_pss_rsae_sha512,rsa_pkcs1_sha256,rsa_pkcs1_sha384,rsa_pkcs1_sha512,ecdsa_sha1,rsa_pkcs1_sha1',
					'--http2',
					'--http2-settings',
					'1:65536;2:0;4:131072;5:16384',
					'--http2-pseudo-headers-order',
					'msap',
					'--http2-window-update',
					'12517377',
					'--http2-stream-weight',
					'42',
					'--http2-stream-exclusive',
					'0',
					'--compressed',
					'--ech',
					'grease',
					'--tls-extension-order',
					'0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037',
					'--tls-delegated-credentials',
					'ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:ecdsa_sha1',
					'--tls-record-size-limit',
					'4001',
					'--tls-key-shares-limit',
					'3',
					'--cert-compression',
					'zlib,brotli,zstd',
					'--tls-signed-cert-timestamps',
					'--tls-use-firefox-tls13-ciphers',
				]);
			}
			this.headers({
				'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0',
				Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
				'Accept-Language': 'en-US,en;q=0.5',
				'Accept-Encoding': 'gzip, deflate, br, zstd',
				'Upgrade-Insecure-Requests': '1',
				'Sec-Fetch-Dest': 'document',
				'Sec-Fetch-Mode': 'navigate',
				'Sec-Fetch-Site': 'none',
				'Sec-Fetch-User': '?1',
				'Priority': 'u=0, i',
				'TE': 'trailers',
			});
		}
		return this;
	}

	/**
	 * @static
	 * impersonate a browser
	 *
	 * @param {BrowserType} browser browser to impersonate
	 * @return {Curl} self
	 */
	static impersonate(browser = 'chrome') {
		const curl = new this();
		curl.impersonate(browser);
		return curl;
	}

	/**
	 * Set or unset the followRedirect option for the connection.
	 *
	 * @param {boolean} shouldFollowRedirect boolean representing whether to follow redirect or not
	 * @return {Curl} self
	 */
	followRedirect(shouldFollowRedirect = true) {
		this.options.followRedirect = shouldFollowRedirect;
		return this;
	}

	/**
	 * Set the number of maximum redirects to follow
	 * @param {number} numRedirects max number of redirects
	 */
	maxRedirects(numRedirects) {
		this.options.maxRedirects = numRedirects;
		return this;
	}

	/**
	 * Set value of a header parameter for the connection.
	 *
	 * @param {string|object} headerName name of the header parameter whose value is to be set
	 * @param {string|undefined} headerValue value to be set
	 * @return {Curl} self
	 */
	header(headerName, headerValue) {
		if (typeof headerName === 'string') {
			this.options.headers[headerName.toLowerCase()] = headerValue;
		}
		else {
			Object.assign(
				this.options.headers,
				Object.fromEntries(
					Object.entries(headerName).map(([key, val]) => [key.toLowerCase(), val])
				),
			);
		}

		return this;
	}

	/**
	 * Set value of the headers for the connection.
	 *
	 * @param {object} headers object representing the headers for the connection
	 * @return {Curl} self
	 */
	headers(headers) {
		this.header(headers);
		return this;
	}

	/**
	 * Clear all headers
	 * 
	 * @return {Curl} self
	 */
	clearHeaders() {
		this.options.headers = {};
		return this;
	}

	/**
	 * Set the content type as json
	 * Optionally also set the body of the request.
	 *
	 * @param {object|undefined} body value for body
	 * @return {Curl} self
	 */
	json(body) {
		this.header('content-type', 'application/json');
		if (body !== undefined) {
			this.options.body = body;
		}
		return this;
	}

	/**
	 * Set the body of the connection object.
	 *
	 * @param {any} body value for body
	 *  if body is an object, contentType will be set to application/json and body will be stringified
	 * @param {string} [contentType=null] string representing the content type of the body
	 *  contentType can be null or json
	 * @return {Curl} self
	 */
	body(body, contentType = null) {
		if (contentType) {
			this.contentType = contentType;
		}

		this.options.body = body;
		return this;
	}

	/**
	 * Set the 'Referer' field in the headers.
	 *
	 * @param {string} referer referer value
	 * @return {Curl}
	 */
	referer(referer) {
		this.header('referer', referer);
		return this;
	}

	/**
	 * Set the 'Referer' field in the headers.
	 *
	 * @param {string} referer referer value
	 * @return {Curl}
	 */
	referrer(referrer) {
		this.header('referer', referrer);
		return this;
	}

	/**
	 * Set the 'User-Agent' field in the headers.
	 *
	 * @param {string} userAgent name of the user-agent or its value
	 * @return {Curl} self
	 */
	userAgent(userAgent) {
		this.header('user-agent', userAgent);
		return this;
	}

	/**
	 * Set the 'Content-Type' field in the headers.
	 *
	 * @param  {string} contentType value for content-type
	 * @return {Curl}
	 */
	contentType(contentType) {
		if (contentType === 'json') {
			this.header('content-type', 'application/json');
		}
		else if (contentType === 'form') {
			this.header('content-type', 'application/x-www-form-urlencoded');
		}
		else {
			this.header('content-type', contentType);
		}

		return this;
	}

	/**
	 * Returns whether the content-type is JSON or not
	 *
	 * @return {boolean} true, if content-type is JSON; false, otherwise
	 */
	isJSON() {
		const contentType = this.options.headers['content-type'] || '';
		return contentType.startsWith('application/json');
	}

	/**
	 * Returns whether the content-type is Form or not
	 *
	 * @return {boolean} true, if content-type is JSON; false, otherwise
	 */
	isForm() {
		return this.options.headers['content-type'] === 'application/x-www-form-urlencoded';
	}

	/**
	 * Sets the value of a cookie.
	 * Can be used to enable global cookies, if cookieName is set to true
	 * and cookieValue is undefined (or is not passed as an argument).
	 * Can also be used to set multiple cookies by passing in an object
	 * representing the cookies and their values as key:value pairs.
	 *
	 * @param {string|boolean|object} cookieName  represents the name of the
	 * cookie to be set, or the cookies object
	 * @param {string|undefined} [cookieValue] cookie value to be set
	 * @return {Curl} self
	 */
	cookie(cookieName, cookieValue) {
		if (cookieValue === undefined) {
			this.globalCookies(cookieName);
		}
		else if (typeof cookieName === 'string') {
			if (cookieValue === null || cookieValue === false) {
				delete this._cookies[cookieName];
			}
			else {
				this._cookies[cookieName] = cookieValue;
			}
		}
		else if (cookieName && typeof cookieName === 'object') {
			Object.assign(this._cookies, cookieName);
		}

		return this;
	}

	/**
	 * Sets multiple cookies.
	 * Can be used to enable global cookies, if cookies is set to true.
	 *
	 * @param {object|boolean} cookies object representing the cookies
	 * and their values as key:value pairs.
	 * @return {Curl} self
	 */
	cookies(cookies) {
		if (cookies === true || cookies === false || cookies == null) {
			this.globalCookies(cookies);
		}
		else if (cookies && typeof cookies === 'object') {
			Object.assign(this._cookies, cookies);
		}

		return this;
	}

	/**
	 * Enable global cookies.
	 *
	 * @param {boolean|object} [options=true]
	 * @return {Curl} self
	 */
	globalCookies(options = true) {
		if (options === false || options === null) {
			delete this.options.cookieJar;
			delete this.options.readCookieJar;
			return this;
		}

		const jar = this.constructor.getGlobalCookieJar();
		this.cookieJar(jar, options);
		return this;
	}

	/**
	 * Set the value of cookie jar.
	 *
	 * @param {CookieJar} cookieJar value to be set
	 * @return {Curl} self
	 */
	cookieJar(cookieJar, options = {}) {
		delete this._cookieFileFn;
		delete this._cookieFileFnRes;

		if (options.readOnly) {
			this.options.readCookieJar = cookieJar;
		}
		else {
			this.options.cookieJar = cookieJar;
		}

		return this;
	}

	/**
	 * Set the value of cookie jar based on a file (cookie store).
	 *
	 * @param {string} fileName name of (or path to) the file
	 * @return {Curl} self
	 */
	cookieFile(fileName, options = {}) {
		const setCookieJar = (cookieJar) => {
			if (options.readOnly) {
				this.options.readCookieJar = cookieJar;
			}
			else {
				this.options.cookieJar = cookieJar;
			}
		};

		this._cookieFileFn = async () => {
			try {
				const contents = await fs.readFile(fileName, {encoding: 'utf8'});
				const obj = JSON.parse(contents);
				const cookieJar = CookieJar.fromJSON(obj);
				setCookieJar(cookieJar);
			}
			catch (e) {
				setCookieJar(this.constructor.getNewCookieJar());
			}
		};

		if (!options.readOnly) {
			this._cookieFileFnRes = async () => {
				const cookieJar = this.options.cookieJar;
				if (!cookieJar) return;
				try {
					const contents = JSON.stringify(cookieJar.toJSON());
					await fs.writeFile(fileName, contents, {encoding: 'utf8'});
				}
				catch (e) {
					// ignore errors
				}
			};
		}

		return this;
	}

	/**
	 * Set request timeout.
	 *
	 * @param  {number} timeout timeout value in seconds
	 * @return {Curl} self
	 */
	timeout(timeout) {
		this.options.timeout = timeout * 1000;
		return this;
	}

	/**
	 * Set request timeout.
	 *
	 * @param  {number} timeoutInMs timeout value in milliseconds
	 * @return {Curl} self
	 */
	timeoutMs(timeoutInMs) {
		this.options.timeout = timeoutInMs;
		return this;
	}

	/**
	 * Set value of a field in the options.
	 * Can also be used to set multiple fields by passing in an object
	 * representing the field-names and their values as key:value pairs.
	 *
	 * @param {string|object} fieldName name of the field to be set, or the fields object
	 * @param {string|undefined} [fieldValue] value to be set
	 * @return {Curl} self
	 */
	field(fieldName, fieldValue) {
		if (typeof fieldName === 'string') {
			this._fields[fieldName] = fieldValue;
		}
		else if (fieldName && typeof fieldName === 'object') {
			Object.assign(this._fields, fieldName);
		}

		return this;
	}

	/**
	 * Set multiple fields.
	 *
	 * @param {object} fields object representing the field-names and their
	 *  values as key:value pairs
	 * @return {Curl} self
	 */
	fields(fields) {
		if (fields && typeof fields === 'object') {
			Object.assign(this._fields, fields);
		}
		return this;
	}

	/**
	 * Set value of a query parameter
	 * Can also be used to set multiple query params by passing in an object
	 * representing the param-names and their values as key:value pairs.
	 *
	 * @param {string|object} fieldName name of the field to be set, or the fields object
	 * @param {string|undefined} [fieldValue] value to be set
	 * @return {Curl} self
	 */
	query(name, value) {
		if (typeof name === 'string') {
			this._query[name] = value;
		}
		else if (name && typeof name === 'object') {
			Object.assign(this._query, name);
		}

		return this;
	}

	/**
	 * set whether to ask for compressed response (handles decompression automatically)
	 * @param {boolean} [askForCompression=true] whether to ask for compressed response
	 * @return {Curl} self
	 */
	compress(askForCompression = true) {
		this.options.compress = askForCompression;
		return this;
	}

	/**
	 * Set the request method for the connection.
	 *
	 * @param {string} method one of the HTTP request methods ('GET', 'PUT', 'POST', etc.)
	 * @return {Curl} self
	 */
	method(method) {
		this.options.method = (method || 'GET').toUpperCase();
		return this;
	}

	/**
	 * @typedef {object} auth
	 * @property {string} username
	 * @property {string} password
	 */

	/**
	 * Set username and password for authentication.
	 *
	 * @param {string | auth} username
	 * @param {string|undefined} password
	 * @return {Curl} self
	 */
	httpAuth(username, password) {
		let auth = '';
		if (typeof username === 'string') {
			if (password === undefined) {
				// username is of the format username:password
				auth = username;
			}
			else {
				// username & password are strings
				auth = `${username}:${password}`;
			}
		}
		else if (username.username) {
			// username argument is an object of {username, password}
			auth = `${username.username}:${username.password}`;
		}

		this.header('authorization', 'Basic ' + Buffer.from(auth).toString('base64'));
		return this;
	}

	/**
	 * Set bearer token for authorization
	 * @param {string} token
	 * @return {Curl} self
	 */
	bearerToken(token) {
		this.header('authorization', `Bearer ${token}`);
		return this;
	}

	/**
	 * Set api token using x-api-token header
	 * @param {string} token
	 * @return {Curl} self
	 */
	apiToken(token) {
		this.header('x-api-token', token);
		return this;
	}

	/**
	 * enable or disable proxy use
	 * you need to set the proxy to use using the proxy() method
	 * 
	 * @package {boolean} [shouldUseProxy=true] whether to use proxy or not
	 * @returns {Curl} self
	 */
	useProxy(shouldUseProxy = true) {
		this.options.useProxy = shouldUseProxy;
		return this;
	}

	/**
	 * Set proxy address (or options).
	 * Proxy type can be http, https, or socks5.
	 *
	 * @param {string|object} proxy proxy address, or object representing proxy options
	 * @param {object} [options={}] options for proxy ({username, password, type})
	 * @return {Curl} self
	 */
	proxy(proxy, options = {}) {
		if (proxy === false || proxy === null) {
			delete this.options.proxy;
		}
		this.options.proxy = makeProxyUrl(proxy, options);
		return this;
	}

	/**
	 * Set keepalive connection option
	 *
	 * @param {boolean} [isKeepAlive=true] whether to keepalive or not
	 * @returns {Curl} self
	 */
	keepalive(isKeepAlive = true) {
		this.options.keepalive = isKeepAlive;
		return this;
	}

	/**
	 * Set request method to 'GET'.
	 *
	 * @return {Curl} self
	 */
	get() {
		this.method('GET');
		return this;
	}

	/**
	 * Set request method to 'POST'.
	 *
	 * @return {Curl} self
	 */
	post() {
		this.method('POST');
		return this;
	}

	/**
	 * Set request method to 'PUT'.
	 *
	 * @return {Curl} self
	 */
	put() {
		this.method('PUT');
		return this;
	}

	/**
	 * Use curl --verbose option to get verbose output.
	 *
	 * @return {Curl} self
	 */
	verbose(isVerbose = true) {
		this.options.verbose = isVerbose;
		return this;
	}

	/**
	 * Set if the body is to be returned as a buffer
	 *
	 * @param {boolean} [returnAsBuffer=true]
	 * @return {Curl} self
	 */
	asBuffer(returnAsBuffer = true) {
		this.options.asBuffer = returnAsBuffer;
		return this;
	}

	/**
	 * Export the current request as a curl command string
	 *
	 * @return {Promise<string>} curl command as a string
	 */
	async exportAsCurl() {
		const cmd = this.options.cliCommand || 'curl';
		const args = await this.getCurlArgs();
		// Filter out internal options that shouldn't appear in exported commands
		const skipOptions = ['--silent', '--no-keepalive', '--keepalive', '--write-out', '--insecure', '--location'];
		const escape = arg => `'${arg.replace(/'/g, "'\"'\"'")}'`;
		
		const url = args[0];
		const lines = [`${cmd} ${escape(url)}`];
		for (let i = 1; i < args.length; i++) {
			const arg = String(args[i]);
			const nextArg = String(args[i + 1] ?? '');
			const isNextArgValue = !nextArg.startsWith('--');
			if (isNextArgValue) {
				i++;
			}
			// Skip internal options and their values
			if (skipOptions.includes(arg)) continue;
			if (isNextArgValue) {
				const escapedNextArg = /[\s"'`&:;,><|(){}~^%#@!/=+\$\?\*\[\]]/.test(nextArg) ? escape(nextArg) : nextArg;
				lines.push(`${arg} ${escapedNextArg}`);
			}
			else {
				lines.push(arg);
			}
		}
		
		return lines.join(' \\\n  ');
	}

	/**
	 * @static
	 * Create a new Curl instance from a curl command string
	 *
	 * @param {string} curlCommand curl command string to parse
	 * @return {Curl} new Curl instance
	 */
	static fromCurl(curlCommand) {
		const curl = new this();
		curl.options.headers = {};
		
		// Parse the command into arguments
		const args = parseCommand(curlCommand);
		
		let method;
		let body;
		
		// Process arguments
		for (let i = 0; i < args.length; i++) {
			const arg = args[i];
			const nextArg = args[i + 1];
			const isNextArgValue = nextArg && !nextArg.startsWith('-');
			
			if (i === 0 && !arg.startsWith('curl')) {
				// First argument should be the URL if no 'curl' command prefix
				curl.url(arg);
			}
			else if (i === 1 && args[0].startsWith('curl')) {
				// Second argument is URL when first is 'curl'
				curl.url(arg);
			}
			else if (arg === '--request' || arg === '-X') {
				if (!isNextArgValue) continue;
				method = nextArg;
				i++;
			}
			else if (arg === '--header' || arg === '-H') {
				if (!isNextArgValue) continue;
				const colonIndex = nextArg.indexOf(':');
				if (colonIndex !== -1) {
					const headerName = nextArg.slice(0, colonIndex).trim();
					const headerValue = nextArg.slice(colonIndex + 1).trim();
					curl.header(headerName, headerValue);
				}
				i++;
			}
			else if (arg === '--data' || arg === '--data-raw' || arg === '-d') {
				if (!isNextArgValue) continue;
				body = nextArg;
				i++;
			}
			else if (arg === '--cookie' || arg === '-b') {
				if (!isNextArgValue) continue;
				curl.header('cookie', nextArg);
				i++;
			}
			else if (arg === '--user-agent' || arg === '-A') {
				if (!isNextArgValue) continue;
				curl.userAgent(nextArg);
				i++;
			}
			else if (arg === '--referer' || arg === '-e') {
				if (!isNextArgValue) continue;
				curl.referer(nextArg);
				i++;
			}
			else if (arg === '--max-time' || arg === '-m') {
				if (!isNextArgValue) continue;
				const timeout = Number(nextArg);
				if (timeout > 0) curl.timeout(timeout);
				i++;
			}
			else if (arg === '--proxy' || arg === '-x') {
				if (!isNextArgValue) continue;
				curl.proxy(nextArg);
				i++;
			}
			else if (arg === '--compressed') {
				curl.compress(true);
			}
			else if (arg === '--location' || arg === '-L') {
				curl.followRedirect(true);
			}
			else if (arg === '--max-redirs') {
				if (!isNextArgValue) continue;
				const maxRedir = Math.floor(Number(nextArg));
				if (maxRedir > 0) curl.maxRedirects(maxRedir);
				i++;
			}
			else if (arg === '--verbose' || arg === '-v') {
				curl.verbose(true);
			}
			else if (arg.startsWith('--') || arg.startsWith('-')) {
				// Ignore internal options that shouldn't be imported
				const ignoreOptions = ['--silent', '--no-keepalive', '--keepalive', '--write-out', '--insecure'];
				if (ignoreOptions.includes(arg)) {
					// If the ignored option has a value, ignore it too
					if (isNextArgValue) {
						i++;
					}
				}
				else {
					// Handle unknown curl options by adding them as cliOptions
					if (isNextArgValue) {
						curl.cliOptions([arg, nextArg]);
						i++; // Skip next argument
					}
					else {
						curl.cliOptions(arg);
					}
				}
			}
		}

		if (body) {
			curl.body(body);
			method = method || 'POST';
		}
		if (method) {
			curl.method(method);
		}
		
		return curl;
	}

	/**
	 * Add the options 'fields' to the options body, form or qs
	 * on the basis of the request method.
	 *
	 * NOTE: This function is for internal use
	 * @private
	 */
	getUrlAndBody() {
		const options = this.options;
		let url = options.url;
		let query = options.query;
		let body = options.body;
		const fields = options.fields;
		const hasBody = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(options.method);

		if (!body) {
			if (fields) {
				body = fields;
				if (hasBody && !this.options.headers['content-type']) {
					this.contentType('form');
				}
			}
		}
		else if (typeof body === 'object') {
			if (fields) {
				Object.assign(body, fields);
			}
			if (hasBody && !options.headers['content-type']) {
				this.contentType('json');
			}
		}

		if (hasBody) {
			if (this.isJSON()) {
				if (typeof body === 'object') {
					body = JSON.stringify(body);
				}
			}
			else if (this.isForm()) {
				if (typeof body === 'object') {
					body = (new URLSearchParams(body)).toString();
				}
			}
		}
		else if (body && (typeof body === 'object')) {
			if (query) {
				Object.assign(body, query);
			}
			query = body;
			body = '';
		}

		if (query) {
			const qs = (new URLSearchParams(query)).toString();
			const joiner = url.includes('?') ? '&' : '?';
			url += (joiner + qs);
		}

		return {
			url,
			body,
		};
	}

	async getCookieHeader() {
		const cookies = [];
		const options = this.options;

		const cookieMap = options.cookies;
		if (cookieMap) {
			for (const [key, value] of Object.entries(cookieMap)) {
				cookies.push(`${key}=${value}`);
			}
		}

		if (this._cookieFileFn) {
			await this._cookieFileFn();
		}

		const cookieJar = options.readCookieJar || options.cookieJar;
		if (cookieJar) {
			const jarCookies = await cookieJar.getCookies(options.url);
			if (jarCookies) {
				if (cookieMap) {
					jarCookies.forEach((cookie) => {
						if (!cookieMap[cookie.key]) {
							cookies.push(`${cookie.key}=${cookie.value}`);
						}
					});
				}
				else {
					jarCookies.forEach((cookie) => {
						cookies.push(`${cookie.key}=${cookie.value}`);
					});
				}
			}
		}

		return cookies.join('; ');
	}

	async getCurlArgs() {
		const {url, body} = this.getUrlAndBody();

		const options = this.options;
		const args = [
			url,
			'--request',
			options.method,
			options.keepalive ? '--keepalive' : '--no-keepalive',
			'--silent',
			'--write-out',
			'%{stderr}===<json>==={"json":%{json},"headers":%{header_json}}===</json>===',
		];

		const cliOptions = options.cliOptions;
		if (cliOptions) {
			args.push(...cliOptions);
		}

		if (options.compress && !cliOptions?.includes('--compressed')) {
			args.push('--compressed');
		}
		if (options.proxy && options.useProxy !== false) {
			args.push('--proxy', options.proxy);
		}
		if (options.timeout) {
			args.push('--max-time', options.timeout / 1000);
		}
		if (options.followRedirect) {
			args.push('--location');
		}
		if (options.maxRedirects) {
			args.push('--max-redirs', options.maxRedirects);
		}
		if (options.ignoreSSLError) {
			args.push('--insecure');
		}
		if (options.verbose) {
			args.push('--verbose');
		}

		const cookieHeader = await this.getCookieHeader();
		if (cookieHeader) {
			this.header('cookie', cookieHeader);
		}

		for (const [key, value] of Object.entries(options.headers)) {
			args.push('--header', `${key}: ${value}`);
		}

		if (body) {
			args.push('--data-raw', body);
		}

		return args;
	}

	async fetch() {
		const startTime = Date.now();
		const options = this.options;
		const cmd = options.cliCommand || 'curl';
		const args = await this.getCurlArgs();
		const curl = spawn(cmd, args);
		const cookieJar = options.cookieJar;

		let stdout = options.asBuffer ? Buffer.from([]) : '';
		let stderr = '';
		const response = new CurlResponse({
			body: options.asBuffer ? Buffer.from([]) : '',
		});
		return new Promise((resolve, reject) => {
			if (options.asBuffer) {
				curl.stdout.on('data', (data) => {
					stdout = Buffer.concat([stdout, data]);
				});
			}
			else {
				curl.stdout.on('data', (data) => {
					stdout += data;
				});
			}

			curl.stderr.on('data', (data) => {
				stderr += data;
			});

			curl.on('error', (error) => {
				error.timeTaken = Date.now() - startTime;
				reject(error);
			});

			curl.on('close', async (code) => {
				response.timeTaken = Date.now() - startTime;
				response.exitCode = code;
				response.url = options.url;
				response.body = stdout;
				stderr = stderr.replace(/===<json>===(.*)===<\/json>===/s, (match, p1) => {
					try {
						response.setCurlJson(JSON.parse(p1), {cookieJar});
					}
					catch (e) {
						// ignore error
					}
					return '';
				});
				response.stderr = stderr;

				if (this._cookieFileFnRes) {
					try {
						await this._cookieFileFnRes();
					}
					catch (e) {
						// ignore errors
					}
				}

				if (code === 0) {
					resolve(response);
				}
				else {
					const error = new Error(response.errorMsg || stderr);
					error.response = response;
					reject(error);
				}
			});
		});
	}

	/**
	 * It is used for method chaining.
	 *
	 * @template T
	 * @param  {function(response):T} successCallback To be called if the Promise is fulfilled
	 * @param  {function(Error):T} [errorCallback] function to be called if the Promise is rejected
	 * @return {Promise<T>} a Promise in pending state
	 */
	then(successCallback, errorCallback) {
		return this.fetch().then(successCallback, errorCallback);
	}

	/**
	 * It is also used for method chaining, but handles rejected cases only.
	 *
	 * @template T
	 * @param  {function(Error):T} errorCallback function to be called if the Promise is rejected
	 * @return {Promise<T>} a Promise in pending state
	 */
	catch(errorCallback) {
		return this.fetch().catch(errorCallback);
	}

	/**
	 * finally method of promise returned
	 *
	 * @template T
	 * @param {function():T} callback function to be called if the promise is fullfilled or rejected
	 * @return {Promise<T>} a Promise in pending state
	 */
	finally(callback) {
		return this.fetch().finally(callback);
	}
}

module.exports = {
	Curl,
	CurlResponse,
};
