const PLACEHOLDER_URI = 'sip:placeholder';

const isSipUri = (uri) => typeof uri === 'string' && /^sips?:/i.test(uri.trim()) && uri.trim() !== PLACEHOLDER_URI;

/**
 * Request-URI for an in-dialog request. drachtio otherwise stores sip:placeholder,
 * and the digest uri= parameter is signed with that instead of the REFER Request-URI.
 * @param {object} dlg
 * @returns {string|undefined}
 */
const requestUriFromDialog = (dlg) => {
  const uri = dlg && dlg.remote && dlg.remote.uri;
  if (!isSipUri(uri)) return undefined;
  return uri.trim().replace(/^<|>$/g, '');
};

/**
 * URI to put in the digest. Prefer the Request-URI of the request that was sent.
 * @param {string} optionsUri uri stored on the original request
 * @param {string} sentRequestUri Request-URI echoed for that request
 * @returns {string|undefined}
 */
const uriForDigest = (optionsUri, sentRequestUri) => {
  if (isSipUri(sentRequestUri)) return sentRequestUri.trim();
  if (isSipUri(optionsUri)) return optionsUri.trim();
  return undefined;
};

/**
 * Realm from a WWW-Authenticate or Proxy-Authenticate challenge.
 * @param {string} header
 * @returns {string|undefined}
 */
const realmFromChallenge = (header) => {
  const value = Array.isArray(header) ? header[0] : header;
  if (typeof value !== 'string') return undefined;
  const match = /realm="([^"]*)"/i.exec(value);
  if (!match || !match[1] || /[\s<>"]/.test(match[1])) return undefined;
  return match[1];
};

/**
 * Digest URI BroadWorks accepts for an in-dialog REFER.
 * The Request-URI stays the caller Contact. The hash uses that user at the
 * challenge realm, with the Contact's transport and without its port, which
 * is the shape of the INVITE digest Telstra already accepts.
 * @param {string} requestUri
 * @param {string} realm
 * @returns {string|undefined}
 */
const referDigestUri = (requestUri, realm) => {
  if (!isSipUri(requestUri) || typeof realm !== 'string' || realm.length === 0) return undefined;
  const uri = requestUri.trim().replace(/^<|>$/g, '');
  const user = /^sips?:([^@/;?]+)@/i.exec(uri);
  if (!user) return undefined;
  const transport = /;transport=([^;>\s]+)/i.exec(uri);
  return `sip:${user[1]}@${realm}${transport ? `;transport=${transport[1]}` : ''}`;
};

const challengeHeader = (res) => {
  if (!res || typeof res.has !== 'function' || typeof res.get !== 'function') return undefined;
  const name = res.statusCode === 407 ? 'proxy-authenticate' : 'www-authenticate';
  if (!res.has(name)) return undefined;
  return res.get(name);
};

/**
 * Keep the retry Request-URI on the Contact after the digest uri is rewritten.
 * DigestClient uses one options.uri for both the hash and the request line.
 * @param {object} agent
 */
const pinRequestUri = (agent) => {
  if (!agent || agent.__referRequestUriPinned || typeof agent.request !== 'function') return;
  const request = agent.request;
  agent.request = function(opts, cb) {
    if (opts && typeof opts.__referRequestUri === 'string') {
      opts.uri = opts.__referRequestUri;
      delete opts.__referRequestUri;
    }
    return request.call(this, opts, cb);
  };
  agent.__referRequestUriPinned = true;
};

/**
 * Send a request inside a dialog, with the remote target as the Request-URI
 * so a 401 digest is computed over that URI.
 * @param {object} dlg
 * @param {{method: string, headers?: object, body?: string, auth?: object, uri?: string}} opts
 * @returns {Promise<object>}
 */
const requestWithinDialog = (dlg, opts) => {
  const uri = opts.uri || requestUriFromDialog(dlg);
  return new Promise((resolve, reject) => {
    dlg.agent.request({
      method: opts.method,
      ...(uri && {uri}),
      stackDialogId: dlg.id,
      headers: opts.headers || {},
      auth: Object.prototype.hasOwnProperty.call(opts, 'auth') ? opts.auth : dlg.auth,
      _socket: dlg.socket,
      body: opts.body
    }, (err, req) => {
      if (err) return reject(err);
      req.once('response', (res) => resolve(res));
    });
  });
};

/**
 * Point drachtio's digest client at the sent Request-URI when it still holds sip:placeholder.
 * A challenged REFER is then signed as the Contact user at the challenge realm.
 */
const installDigestUriFix = () => {
  const DigestClient = require('drachtio-srf/lib/digest-client');
  if (DigestClient.prototype.__referDigestUriFixed) return;
  const authenticate = DigestClient.prototype.authenticate;
  DigestClient.prototype.authenticate = function(callback) {
    const options = this.req && this.req._originalParams && this.req._originalParams.options;
    if (options) {
      const uri = uriForDigest(options.uri, this.req && this.req.uri);
      if (uri) options.uri = uri;
      if (String(options.method || '').toUpperCase() === 'REFER') {
        const signed = referDigestUri(options.uri, realmFromChallenge(challengeHeader(this.res)));
        if (signed && signed !== options.uri) {
          options.__referRequestUri = options.uri;
          options.uri = signed;
          pinRequestUri(this.agent);
        }
      }
    }
    return authenticate.call(this, callback);
  };
  DigestClient.prototype.__referDigestUriFixed = true;
};

module.exports = {
  requestUriFromDialog,
  uriForDigest,
  referDigestUri,
  realmFromChallenge,
  requestWithinDialog,
  installDigestUriFix
};
