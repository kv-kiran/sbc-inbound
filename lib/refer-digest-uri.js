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
 * The digest uri stays that Request-URI. RFC 3261 hashes the request line, not the realm.
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
    }
    return authenticate.call(this, callback);
  };
  DigestClient.prototype.__referDigestUriFixed = true;
};

module.exports = {
  requestUriFromDialog,
  uriForDigest,
  requestWithinDialog,
  installDigestUriFix
};
