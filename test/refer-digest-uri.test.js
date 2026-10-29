const test = require('node:test');
const assert = require('node:assert');
const {requestUriFromDialog, uriForDigest, installDigestUriFix} = require('../lib/refer-digest-uri');

test('in-dialog Request-URI is the dialog remote target', () => {
  assert.strictEqual(
    requestUriFromDialog({remote: {uri: 'sip:broadworks@203.0.113.10:5061;transport=tls'}}),
    'sip:broadworks@203.0.113.10:5061;transport=tls'
  );
});

test('sip:placeholder is not used as a Request-URI', () => {
  assert.strictEqual(requestUriFromDialog({remote: {uri: 'sip:placeholder'}}), undefined);
  assert.strictEqual(requestUriFromDialog({}), undefined);
});

test('digest uses the sent Request-URI when the stored uri is the placeholder', () => {
  assert.strictEqual(
    uriForDigest('sip:placeholder', 'sip:broadworks@203.0.113.10:5061;transport=tls'),
    'sip:broadworks@203.0.113.10:5061;transport=tls'
  );
});

test('digest keeps a real stored uri when nothing was echoed', () => {
  assert.strictEqual(
    uriForDigest('sip:broadworks@203.0.113.10:5061', 'sip:placeholder'),
    'sip:broadworks@203.0.113.10:5061'
  );
});

let DigestClient;
try {
  DigestClient = require('drachtio-srf/lib/digest-client');
} catch (err) {
  DigestClient = null;
}

const challengedRefer = (method, requestUri) => {
  const sent = [];
  const agent = {
    request(opts) {
      sent.push({uri: opts.uri, authorization: opts.headers && opts.headers.Authorization});
    }
  };
  const options = {
    method,
    uri: 'sip:placeholder',
    auth: {username: 'trunk-user', password: 'not-a-real-secret'},
    headers: {}
  };
  const req = {
    uri: requestUri,
    method,
    _originalParams: {options},
    getParsedHeader() { return {seq: 1}; },
    get() { return '<sip:862174320@sipconn-tls.telstra.com>;tag=from-tag'; }
  };
  const res = {
    statusCode: 401,
    source_address: '192.148.164.23',
    source_port: 5061,
    agent,
    req,
    has(name) { return name === 'www-authenticate'; },
    get() { return 'DIGEST realm="sipconn-tls.telstra.com",qop="auth",nonce="n1",algorithm=MD5'; }
  };
  const client = new DigestClient(res);
  client.authenticate(() => {});
  return sent[0];
};

test('challenged REFER signs the Request-URI', {skip: !DigestClient}, () => {
  installDigestUriFix();
  const requestUri = 'sip:+917263986838@192.148.164.7:5061;transport=tls';
  const sent = challengedRefer('REFER', requestUri);
  assert.strictEqual(sent.uri, requestUri);
  assert.match(sent.authorization, /uri="sip:\+917263986838@192\.148\.164\.7:5061;transport=tls"/);
});

test('challenged INVITE is still signed over its own Request-URI', {skip: !DigestClient}, () => {
  installDigestUriFix();
  const sent = challengedRefer('INVITE', 'sip:399301264@sipconn-tls.telstra.com;transport=tls');
  assert.strictEqual(sent.uri, 'sip:399301264@sipconn-tls.telstra.com;transport=tls');
  assert.match(sent.authorization, /uri="sip:399301264@sipconn-tls.telstra.com;transport=tls"/);
});
