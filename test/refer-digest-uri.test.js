const test = require('node:test');
const assert = require('node:assert');
const {
  requestUriFromDialog,
  uriForDigest,
  referDigestUri,
  realmFromChallenge,
  referredByForCarrier,
  referToForCarrier,
  installDigestUriFix
} = require('../lib/refer-digest-uri');

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

test('REFER digest uses the Contact user at the challenge realm', () => {
  assert.strictEqual(
    referDigestUri(
      'sip:+917263986838@192.148.164.23:5061;transport=tls',
      'sipconn-tls.telstra.com'
    ),
    'sip:+917263986838@sipconn-tls.telstra.com;transport=tls'
  );
});

test('REFER digest keeps a Contact that has no transport parameter', () => {
  assert.strictEqual(
    referDigestUri('sip:+917263986838@192.148.164.23:5061', 'sipconn-tls.telstra.com'),
    'sip:+917263986838@sipconn-tls.telstra.com'
  );
});

test('attended REFER uses the consult user and a public Referred-By', () => {
  const referTo = referToForCarrier(
    '<sip:0399301264@sipconn-tls.telstra.com?Replaces=call-id%3Bto-tag%3Dt%3Bfrom-tag%3Df>'
  );
  assert.strictEqual(
    referTo,
    '<sip:399301264@sipconn-tls.telstra.com?Replaces=call-id%3Bto-tag%3Dt%3Bfrom-tag%3Df>'
  );
  assert.strictEqual(
    referredByForCarrier('<sip:+919567464915@172.20.11.137>', referTo),
    '<sip:+919567464915@sipconn-tls.telstra.com>'
  );
});

test('a public Referred-By and a Refer-To without Replaces are left alone', () => {
  assert.strictEqual(
    referredByForCarrier('<sip:862174320@sipconn-tls.telstra.com>', '<sip:399301264@sipconn-tls.telstra.com>'),
    '<sip:862174320@sipconn-tls.telstra.com>'
  );
  assert.strictEqual(
    referToForCarrier('<sip:0399301264@sipconn-tls.telstra.com>'),
    '<sip:0399301264@sipconn-tls.telstra.com>'
  );
});

test('REFER digest is not rewritten without a realm or a user', () => {
  assert.strictEqual(referDigestUri('sip:+917263986838@192.148.164.23', ''), undefined);
  assert.strictEqual(referDigestUri('sip:192.148.164.23:5061;transport=tls', 'sipconn-tls.telstra.com'), undefined);
  assert.strictEqual(realmFromChallenge('DIGEST qop="auth",nonce="n"'), undefined);
  assert.strictEqual(
    realmFromChallenge('DIGEST realm="sipconn-tls.telstra.com",qop="auth"'),
    'sipconn-tls.telstra.com'
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

test('challenged REFER keeps the Contact on the request and signs the realm', {skip: !DigestClient}, () => {
  installDigestUriFix();
  const sent = challengedRefer('REFER', 'sip:+917263986838@192.148.164.23:5061;transport=tls');
  assert.strictEqual(sent.uri, 'sip:+917263986838@192.148.164.23:5061;transport=tls');
  assert.match(sent.authorization, /uri="sip:\+917263986838@sipconn-tls.telstra.com;transport=tls"/);
});

test('challenged INVITE is still signed over its own Request-URI', {skip: !DigestClient}, () => {
  installDigestUriFix();
  const sent = challengedRefer('INVITE', 'sip:399301264@sipconn-tls.telstra.com;transport=tls');
  assert.strictEqual(sent.uri, 'sip:399301264@sipconn-tls.telstra.com;transport=tls');
  assert.match(sent.authorization, /uri="sip:399301264@sipconn-tls.telstra.com;transport=tls"/);
});
