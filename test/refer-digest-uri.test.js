const test = require('node:test');
const assert = require('node:assert');
const {requestUriFromDialog, uriForDigest} = require('../lib/refer-digest-uri');

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
